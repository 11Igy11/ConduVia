from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from core.analyst import compute_analyst_summary
from core.analyzer import top_applications
from core.formatters import human_bytes
from core.pcap_analyzer import PcapSummary, build_investigator_view
from core.service_classification import communication_indicator_family
from core.summary_heuristics import (
    burst_hour_labels,
    communication_lead_line,
    flow_activity_window,
    format_activity_window,
    format_hour_label,
    largest_flow_narrative,
    messaging_and_social_lines,
    pcap_peak_hour_label,
    peak_hour_share_pct,
    rhythm_label,
    service_groups_from_flows,
)

SnapshotSource = Literal["json", "pcap"]


@dataclass
class InvestigationSnapshot:
    headline: str = ""
    findings: list[str] = field(default_factory=list)
    patterns: list[str] = field(default_factory=list)
    apps_line: str = ""
    next_steps: list[str] = field(default_factory=list)
    narrative: str = ""
    limitations: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any] | None) -> InvestigationSnapshot:
        data = dict(payload or {})
        return cls(
            headline=str(data.get("headline") or ""),
            findings=[str(item) for item in (data.get("findings") or []) if str(item).strip()],
            patterns=[str(item) for item in (data.get("patterns") or []) if str(item).strip()],
            apps_line=str(data.get("apps_line") or ""),
            next_steps=[str(item) for item in (data.get("next_steps") or []) if str(item).strip()],
            narrative=str(data.get("narrative") or ""),
            limitations=[str(item) for item in (data.get("limitations") or []) if str(item).strip()],
            meta=dict(data.get("meta") or {}),
        )


def format_snapshot_notes_block(
    label: str,
    snapshot: InvestigationSnapshot,
    *,
    stats_lines: list[str] | None = None,
) -> str:
    lines = [f"[{label}]"]
    if stats_lines:
        lines.extend(stats_lines)
        lines.append("")
    if snapshot.headline:
        lines.append(snapshot.headline)
    if snapshot.findings:
        lines.extend(["", "Findings:"])
        lines.extend(f"- {item}" for item in snapshot.findings[:5])
    if snapshot.patterns:
        lines.extend(["", "Patterns:"])
        lines.extend(f"- {item}" for item in snapshot.patterns[:4])
    if snapshot.apps_line:
        lines.extend(["", snapshot.apps_line])
    if snapshot.narrative:
        lines.extend(["", snapshot.narrative])
    if snapshot.limitations:
        lines.extend(["", "Limitations:"])
        lines.extend(f"- {item}" for item in snapshot.limitations[:3])
    lines.append("-" * 60)
    return "\n".join(lines) + "\n"


def _hour_label_from_bucket(bucket: str) -> str:
    text = str(bucket or "").strip()
    if not text:
        return ""
    if " " in text:
        return text.rsplit(" ", 1)[-1]
    return text


def _peak_hour_label(hourly_rows: list[dict[str, Any]]) -> str:
    if not hourly_rows:
        return ""
    peak = max(hourly_rows, key=lambda row: int(row.get("packets") or row.get("count") or 0))
    return _hour_label_from_bucket(str(peak.get("hour") or ""))


def _pattern_share_pct(rows: list[dict[str, Any]], *, value_key: str) -> float:
    values = [int(row.get(value_key) or row.get("packets") or row.get("count") or 0) for row in rows]
    total = sum(values)
    if total <= 0:
        return 0.0
    peak = max(values)
    return (peak / total) * 100.0


def _json_findings(
    analyst: dict[str, Any],
    *,
    flows: list[dict[str, Any]],
    service_groups: list[tuple[str, int, int]],
) -> list[str]:
    findings: list[str] = []
    bytes_info = analyst.get("bytes") or {}
    activity = analyst.get("activity") or {}
    largest = analyst.get("largest") or {}
    total_bytes = int(bytes_info.get("total_bytes") or 0)

    peak_hour = activity.get("peak_hour")
    peak_share = peak_hour_share_pct(list(activity.get("hour_hist") or []), peak_hour)
    peak_label = format_hour_label(peak_hour)
    if peak_label and peak_share >= 8:
        findings.append(f"Peak activity around {peak_label} ({peak_share:.1f}% of timed flows).")

    for burst in burst_hour_labels(list(activity.get("hour_hist") or [])):
        if len(findings) >= 5:
            break
        if peak_label and burst.startswith(peak_label):
            continue
        findings.append(f"Activity spike at {burst}.")

    messaging, social = messaging_and_social_lines(service_groups, total_bytes=total_bytes)
    if messaging:
        findings.append(f"Messaging/cloud services stand out: {messaging[0]}.")
    if social and len(findings) < 5:
        findings.append(f"Social/content usage: {social[0]}.")

    night_share = float(activity.get("night_share_pct") or 0.0)
    if night_share >= 60:
        findings.append(
            f"Night-heavy activity: {night_share:.1f}% of timed flows occur between 22:00 and 06:00."
        )
    elif night_share >= 35 and len(findings) < 5:
        findings.append(
            f"Noticeable night activity: {night_share:.1f}% of timed flows occur between 22:00 and 06:00."
        )

    outbound_share = float(bytes_info.get("outbound_share_total_pct") or 0.0)
    if outbound_share > 60 and len(findings) < 5:
        findings.append(
            f"High outbound share: {outbound_share:.1f}% of total bytes leaves the private side."
        )
    elif outbound_share >= 35 and len(findings) < 5:
        findings.append(
            f"Moderate outbound share: {outbound_share:.1f}% of total bytes leaves the private side."
        )

    largest_out_share = float(largest.get("largest_outbound_share_pct") or 0.0)
    if largest_out_share >= 15 and len(findings) < 5:
        narrative = largest_flow_narrative(largest.get("largest_outbound_flow"), outbound=True)
        if narrative:
            findings.append(narrative)
    elif float(largest.get("largest_total_share_pct") or 0.0) >= 20 and len(findings) < 5:
        narrative = largest_flow_narrative(largest.get("largest_total_flow"), outbound=False)
        if narrative:
            findings.append(narrative)

    dominant = analyst.get("dominant_app") or {}
    app_name = str((dominant.get("by_bytes") or {}).get("name") or "")
    app_share = float((dominant.get("by_bytes") or {}).get("share_pct") or 0.0)
    if app_name and app_name != "—" and app_share >= 25 and len(findings) < 5:
        findings.append(f"Dominant application label by volume: {app_name} ({app_share:.1f}% of bytes).")

    return findings[:5]


def _json_headline(
    analyst: dict[str, Any],
    *,
    period_label: str,
    service_groups: list[tuple[str, int, int]],
    activity_window: str,
) -> str:
    activity = analyst.get("activity") or {}
    coverage = analyst.get("coverage") or {}
    bytes_info = analyst.get("bytes") or {}

    flows = int(coverage.get("total_flows") or 0)
    total_bytes = int(bytes_info.get("total_bytes") or 0)
    peak_label = format_hour_label(activity.get("peak_hour"))
    peak_share = peak_hour_share_pct(list(activity.get("hour_hist") or []), activity.get("peak_hour"))
    rhythm = rhythm_label(
        night_share=float(activity.get("night_share_pct") or 0.0),
        business_share=float(activity.get("business_share_pct") or 0.0),
    )

    lead_service = service_groups[0][0] if service_groups else "mixed applications"
    lead_share = 0.0
    if service_groups and total_bytes > 0:
        lead_share = (service_groups[0][2] / total_bytes) * 100.0

    period_part = f" for {period_label}" if period_label else ""
    headline = (
        f"{rhythm.capitalize()} activity{period_part}: {flows:,} flows, "
        f"{human_bytes(total_bytes, precision=2)}."
    )
    if peak_label:
        headline += f" Busiest around {peak_label}"
        if peak_share >= 8:
            headline += f" ({peak_share:.1f}% of timed flows)"
        headline += "."
    headline += f" Leading service group: {lead_service}"
    if lead_share >= 5:
        headline += f" ({lead_share:.1f}% of bytes)"
    headline += "."
    if activity_window:
        headline += f" Traffic observed {activity_window}."
    return headline


def _json_next_steps(
    analyst: dict[str, Any],
    *,
    service_groups: list[tuple[str, int, int]],
) -> list[str]:
    steps = [
        "Open Registry for concentration metrics and analyst flags.",
        "Open Flows to filter by top application or destination.",
    ]
    activity = analyst.get("activity") or {}
    night_share = float(activity.get("night_share_pct") or 0.0)
    peak_label = format_hour_label(activity.get("peak_hour"))
    bursts = burst_hour_labels(list(activity.get("hour_hist") or []))

    if bursts:
        steps.append(f"Review flows around {bursts[0].split(' ')[0]} first — that hour shows a clear spike.")
    elif peak_label and night_share >= 35:
        steps.append(f"Review late-night flows first, especially around {peak_label}.")
    elif service_groups:
        steps.append(f"Filter Flows by {service_groups[0][0]} to inspect the leading service group.")
    else:
        steps.append("Open Listing when you need a tabular export view.")
    return steps[:3]


def build_json_snapshot(
    flows: list[dict[str, Any]],
    meta: dict[str, Any] | None = None,
    *,
    period_label: str = "",
    period_mode: str = "day",
) -> InvestigationSnapshot:
    flows = flows or []
    analyst = compute_analyst_summary(flows, meta)
    coverage = analyst.get("coverage") or {}
    activity = analyst.get("activity") or {}
    bytes_info = analyst.get("bytes") or {}

    total_bytes = int(bytes_info.get("total_bytes") or 0)
    total_flows = int(coverage.get("total_flows") or len(flows))
    service_groups = service_groups_from_flows(flows, limit=5)
    first_seen, last_seen = flow_activity_window(flows)
    activity_window = format_activity_window(first_seen, last_seen)

    findings = _json_findings(analyst, flows=flows, service_groups=service_groups)

    patterns = []
    peak_label = format_hour_label(activity.get("peak_hour"))
    quiet_label = format_hour_label(activity.get("quiet_hour"))
    if peak_label:
        peak_share = peak_hour_share_pct(list(activity.get("hour_hist") or []), activity.get("peak_hour"))
        patterns.append(f"Peak hour: {peak_label} ({peak_share:.1f}% of timed flows)")
    if quiet_label and quiet_label != peak_label:
        patterns.append(f"Quietest hour: {quiet_label}")
    patterns.append(
        f"Night share: {float(activity.get('night_share_pct') or 0.0):.1f}% | "
        f"Business hours: {float(activity.get('business_share_pct') or 0.0):.1f}%"
    )
    patterns.append(
        f"Outbound share of total bytes: {float(bytes_info.get('outbound_share_total_pct') or 0.0):.1f}%"
    )
    burst_lines = burst_hour_labels(list(activity.get("hour_hist") or []))
    if burst_lines:
        patterns.append("Activity spikes: " + ", ".join(burst_lines))
    active_days = int(coverage.get("active_days") or 0)
    if active_days:
        patterns.append(
            f"Active days in view: {active_days:,} "
            f"({str(coverage.get('pattern') or 'unknown')} communication pattern)."
        )
    if activity_window:
        patterns.append(f"Observed traffic window: {activity_window}")

    top_apps = top_applications(flows, limit=3)
    apps_line = ""
    if service_groups:
        apps_line = "Service groups by volume: " + ", ".join(
            f"{name} ({human_bytes(byte_count, precision=2)})"
            for name, _count, byte_count in service_groups[:3]
        )
    elif top_apps:
        apps_line = "Detected applications: " + ", ".join(name for name, _count in top_apps)

    narrative_parts = []
    if period_label:
        narrative_parts.append(f"This snapshot covers {period_label}.")
    narrative_parts.append(
        f"The dataset contains {total_flows:,} flows and {human_bytes(total_bytes, precision=2)} of bidirectional volume."
    )
    if findings:
        narrative_parts.append("Most notable signals: " + " ".join(findings[:2]))
    deviation = analyst.get("behavior_deviation") or {}
    reasons = [str(item).strip() for item in (deviation.get("reasons") or []) if str(item).strip()]
    for reason in reasons:
        if any(token in reason for token in ("private→public", "outbound", "night", "bulk", "concentrated")):
            if "." not in reason.split(":")[-1]:  # skip IP-heavy dominance lines
                narrative_parts.append(reason)
                break
            if "ratio" in reason.lower() or "night" in reason.lower():
                narrative_parts.append(reason)
                break
    narrative_parts.append(
        "Use Registry for full statistics, Flows for record-level review, and Listing for export-oriented tables."
    )

    return InvestigationSnapshot(
        headline=_json_headline(
            analyst,
            period_label=period_label,
            service_groups=service_groups,
            activity_window=activity_window,
        ),
        findings=findings,
        patterns=patterns,
        apps_line=apps_line,
        next_steps=_json_next_steps(analyst, service_groups=service_groups),
        narrative=" ".join(narrative_parts),
        limitations=[
            "Flow records reflect lawful-interception export metadata, not packet-level payload.",
            "Application labels depend on the exporter classification and may group distinct services.",
            "Timing and volume patterns are indicative; verify notable flows in the Flows tab.",
        ],
        meta={
            "source": "json",
            "period_label": period_label,
            "period_mode": period_mode,
            "total_flows": total_flows,
            "total_bytes": total_bytes,
        },
    )


def build_pcap_snapshot(summary: PcapSummary) -> InvestigationSnapshot:
    investigator = build_investigator_view(summary)
    service_rows = list(investigator.get("service_rows") or [])
    comm_rows = list(summary.communication_rows or [])
    comm_only = [row for row in comm_rows if str(row.get("category") or "communications") != "social"]
    social_rows = [row for row in comm_rows if str(row.get("category") or "") == "social"]
    review_rows = [row for row in comm_only if str(row.get("tier") or "") == "review"]
    high_rows = [row for row in comm_only if str(row.get("confidence") or "").lower() == "high"]
    routine_flows = sum(int(row.get("sessions") or 0) for row in comm_only if str(row.get("tier") or "") == "routine")

    peak_label, peak_share = pcap_peak_hour_label(list(summary.hourly_activity or []))
    top_services = [str(row.get("service") or "") for row in service_rows[:3] if str(row.get("service") or "")]
    service_text = ", ".join(top_services) if top_services else "mixed services"
    family_counts = {"call_media": 0, "messaging": 0, "background": 0, "content": 0, "other": 0}
    for row in comm_only:
        family = communication_indicator_family(str(row.get("activity_type") or ""))
        family_counts[family] = family_counts.get(family, 0) + int(row.get("sessions") or 1)

    activity_window = format_activity_window(summary.first_seen, summary.last_seen)
    lead_count = len(review_rows) or len([row for row in comm_only if str(row.get("tier") or "") != "routine"])
    headline = (
        f"Capture for this period: {int(summary.packet_count or 0):,} packets, "
        f"{human_bytes(summary.wire_bytes, precision=2)}."
    )
    if peak_label:
        headline += f" Peak activity around {peak_label}"
        if peak_share >= 8:
            headline += f" ({peak_share:.1f}% of timed packets)"
        headline += "."
    headline += f" {lead_count:,} review-worthy communication leads; leading services: {service_text}."
    if routine_flows:
        headline += f" {routine_flows:,} routine background flows are grouped separately."
    if activity_window:
        headline += f" Traffic observed {activity_window}."

    findings: list[str] = []
    lead_source = review_rows or [row for row in comm_only if str(row.get("tier") or "") != "routine"] or comm_only
    for row in lead_source[:3]:
        findings.append(communication_lead_line(row))
    if social_rows and len(findings) < 5:
        top_social = social_rows[0]
        label = top_social.get("activity_label") or top_social.get("activity_type")
        findings.append(
            f"Social/content: {top_social.get('service')} — {label} "
            f"({human_bytes(int(top_social.get('bytes') or 0), precision=2)})."
        )
    if family_counts["background"] and len(findings) < 5:
        findings.append(
            f"{family_counts['background']:,} grouped flows look like background sync/push rather than direct user interaction."
        )

    visibility_rows = list(investigator.get("visibility_rows") or [])
    encrypted = next((row for row in visibility_rows if str(row.get("label") or "").startswith("Encrypted")), None)
    patterns = [
        f"Packets: {int(summary.packet_count or 0):,} | Volume: {human_bytes(summary.wire_bytes, precision=2)}",
    ]
    if peak_label:
        patterns.append(f"Peak hour bucket: {peak_label} ({peak_share:.1f}% of timed packets).")
    if activity_window:
        patterns.append(f"Observed traffic window: {activity_window}")
    if encrypted and int(encrypted.get("count") or 0) > 0:
        patterns.append(
            f"Encrypted or metadata-only sessions: {int(encrypted.get('count') or 0):,} packets "
            f"({float(encrypted.get('share') or 0.0):.1f}% share)."
        )
    mix_parts: list[str] = []
    if family_counts["call_media"]:
        mix_parts.append(f"{family_counts['call_media']:,} call/media-like")
    if family_counts["messaging"]:
        mix_parts.append(f"{family_counts['messaging']:,} messaging/push-like")
    if family_counts["background"]:
        mix_parts.append(f"{family_counts['background']:,} background/sync")
    if family_counts["content"]:
        mix_parts.append(f"{family_counts['content']:,} content/app-session")
    if mix_parts:
        patterns.append("Communication mix: " + ", ".join(mix_parts) + ".")
    patterns.append(
        f"Visible DNS names: {int(summary.total_dns_names or len(summary.dns_queries or [])):,}; "
        f"TLS SNI hosts: {int(summary.total_tls_sni_hosts or len(summary.tls_sni or [])):,}."
    )

    apps_line = ""
    if top_services:
        apps_line = "Detected services: " + ", ".join(top_services)

    narrative = str(investigator.get("plain_summary") or "").strip()
    if high_rows and len(findings) < 2:
        narrative += " " + communication_lead_line(high_rows[0])
    limitations = list(investigator.get("limitations") or [])[:3]

    return InvestigationSnapshot(
        headline=headline,
        findings=findings,
        patterns=patterns,
        apps_line=apps_line,
        next_steps=[
            "Open Communications and review high-confidence call/media or messaging indicators first.",
            "Open Evidence for DNS, TLS hosts and readable payload samples.",
            "Mark a finding only after confirming the indicator against surrounding metadata and timing.",
        ],
        narrative=narrative,
        limitations=limitations,
        meta={
            "source": "pcap",
            "packet_count": int(summary.packet_count or 0),
            "wire_bytes": int(summary.wire_bytes or 0),
            "communication_indicators": len(comm_rows),
            "high_confidence_indicators": len(high_rows),
        },
    )
