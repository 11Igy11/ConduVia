from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from core.analyst import compute_analyst_summary
from core.analyzer import top_applications
from core.formatters import human_bytes
from core.pcap_analyzer import PcapSummary, build_investigator_view

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


def _json_findings(analyst: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    bytes_info = analyst.get("bytes") or {}
    dominance = analyst.get("dominance") or {}
    activity = analyst.get("activity") or {}
    largest = analyst.get("largest") or {}
    dominant = analyst.get("dominant_app") or {}

    outbound_share = float(bytes_info.get("outbound_share_total_pct") or 0.0)
    if outbound_share > 60:
        findings.append(
            f"High outbound share: {outbound_share:.1f}% of total bytes (private to public)."
        )
    elif outbound_share >= 35:
        findings.append(
            f"Moderate outbound share: {outbound_share:.1f}% of total bytes (private to public)."
        )

    internal = dominance.get("top_internal_outbound") or {}
    internal_share = float(internal.get("share_of_outbound_pct") or 0.0)
    if internal_share > 70:
        findings.append(
            f"Outbound bytes are highly concentrated on one internal host ({internal_share:.1f}% of outbound)."
        )
    elif internal_share >= 40:
        findings.append(
            f"Outbound bytes are moderately concentrated on one internal host ({internal_share:.1f}% of outbound)."
        )

    destination = dominance.get("top_destination_outbound") or {}
    dst_share = float(destination.get("share_of_outbound_pct") or 0.0)
    if dst_share > 70:
        findings.append(
            f"Outbound traffic is dominated by one destination ({dst_share:.1f}% of outbound bytes)."
        )
    elif dst_share >= 40:
        findings.append(
            f"Outbound traffic is concentrated on one destination ({dst_share:.1f}% of outbound bytes)."
        )

    night_share = float(activity.get("night_share_pct") or 0.0)
    if night_share >= 60:
        findings.append(
            f"Night-heavy activity: {night_share:.1f}% of timed flows occur between 22:00 and 06:00."
        )
    elif night_share >= 35:
        findings.append(
            f"Noticeable night activity: {night_share:.1f}% of timed flows occur between 22:00 and 06:00."
        )

    largest_out_share = float(largest.get("largest_outbound_share_pct") or 0.0)
    if largest_out_share >= 35:
        findings.append(
            f"One outbound flow accounts for {largest_out_share:.1f}% of outbound bytes."
        )
    elif largest_out_share >= 15:
        findings.append(
            f"A single outbound flow is unusually large ({largest_out_share:.1f}% of outbound bytes)."
        )

    app_name = str((dominant.get("by_bytes") or {}).get("name") or "")
    app_share = float((dominant.get("by_bytes") or {}).get("share_pct") or 0.0)
    if app_name and app_name != "—" and app_share >= 25 and len(findings) < 5:
        findings.append(f"Dominant application by volume: {app_name} ({app_share:.1f}% of bytes).")

    return findings[:5]


def _json_headline(analyst: dict[str, Any], *, period_label: str) -> str:
    activity = analyst.get("activity") or {}
    dominant = analyst.get("dominant_app") or {}
    coverage = analyst.get("coverage") or {}
    deviation = analyst.get("behavior_deviation") or {}

    app_name = str((dominant.get("by_bytes") or {}).get("name") or "mixed applications")
    app_share = float((dominant.get("by_bytes") or {}).get("share_pct") or 0.0)
    night_share = float(activity.get("night_share_pct") or 0.0)
    business_share = float(activity.get("business_share_pct") or 0.0)
    level = str(deviation.get("level") or "LOW")

    if night_share >= 55:
        rhythm = "evening- and night-heavy"
    elif business_share >= 55:
        rhythm = "business-hours-heavy"
    else:
        rhythm = "mixed-hour"

    period_part = f" for {period_label}" if period_label else ""
    flows = int(coverage.get("total_flows") or 0)
    return (
        f"{rhythm.capitalize()} flow dataset{period_part}: "
        f"{flows:,} flows; {app_name} leads with {app_share:.1f}% of bytes "
        f"(deviation level {level})."
    )


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
    dominant = analyst.get("dominant_app") or {}

    total_bytes = int(bytes_info.get("total_bytes") or 0)
    total_flows = int(coverage.get("total_flows") or len(flows))
    peak_hour = activity.get("peak_hour")
    peak_text = f"{int(peak_hour):02d}:00" if peak_hour is not None else "unknown"

    patterns = [
        f"Peak activity hour: {peak_text}",
        f"Night share: {float(activity.get('night_share_pct') or 0.0):.1f}% | "
        f"Business hours: {float(activity.get('business_share_pct') or 0.0):.1f}%",
        f"Outbound share of total bytes: {float(bytes_info.get('outbound_share_total_pct') or 0.0):.1f}%",
    ]
    active_days = int(coverage.get("active_days") or 0)
    if active_days:
        patterns.append(
            f"Active days in view: {active_days:,} "
            f"({str(coverage.get('pattern') or 'unknown')} communication pattern)."
        )

    top_apps = top_applications(flows, limit=3)
    apps_line = ""
    if top_apps:
        apps_line = "Detected applications: " + ", ".join(name for name, _count in top_apps)

    narrative_parts = []
    if period_label:
        narrative_parts.append(f"This snapshot covers {period_label}.")
    narrative_parts.append(
        f"The dataset contains {total_flows:,} flows and {human_bytes(total_bytes, precision=2)} of bidirectional volume."
    )
    dominant_name = str((dominant.get("by_bytes") or {}).get("name") or "")
    if dominant_name and dominant_name != "—":
        narrative_parts.append(
            f"{dominant_name} is the leading application by bytes "
            f"({float((dominant.get('by_bytes') or {}).get('share_pct') or 0.0):.1f}% share)."
        )
    narrative_parts.append(
        "Use Registry for full statistics, Flows for record-level review, and Listing for export-oriented tables."
    )

    return InvestigationSnapshot(
        headline=_json_headline(analyst, period_label=period_label),
        findings=_json_findings(analyst),
        patterns=patterns,
        apps_line=apps_line,
        next_steps=[
            "Open Registry for concentration metrics and analyst flags.",
            "Open Flows to filter by top application or destination.",
            "Open Listing when you need a tabular export view.",
        ],
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
    high_rows = [row for row in comm_rows if str(row.get("confidence") or "").lower() == "high"]

    peak_label = _peak_hour_label(list(summary.hourly_activity or []))
    peak_share = _pattern_share_pct(list(summary.hourly_activity or []), value_key="packets")
    top_services = [str(row.get("service") or "") for row in service_rows[:3] if str(row.get("service") or "")]
    service_text = ", ".join(top_services) if top_services else "mixed services"

    headline = (
        f"Capture shows {len(comm_rows):,} communication indicators"
        + (f" with peak activity around {peak_label}" if peak_label else "")
        + f"; leading services: {service_text}."
    )
    if high_rows:
        headline += f" {len(high_rows):,} high-confidence indicators deserve review."

    findings: list[str] = []
    for row in high_rows[:3]:
        findings.append(
            f"{row.get('service')}: {row.get('activity_type')} "
            f"({row.get('confidence')} confidence)."
        )
    if not findings and comm_rows:
        for row in comm_rows[:2]:
            findings.append(
                f"{row.get('service')}: {row.get('activity_type')} "
                f"({row.get('confidence')} confidence)."
            )

    visibility_rows = list(investigator.get("visibility_rows") or [])
    encrypted = next((row for row in visibility_rows if str(row.get("label") or "").startswith("Encrypted")), None)
    patterns = [
        f"Packets: {int(summary.packet_count or 0):,} | Volume: {human_bytes(summary.wire_bytes, precision=2)}",
    ]
    if peak_label:
        patterns.append(f"Peak hour bucket: {peak_label} ({peak_share:.1f}% of timed packets).")
    if encrypted and int(encrypted.get("count") or 0) > 0:
        patterns.append(
            f"Encrypted or metadata-only sessions: {int(encrypted.get('count') or 0):,} packets "
            f"({float(encrypted.get('share') or 0.0):.1f}% share)."
        )
    patterns.append(
        f"Visible DNS names: {int(summary.total_dns_names or len(summary.dns_queries or [])):,}; "
        f"TLS SNI hosts: {int(summary.total_tls_sni_hosts or len(summary.tls_sni or [])):,}."
    )

    apps_line = ""
    if top_services:
        apps_line = "Detected services: " + ", ".join(top_services)

    narrative = str(investigator.get("plain_summary") or "").strip()
    limitations = list(investigator.get("limitations") or [])[:3]

    return InvestigationSnapshot(
        headline=headline,
        findings=findings,
        patterns=patterns,
        apps_line=apps_line,
        next_steps=[
            "Open Communications for classified activity indicators.",
            "Open Evidence for DNS, TLS hosts and readable payload samples.",
            "Use Mark as Finding when a period should be saved to the case.",
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
