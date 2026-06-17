from typing import Any

from core.analyzer import top_applications, top_dst_ips, top_protocols, top_src_ips
from core.analyst import compute_analyst_summary
from core.flow_stats import top_field_by_bytes, top_flows_by_bytes
from core.formatters import human_bytes
from core.pcap_analyzer import PcapSummary, build_investigator_view
from core.protocols import format_ip_proto, format_ip_proto_with_description


def _pct(value: Any) -> str:
    try:
        return f"{float(value):.1f}%"
    except Exception:
        return "0.0%"


def build_dataset_context(
    flows: list[dict[str, Any]],
    project_name: str = "",
    dataset_path: str = "",
    total_flows: int | None = None,
    limit: int = 10,
    *,
    period_label: str = "",
    period_mode: str = "day",
) -> str:
    lines: list[str] = []

    actual_total = total_flows if total_flows is not None else len(flows)
    mode = str(period_mode or "day").strip().casefold()
    month_aggregate = mode.startswith("month")

    lines.append(f"Project: {project_name or '(none)'}")
    lines.append(f"Dataset: {dataset_path or '(none)'}")
    if period_label:
        scope = "month aggregate" if month_aggregate else "single day"
        lines.append(f"Loaded period: {period_label} ({scope})")
        if month_aggregate:
            lines.append(
                "Period scope: all flows in the selected calendar month bucket, not the whole project."
            )
    lines.append("Goal: describe observable device or user communication behavior based on network flow metadata.")
    lines.append(f"Total flows in loaded period: {actual_total}")
    lines.append("")

    analyst = compute_analyst_summary(flows)
    coverage = analyst.get("coverage", {}) or {}
    bytes_info = analyst.get("bytes", {}) or {}
    dominant_app = analyst.get("dominant_app", {}) or {}
    dominance = analyst.get("dominance", {}) or {}
    activity = analyst.get("activity", {}) or {}
    largest = analyst.get("largest", {}) or {}
    deviation = analyst.get("behavior_deviation", {}) or {}

    lines.append("Dataset-level behavior indicators:")
    lines.append(f"- Total bytes: {human_bytes(bytes_info.get('total_bytes', 0))}")
    if not month_aggregate:
        lines.append(f"- Coverage pattern: {coverage.get('pattern', 'unknown')}")
        lines.append(f"- Active days: {coverage.get('active_days', 0)}")
        lines.append(f"- Avg flows per active day: {float(coverage.get('avg_flows_per_active_day', 0.0) or 0.0):.1f}")
    lines.append(f"- Outbound share of total bytes: {_pct(bytes_info.get('outbound_share_total_pct', 0.0))}")
    lines.append(f"- Peak hour: {activity.get('peak_hour', 'unknown')}")
    lines.append(f"- Night share: {_pct(activity.get('night_share_pct', 0.0))}")
    lines.append(f"- Business-hours share: {_pct(activity.get('business_share_pct', 0.0))}")
    reasons = list(deviation.get("reasons", []) or [])
    if reasons:
        lines.append("- Traffic pattern flags:")
        for reason in reasons[:8]:
            lines.append(f"  • {reason}")
    else:
        lines.append("- Traffic pattern flags: none notable")
    lines.append("")

    dom_bytes = dominant_app.get("by_bytes", {}) or {}
    dom_count = dominant_app.get("by_count", {}) or {}
    lines.append("Dominant application labels:")
    lines.append(
        f"- By bytes: {dom_bytes.get('name', '-')}, "
        f"{human_bytes(dom_bytes.get('bytes', 0))}, share {_pct(dom_bytes.get('share_pct', 0.0))}"
    )
    lines.append(
        f"- By count: {dom_count.get('name', '-')}, "
        f"{dom_count.get('count', 0)} flows, share {_pct(dom_count.get('share_pct', 0.0))}"
    )
    lines.append("")

    top_internal = (dominance.get("top_internal_outbound", {}) or {})
    top_dst = (dominance.get("top_destination_outbound", {}) or {})
    lines.append("Concentration indicators:")
    lines.append(
        f"- Top internal outbound host: {top_internal.get('ip', '-')}, "
        f"{human_bytes(top_internal.get('bytes', 0))}, share of outbound {_pct(top_internal.get('share_of_outbound_pct', 0.0))}"
    )
    lines.append(
        f"- Top outbound destination: {top_dst.get('ip', '-')}, "
        f"{human_bytes(top_dst.get('bytes', 0))}, share of outbound {_pct(top_dst.get('share_of_outbound_pct', 0.0))}"
    )
    lines.append("")

    lines.append("Top source IPs by flow count:")
    for ip, count in top_src_ips(flows, limit=limit):
        lines.append(f"- {ip}: {count}")

    lines.append("")
    lines.append("Top destination IPs by flow count:")
    for ip, count in top_dst_ips(flows, limit=limit):
        lines.append(f"- {ip}: {count}")

    lines.append("")
    lines.append("Top protocols:")
    for proto, count in top_protocols(flows, limit=limit):
        lines.append(f"- {format_ip_proto_with_description(proto)}: {count}")

    lines.append("")
    lines.append("Top applications:")
    for app, count in top_applications(flows, limit=limit):
        lines.append(f"- {app}: {count}")

    lines.append("")
    lines.append("Top source IPs by bytes:")
    for ip, total_bytes in top_field_by_bytes(flows, "src_ip", limit=limit):
        lines.append(f"- {ip}: {human_bytes(total_bytes)}")

    lines.append("")
    lines.append("Top destination IPs by bytes:")
    for ip, total_bytes in top_field_by_bytes(flows, "dst_ip", limit=limit):
        lines.append(f"- {ip}: {human_bytes(total_bytes)}")

    lines.append("")
    lines.append("Largest individual flows:")
    for flow in top_flows_by_bytes(flows, limit=5):
        lines.append(
            "- "
            f"{flow.get('src_ip')}:{flow.get('src_port')} -> {flow.get('dst_ip')}:{flow.get('dst_port')}, "
            f"protocol {format_ip_proto_with_description(flow.get('protocol'))}, "
            f"app label {flow.get('app') or '-'}, "
            f"bytes {human_bytes(flow.get('bytes', 0))}, "
            f"packets {flow.get('packets', 0)}, "
            f"duration_ms {flow.get('duration_ms', 0)}, "
            f"hostname-like value {flow.get('sni') or '-'}"
        )

    largest_total = largest.get("largest_total_flow")
    if largest_total:
        lines.append("")
        lines.append("Largest-flow share:")
        lines.append(f"- Largest total flow share of all bytes: {_pct(largest.get('largest_total_share_pct', 0.0))}")

    return "\n".join(lines)

def build_flow_context(flow: dict[str, Any]) -> str:
    lines: list[str] = []

    lines.append(f"Source IP: {flow.get('src_ip', '')}")
    lines.append(f"Source Port: {flow.get('src_port', '')}")
    lines.append(f"Destination IP: {flow.get('dst_ip', '')}")
    lines.append(f"Destination Port: {flow.get('dst_port', '')}")
    lines.append(f"Protocol: {format_ip_proto_with_description(flow.get('protocol', ''))}")
    lines.append(f"Application: {flow.get('application_name', '')}")
    lines.append(f"Bytes: {flow.get('bidirectional_bytes', '')}")
    lines.append(f"Packets: {flow.get('bidirectional_packets', '')}")
    lines.append(f"Duration (ms): {flow.get('bidirectional_duration_ms', '')}")
    lines.append(f"Requested server name / hostname field: {flow.get('requested_server_name', '')}")

    return "\n".join(lines)

def build_finding_context(finding: dict[str, Any]) -> str:
    lines: list[str] = []

    lines.append(f"Finding ID: {finding.get('id', '')}")
    lines.append(f"Title: {finding.get('title', '')}")
    lines.append(f"Status: {finding.get('status', '')}")
    lines.append(f"Created: {finding.get('created_at', '')}")
    lines.append(f"Tags: {finding.get('tags', '')}")
    lines.append("")

    lines.append(f"Source IP: {finding.get('src_ip', '')}")
    lines.append(f"Source Port: {finding.get('src_port', '')}")
    lines.append(f"Destination IP: {finding.get('dst_ip', '')}")
    lines.append(f"Destination Port: {finding.get('dst_port', '')}")
    lines.append(f"Protocol: {format_ip_proto_with_description(finding.get('protocol', ''))}")
    lines.append(f"Application: {finding.get('application_name', '')}")
    lines.append(f"Bytes: {finding.get('bidirectional_bytes', '')}")
    lines.append(f"Packets: {finding.get('bidirectional_packets', '')}")
    lines.append(f"Duration (ms): {finding.get('bidirectional_duration_ms', '')}")
    lines.append(f"Requested server name / hostname field: {finding.get('requested_server_name', '')}")
    lines.append("")
    lines.append("Finding note:")
    lines.append(str(finding.get("note", "") or ""))
    lines.append("")
    lines.append("Important: roles of IPs, hostname meaning, and traffic purpose are not confirmed unless explicitly stated above.")

    return "\n".join(lines)


def build_pcap_context(
    summary: PcapSummary,
    project_name: str = "",
    limit: int = 12,
    *,
    period_label: str = "",
    period_mode: str = "day",
) -> str:
    investigator = build_investigator_view(summary)
    artifact_counts: dict[str, int] = {}
    for artifact in summary.artifacts or []:
        category = str(artifact.get("category") or "Other")
        artifact_counts[category] = artifact_counts.get(category, 0) + 1

    mode = str(period_mode or "day").strip().casefold()
    month_aggregate = mode.startswith("month")

    lines: list[str] = []
    lines.append(f"Project: {project_name or '(none)'}")
    lines.append(f"PCAP file: {summary.file_name}")
    lines.append(f"Source path: {summary.file_path}")
    if period_label:
        scope = "month aggregate" if month_aggregate else "single day"
        lines.append(f"Loaded period: {period_label} ({scope})")
    lines.append("Goal: explain what is visible in this packet capture for an investigator.")
    lines.append("")
    lines.append("Capture facts:")
    lines.append(f"- Format: {summary.format}")
    lines.append(f"- Packets: {summary.packet_count:,}")
    lines.append(f"- Wire bytes: {human_bytes(summary.wire_bytes, precision=2)}")
    lines.append(f"- Capture period: {summary.first_seen or '-'} to {summary.last_seen or '-'}")
    lines.append(f"- Duration seconds: {summary.duration_seconds:.1f}")
    lines.append(f"- Device IP: {summary.likely_device_ip or '-'}")
    lines.append("")

    lines.append("Plain-language investigator summary generated from deterministic analysis:")
    lines.append(str(investigator.get("plain_summary") or "-"))
    lines.append("")

    lines.append("Key deterministic points:")
    for point in investigator.get("key_points") or []:
        lines.append(f"- {point}")
    lines.append("")

    lines.append("Visibility limitations that must be preserved:")
    for item in investigator.get("limitations") or []:
        lines.append(f"- {item}")
    lines.append("")

    lines.append("Service groups / visible service families:")
    for row in (investigator.get("service_rows") or [])[:limit]:
        lines.append(
            f"- {row.get('service')}: {row.get('count')} signals, "
            f"share {float(row.get('share') or 0.0):.1f}%, example {row.get('example') or '-'}"
        )
    lines.append("")

    lines.append("Visibility breakdown:")
    for row in (investigator.get("visibility_rows") or [])[:limit]:
        lines.append(
            f"- {row.get('visibility')}: {row.get('count')} signals, "
            f"share {float(row.get('share') or 0.0):.1f}%"
        )
    lines.append("")

    lines.append("Activity by hour:")
    for row in (investigator.get("activity_rows") or [])[:limit]:
        lines.append(f"- {row.get('hour')}: {row.get('packets')} packets, share {float(row.get('share') or 0.0):.1f}%")
    lines.append("")

    lines.append("Communication highlights / app activity indicators:")
    communication_rows = summary.communication_rows or []
    if communication_rows:
        for row in communication_rows[:limit]:
            lines.append(
                f"- {row.get('service')}: {row.get('activity_type')} "
                f"({row.get('confidence')} confidence); host {row.get('host') or '-'}; "
                f"evidence: {row.get('evidence')}"
            )
    else:
        lines.append("- No app communication indicators were classified.")
    lines.append("")

    lines.append("Artifact categories:")
    if artifact_counts:
        for category, count in sorted(artifact_counts.items()):
            lines.append(f"- {category}: {count}")
    else:
        lines.append("- No extracted artifacts.")
    lines.append("")

    lines.append("Top extracted artifacts:")
    for artifact in (summary.artifacts or [])[:limit]:
        lines.append(
            f"- {artifact.get('category')} / {artifact.get('type')}: "
            f"{artifact.get('value')} ({artifact.get('count')}x, {artifact.get('visibility')}); "
            f"{artifact.get('explanation')}"
        )
    lines.append("")

    lines.append("Readable evidence samples:")
    for sample in (summary.readable_samples or [])[:limit]:
        lines.append(
            f"- {sample.get('time')} {sample.get('type')}: "
            f"{sample.get('source')} -> {sample.get('destination')}; {sample.get('value')}"
        )
    lines.append("")

    lines.append("Top connections by volume:")
    for flow in (summary.flows or [])[:limit]:
        lines.append(
            "- "
            f"{flow.get('src_ip')}:{flow.get('src_port')} -> {flow.get('dst_ip')}:{flow.get('dst_port')}, "
            f"protocol {format_ip_proto_with_description(flow.get('protocol'))}, "
            f"application {flow.get('application_name') or '-'}, "
            f"host/query {flow.get('requested_server_name') or '-'}, "
            f"bytes {human_bytes(flow.get('bidirectional_bytes', 0), precision=2)}, "
            f"packets {flow.get('bidirectional_packets', 0)}"
        )
    lines.append("")
    lines.append("Important: DNS names, TLS SNI names, endpoints, ports and timing are metadata. They show communication patterns, not message contents.")
    lines.append("Important: Credentials or payload contents are present only if explicitly listed above as plaintext evidence or artifacts.")

    return "\n".join(lines)


def build_activity_profile_context(
    profile: dict[str, Any],
    project_name: str = "",
    limit: int = 12,
) -> str:
    lines: list[str] = []
    lines.append(f"Project: {project_name or '(none)'}")
    lines.append("Goal: explain the case activity profile built from saved ViaNyquist project evidence.")
    lines.append("Scope: project-wide saved evidence, not filtered by the Explore/PCAP period selector.")
    lines.append("")

    lines.append("Case snapshot:")
    for line in profile.get("summary_lines") or []:
        lines.append(str(line))
    lines.append("")

    lines.append("Evidence counts:")
    for row in profile.get("evidence_counts") or []:
        lines.append(f"- {row.get('label')}: {row.get('count')}")
    lines.append("")

    lines.append("PCAP device IP distribution:")
    device_rows = profile.get("pcap_device_ip_rows") or []
    if device_rows:
        for row in device_rows[:limit]:
            lines.append(f"- {row.get('label')}: {row.get('count')}")
    else:
        lines.append("- No saved PCAP device IPs.")
    lines.append("")

    lines.append("Activity event type distribution:")
    activity_rows = profile.get("activity_type_rows") or []
    if activity_rows:
        for row in activity_rows[:limit]:
            lines.append(f"- {row.get('label')}: {row.get('count')}")
    else:
        lines.append("- No activity events.")
    lines.append("")

    capture_range = profile.get("capture_range") or {}
    lines.append("Observed PCAP capture range:")
    lines.append(f"- {capture_range.get('label') or '-'}")
    lines.append("")

    behavior = profile.get("behavior_profile") or {}
    if behavior:
        lines.append("Loaded-dataset behavior indicators:")
        lines.append(f"- Flow count: {behavior.get('flow_count', 0)}")
        lines.append(f"- Total volume: {behavior.get('total_bytes_label') or human_bytes(behavior.get('total_bytes', 0), precision=2)}")
        dataset_info = behavior.get("project_dataset_info") or {}
        if dataset_info:
            loaded_files = dataset_info.get("loaded_json_file_count", 0)
            file_count = dataset_info.get("json_file_count", 0)
            lines.append(
                "- Project JSON files included: "
                f"{loaded_files} / {file_count}; "
                f"saved sources {dataset_info.get('loaded_source_count', 0)} / {dataset_info.get('source_count', 0)}; "
                f"deduped paths {dataset_info.get('deduped_path_count', 0)}; "
                f"missing/error paths {len(dataset_info.get('missing_rows') or [])}"
            )
        lines.append("Service groups by volume:")
        service_rows = behavior.get("service_rows") or []
        if service_rows:
            for row in service_rows[:limit]:
                lines.append(
                    f"- {row.get('label')}: {row.get('bytes_label')}, "
                    f"{row.get('count')} flows, example {row.get('example') or '-'}"
                )
        else:
            lines.append("- No visible service groups.")
        lines.append("Observed domains by volume:")
        domain_rows = behavior.get("domain_rows") or []
        if domain_rows:
            for row in domain_rows[:limit]:
                lines.append(f"- {row.get('label')}: {row.get('bytes_label')}, {row.get('count')} flows")
        else:
            lines.append("- No visible hostnames.")
        lines.append("Activity rhythm:")
        for line in behavior.get("routine_lines") or []:
            lines.append(f"- {line}")
        lines.append("")

    lines.append("Recent project timeline:")
    timeline = profile.get("timeline_lines") or []
    if timeline:
        for line in timeline[:limit]:
            lines.append(str(line))
    else:
        lines.append("- No project activity yet.")
    lines.append("")
    lines.append("Important: this profile describes saved project evidence and observed device/network activity. It does not prove a person's identity, intent, or full communication content.")

    return "\n".join(lines)
