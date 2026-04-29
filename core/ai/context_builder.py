from typing import Any

from core.analyzer import top_applications, top_dst_ips, top_protocols, top_src_ips
from core.analyst import compute_analyst_summary
from core.flow_stats import top_field_by_bytes, top_flows_by_bytes
from core.formatters import human_bytes
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
) -> str:
    lines: list[str] = []

    actual_total = total_flows if total_flows is not None else len(flows)

    lines.append(f"Project: {project_name or '(none)'}")
    lines.append(f"Dataset: {dataset_path or '(none)'}")
    lines.append("Goal: describe observable device or user communication behavior based on network flow metadata.")
    lines.append(f"Total flows in dataset: {actual_total}")
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
    lines.append(f"- Coverage pattern: {coverage.get('pattern', 'unknown')}")
    lines.append(f"- Active days: {coverage.get('active_days', 0)}")
    lines.append(f"- Avg flows per active day: {float(coverage.get('avg_flows_per_active_day', 0.0) or 0.0):.1f}")
    lines.append(f"- Outbound share of total bytes: {_pct(bytes_info.get('outbound_share_total_pct', 0.0))}")
    lines.append(f"- Peak hour: {activity.get('peak_hour', 'unknown')}")
    lines.append(f"- Night share: {_pct(activity.get('night_share_pct', 0.0))}")
    lines.append(f"- Business-hours share: {_pct(activity.get('business_share_pct', 0.0))}")
    lines.append(f"- Behavior deviation score: {deviation.get('score', 0)}/100 ({deviation.get('level', 'LOW')})")
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
