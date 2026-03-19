from typing import Any

from core.analyzer import top_src_ips, top_dst_ips, top_applications, top_protocols
from core.protocols import format_ip_proto


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
    lines.append(f"Total flows in dataset: {actual_total}")
    lines.append(f"Flows used for AI summary: {len(flows)}")
    lines.append("")

    lines.append("Top source IPs:")
    for ip, count in top_src_ips(flows, limit=limit):
        lines.append(f"- {ip}: {count}")

    lines.append("")
    lines.append("Top destination IPs:")
    for ip, count in top_dst_ips(flows, limit=limit):
        lines.append(f"- {ip}: {count}")

    lines.append("")
    lines.append("Top protocols:")
    for proto, count in top_protocols(flows, limit=limit):
        lines.append(f"- {format_ip_proto(proto)}: {count}")

    lines.append("")
    lines.append("Top applications:")
    for app, count in top_applications(flows, limit=limit):
        lines.append(f"- {app}: {count}")

    return "\n".join(lines)

def build_flow_context(flow: dict[str, Any]) -> str:
    lines: list[str] = []

    lines.append(f"Source IP: {flow.get('src_ip', '')}")
    lines.append(f"Source Port: {flow.get('src_port', '')}")
    lines.append(f"Destination IP: {flow.get('dst_ip', '')}")
    lines.append(f"Destination Port: {flow.get('dst_port', '')}")
    lines.append(f"Protocol: {format_ip_proto(flow.get('protocol', ''))}")
    lines.append(f"Application: {flow.get('application_name', '')}")
    lines.append(f"Bytes: {flow.get('bidirectional_bytes', '')}")
    lines.append(f"Packets: {flow.get('bidirectional_packets', '')}")
    lines.append(f"Duration (ms): {flow.get('bidirectional_duration_ms', '')}")
    lines.append(f"Requested server name / hostname field: {flow.get('requested_server_name', '')}")

    return "\n".join(lines)