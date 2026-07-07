from __future__ import annotations

import re
from typing import Any

from core.pcap_analyzer import PcapSummary, build_investigator_view

_ENDPOINT_RE = re.compile(r"^(?P<host>.+):(?P<port>\d+)$")


def parse_endpoint(value: object) -> tuple[str, int | None]:
    text = str(value or "").strip()
    if not text:
        return "", None
    match = _ENDPOINT_RE.match(text)
    if match:
        return match.group("host").strip(), int(match.group("port"))
    return text, None


def flow_from_communication_row(row: dict[str, Any]) -> dict[str, Any]:
    src_ip, src_port = parse_endpoint(row.get("source"))
    dst_ip, dst_port = parse_endpoint(row.get("destination"))
    return {
        "src_ip": src_ip or "0.0.0.0",
        "dst_ip": dst_ip or "0.0.0.0",
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": str(row.get("protocol") or ""),
        "application_name": str(row.get("service") or ""),
        "requested_server_name": str(row.get("host") or ""),
        "bidirectional_bytes": row.get("bytes"),
        "bidirectional_packets": row.get("packets"),
        "bidirectional_duration_ms": row.get("duration_ms"),
    }


def flow_from_pcap_summary(summary: PcapSummary) -> dict[str, Any]:
    rows = list(summary.communication_rows or [])
    if rows:
        flow = flow_from_communication_row(rows[0])
        device_ip = str(summary.likely_device_ip or "").strip()
        if device_ip and flow.get("src_ip") in {"", "0.0.0.0"}:
            flow["src_ip"] = device_ip
        return flow

    device_ip = str(summary.likely_device_ip or "").strip() or "0.0.0.0"
    dst_ip = "0.0.0.0"
    for endpoint in summary.top_endpoints or []:
        if isinstance(endpoint, dict):
            candidate = str(endpoint.get("ip") or endpoint.get("label") or "").strip()
        else:
            candidate = str(endpoint or "").strip()
        if candidate:
            dst_ip = parse_endpoint(candidate)[0] or candidate
            break

    return {
        "src_ip": device_ip,
        "dst_ip": dst_ip,
        "src_port": None,
        "dst_port": None,
        "protocol": "",
        "application_name": str(summary.file_name or "PCAP"),
        "requested_server_name": "",
        "bidirectional_bytes": summary.wire_bytes,
        "bidirectional_packets": summary.packet_count,
        "bidirectional_duration_ms": int((summary.duration_seconds or 0) * 1000),
    }


def default_communication_finding_title(row: dict[str, Any]) -> str:
    service = str(row.get("service") or "PCAP service").strip()
    activity = str(row.get("activity_label") or row.get("activity_type") or "indicator").strip()
    return f"PCAP: {service} — {activity}"


def default_period_finding_title(summary: PcapSummary, *, period_label: str = "") -> str:
    label = str(period_label or summary.file_name or "PCAP period").strip()
    return f"PCAP period: {label}"


def communication_finding_note(row: dict[str, Any]) -> str:
    indicator = row.get("activity_label") or row.get("activity_type") or "-"
    lines = [
        "PCAP communication indicator",
        f"Type: {row.get('type') or '-'}",
        f"Service: {row.get('service') or '-'}",
        f"Indicator: {indicator}",
        f"Confidence: {row.get('confidence') or '-'}",
        f"Sessions: {row.get('sessions') or 1}",
        f"Host / signal: {row.get('host') or '-'}",
        f"Source: {row.get('source') or '-'}",
        f"Destination: {row.get('destination') or '-'}",
        f"Protocol: {row.get('protocol') or '-'}",
        f"Packets: {row.get('packets') or 0}",
        "",
        "Evidence:",
        str(row.get("evidence") or "-"),
    ]
    return "\n".join(lines)


def period_finding_note(
    summary: PcapSummary,
    *,
    period_label: str = "",
    file_label: str = "",
) -> str:
    view = build_investigator_view(summary)
    lines = [
        "PCAP period finding",
        f"Period: {period_label or '-'}",
        f"Capture: {file_label or summary.file_name or '-'}",
        "",
        str(view.get("plain_summary") or "").strip(),
    ]
    key_points = str(view.get("key_points") or "").strip()
    if key_points:
        lines.extend(["", "Key points:", key_points])
    return "\n".join(line for line in lines if line is not None).strip()
