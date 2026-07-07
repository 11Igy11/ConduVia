from __future__ import annotations

from typing import Any

from core.formatters import (
    format_duration_compact_ms,
    format_flow_date,
    format_flow_datetime,
    format_flow_time,
    human_bytes,
)
from core.protocols import format_ip_proto
from core.timeutils import parse_timestamp

DEFAULT_FLOW_COLUMNS: list[str] = [
    "date",
    "time",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "application_name",
    "requested_server_name",
    "bidirectional_bytes",
    "bidirectional_packets",
    "bidirectional_duration_ms",
]

FLOW_VIEW_MODES = ("Default", "All fields", "Custom")

HEADER_LABELS: dict[str, str] = {
    "date": "Date",
    "time": "Time",
    "src_ip": "Source IP",
    "src_port": "Source Port",
    "dst_ip": "Destination IP",
    "dst_port": "Destination Port",
    "protocol": "Protocol",
    "application_name": "Application",
    "requested_server_name": "Server Name",
    "bidirectional_bytes": "Volume",
    "bidirectional_packets": "Packets",
    "bidirectional_duration_ms": "Duration",
}

FRIENDLY_OVERRIDES: dict[str, str] = {
    "id": "ID",
    "expiration_id": "Expiration ID",
    "src_mac": "Source MAC",
    "dst_mac": "Destination MAC",
    "src_oui": "Source OUI",
    "dst_oui": "Destination OUI",
    "ip_version": "IP Version",
    "vlan_id": "VLAN ID",
    "tunnel_id": "Tunnel ID",
    "bidirectional_first_seen_ms": "First Seen",
    "bidirectional_last_seen_ms": "Last Seen",
    "src2dst_first_seen_ms": "Src → Dst First Seen",
    "src2dst_last_seen_ms": "Src → Dst Last Seen",
    "dst2src_first_seen_ms": "Dst → Src First Seen",
    "dst2src_last_seen_ms": "Dst → Src Last Seen",
    "src2dst_duration_ms": "Src → Dst Duration",
    "dst2src_duration_ms": "Dst → Src Duration",
    "src2dst_bytes": "Src → Dst Volume",
    "dst2src_bytes": "Dst → Src Volume",
    "src2dst_packets": "Src → Dst Packets",
    "dst2src_packets": "Dst → Src Packets",
}


def friendly_label(key: str) -> str:
    column = str(key or "").strip()
    if column in HEADER_LABELS:
        return HEADER_LABELS[column]
    if column in FRIENDLY_OVERRIDES:
        return FRIENDLY_OVERRIDES[column]
    return column.replace("_", " ").title()


def available_flow_columns(flows: list[dict[str, Any]] | None) -> list[str]:
    if not flows:
        return list(DEFAULT_FLOW_COLUMNS)

    raw_keys = list(flows[0].keys())
    derived = ["date", "time"]
    excluded = {"bidirectional_first_seen_ms"}
    result = list(derived)
    for key in raw_keys:
        if key not in excluded and key not in result:
            result.append(key)
    return result


def flow_cell_display(key: str, flow: dict[str, Any]) -> str:
    column = str(key or "").strip()
    value = flow.get(column, "")

    if column in ("date", "time"):
        raw_value = flow.get("bidirectional_first_seen_ms", "")
        if column == "date":
            return format_flow_date(raw_value) or str(raw_value or "")
        return format_flow_time(raw_value) or str(raw_value or "")

    if column.endswith("_seen_ms"):
        return format_flow_datetime(value)

    if column == "bidirectional_bytes":
        return human_bytes(value, precision=2)

    if column == "bidirectional_duration_ms":
        return format_duration_compact_ms(value)

    if column == "protocol":
        return format_ip_proto(value)

    return "" if value is None else str(value)


def flow_cell_sort_value(key: str, flow: dict[str, Any]) -> Any:
    column = str(key or "").strip()
    value = flow.get(column)

    if column in ("date", "time"):
        dt = parse_timestamp(flow.get("bidirectional_first_seen_ms"))
        return dt.timestamp() if dt is not None else 0

    if column.endswith("_seen_ms"):
        dt = parse_timestamp(value)
        return dt.timestamp() if dt is not None else 0

    if column in {
        "bidirectional_bytes",
        "bidirectional_duration_ms",
        "bidirectional_packets",
        "src_port",
        "dst_port",
        "protocol",
    }:
        try:
            return float(value)
        except Exception:
            return 0

    return str(value or "").lower()
