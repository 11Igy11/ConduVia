from __future__ import annotations

from typing import Any

from core.timeutils import parse_timestamp


def safe_int(value: Any) -> int:
    try:
        return int(float(value or 0))
    except Exception:
        return 0


def human_bytes(value: Any, *, precision: int = 1) -> str:
    try:
        size = float(value or 0)
    except Exception:
        size = 0.0

    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0

    while size >= 1024 and idx < len(units) - 1:
        size /= 1024.0
        idx += 1

    if idx == 0:
        return f"{int(size)} {units[idx]}"

    return f"{size:.{precision}f} {units[idx]}"


def bytes_mb_or_b(value: Any, *, precision: int = 2) -> str:
    try:
        size = float(value or 0)
    except Exception:
        size = 0.0

    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.{precision}f} MB"
    return f"{int(size):,} B"


def format_flow_date(value: Any) -> str:
    dt = parse_timestamp(value)
    return "" if dt is None else dt.strftime("%d.%m.%Y")


def format_flow_time(value: Any) -> str:
    dt = parse_timestamp(value)
    return "" if dt is None else dt.strftime("%H:%M:%S")


def format_flow_datetime(value: Any, *, milliseconds: bool = False) -> str:
    dt = parse_timestamp(value)
    if dt is None:
        return "" if value is None else str(value)

    if milliseconds:
        return dt.strftime("%d.%m.%Y %H:%M:%S.%f")[:-3]

    return dt.strftime("%d.%m.%Y %H:%M:%S")


def format_pcap_datetime(value: Any, *, milliseconds: bool = True) -> str:
    dt = parse_timestamp(value)
    if dt is None:
        return "" if value is None else str(value)

    if milliseconds:
        return dt.strftime("%d/%m/%Y %H:%M:%S.%f")[:-3]

    return dt.strftime("%d/%m/%Y %H:%M:%S")


def format_short_date(value: Any, *, missing: str = "-") -> str:
    dt = parse_timestamp(value)
    if dt is None:
        return missing if not value else str(value)

    return dt.strftime("%d.%m.%Y.")


def format_duration_compact_ms(value: Any) -> str:
    try:
        total_sec = int(float(value)) / 1000
    except Exception:
        return "" if value is None else str(value)

    minutes = int(total_sec // 60)
    seconds = int(total_sec % 60)
    return f"{minutes}m {seconds}s"


def format_export_datetime(value: Any) -> str:
    """Unified export timestamp: dd.mm.yyyy HH:MM:SS."""
    return format_flow_datetime(value)


def format_export_bytes(value: Any, *, precision: int = 2) -> str:
    """Unified export volume using B / KB / MB / GB."""
    return human_bytes(value, precision=precision)


def format_export_cell(key: str, value: Any, *, flow: dict | None = None) -> str:
    column = str(key or "").strip()
    if column in ("date", "time") and flow is not None:
        raw_value = flow.get("bidirectional_first_seen_ms", "")
        if column == "date":
            return format_flow_date(raw_value) or str(raw_value or "")
        return format_flow_time(raw_value) or str(raw_value or "")
    if column.endswith("_seen_ms"):
        return format_export_datetime(value)
    if column.endswith("_bytes") or column in {"bidirectional_bytes", "src2dst_bytes", "dst2src_bytes"}:
        return format_export_bytes(value)
    if column.endswith("_duration_ms"):
        return format_duration_compact_ms(value)
    if column == "protocol":
        from core.protocols import format_ip_proto

        return format_ip_proto(value)
    if value is None:
        return ""
    return str(value)
