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


def format_duration_hms_ms(value: Any) -> str:
    try:
        ms = int(float(value))
    except Exception:
        return "" if value is None else str(value)

    hours = ms // 3_600_000
    minutes = (ms % 3_600_000) // 60_000
    seconds = (ms % 60_000) // 1000
    millis = ms % 1000
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}.{millis:03d}"
