from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from core.timeutils import parse_timestamp


def resolve_period_day(
    *,
    active_day: str = "",
    file_paths: list[str] | None = None,
    first_seen: str = "",
    last_seen: str = "",
) -> str:
    day = (active_day or "").strip()
    if day and day != "undated":
        return day

    for value in (first_seen, last_seen):
        parsed = _iso_day(value)
        if parsed:
            return parsed

    for path in file_paths or []:
        parsed = _iso_day_from_path(str(path))
        if parsed:
            return parsed

    return ""


def aggregate_hash_for_paths(paths: list[str]) -> str:
    digest = hashlib.sha256()
    for raw_path in sorted(str(path) for path in paths if str(path or "").strip()):
        path = Path(raw_path)
        try:
            stat = path.stat()
            marker = f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}"
        except Exception:
            marker = f"{raw_path}|missing"
        digest.update(marker.encode("utf-8", errors="replace"))
        digest.update(b"\n")
    return "aggregate:" + digest.hexdigest()


def _iso_day(value: str) -> str:
    dt = parse_timestamp(value)
    return "" if dt is None else dt.strftime("%Y-%m-%d")


def _iso_day_from_path(value: str) -> str:
    text = str(value or "")
    match = re.search(r"(20\d{6})", text)
    if match:
        raw = match.group(1)
        return f"{raw[:4]}-{raw[4:6]}-{raw[6:8]}"
    for pattern in (
        r"(20\d{2})[-_/\.]([01]\d)[-_/\.]([0-3]\d)",
        r"([0-3]\d)[-_/\.]([01]\d)[-_/\.](20\d{2})",
    ):
        match = re.search(pattern, text)
        if not match:
            continue
        groups = match.groups()
        if len(groups[0]) == 4:
            year, month, day = groups
        else:
            day, month, year = groups
        try:
            return f"{int(year):04d}-{int(month):02d}-{int(day):02d}"
        except Exception:
            continue
    return ""


def capture_span_note(first_seen: str, last_seen: str, *, period_day: str = "") -> str:
    """Explain gaps inside a calendar day (first/last packet vs full day)."""
    start = parse_timestamp(first_seen)
    end = parse_timestamp(last_seen)
    if start is None or end is None:
        return ""

    duration = max(0.0, end.timestamp() - start.timestamp())
    hours = int(duration // 3600)
    minutes = int((duration % 3600) // 60)
    span = f"{hours}h {minutes}m" if hours else f"{minutes}m"

    if period_day:
        try:
            from datetime import datetime

            day_start = datetime.strptime(period_day, "%Y-%m-%d")
            lead = max(0, int((start - day_start).total_seconds() // 60))
            day_end = day_start.replace(hour=23, minute=59, second=59)
            trail = max(0, int((day_end - end).total_seconds() // 60))
            parts = [f"Observed packet span: {span}."]
            if lead >= 5:
                parts.append(f"No packets in the first {lead} minutes after midnight.")
            if trail >= 5:
                parts.append(f"No packets in the last {trail} minutes before midnight.")
            return " ".join(parts)
        except Exception:
            pass

    return f"Observed packet span: {span} (from first to last packet in the capture, not a full 24h window)."
