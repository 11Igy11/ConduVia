from __future__ import annotations

from collections import defaultdict
from typing import Iterable


def month_key(day: str) -> str:
    text = str(day or "").strip()
    if len(text) >= 7 and text[4:5] == "-":
        return text[:7]
    return "undated"


def group_paths_by_month(day_groups: dict[str, list[str]]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = defaultdict(list)
    for day, paths in (day_groups or {}).items():
        key = month_key(day)
        for path in paths or []:
            if path and path not in grouped[key]:
                grouped[key].append(path)
    return dict(sorted(grouped.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True))


RANGE_KEY_PREFIX = "range:"


def is_range_period_key(value: str) -> bool:
    return str(value or "").strip().startswith(RANGE_KEY_PREFIX)


def make_range_period_key(start_day: str, end_day: str) -> str:
    from core.period_gaps import normalize_period_day

    start = normalize_period_day(start_day)
    end = normalize_period_day(end_day)
    if not start or not end:
        return ""
    if end < start:
        start, end = end, start
    return f"{RANGE_KEY_PREFIX}{start}:{end}"


def parse_range_period_key(value: str) -> tuple[str, str]:
    text = str(value or "").strip()
    if not text.startswith(RANGE_KEY_PREFIX):
        return "", ""
    parts = text.split(":", 2)
    if len(parts) < 3:
        return "", ""
    return parts[1], parts[2]


def rollup_day_groups_for_range(
    day_groups: dict[str, list[str]],
    start_day: str,
    end_day: str,
) -> dict[str, list[str]]:
    from core.period_gaps import calendar_days_between, normalize_period_day

    allowed = set(calendar_days_between(start_day, end_day))
    if not allowed:
        return {}
    merged: list[str] = []
    for day in sorted(day_groups.keys()):
        normalized = normalize_period_day(day)
        if normalized not in allowed:
            continue
        for path in day_groups.get(day) or []:
            text = str(path or "").strip()
            if text and text not in merged:
                merged.append(text)
    if not merged:
        return {}
    key = make_range_period_key(start_day, end_day)
    return {key: merged}


def rollup_day_groups(
    day_groups: dict[str, list[str]],
    *,
    granularity: str,
    complete_months_only: bool = True,
    range_start: str = "",
    range_end: str = "",
) -> dict[str, list[str]]:
    cleaned = {
        str(day): [str(path) for path in (paths or []) if str(path or "").strip()]
        for day, paths in (day_groups or {}).items()
    }
    cleaned = {day: paths for day, paths in cleaned.items() if paths or day}
    mode = str(granularity or "day").strip().casefold()
    if mode in {"range", "selected", "selected period", "selected_period"}:
        return rollup_day_groups_for_range(cleaned, range_start, range_end)
    if mode.startswith("month"):
        rolled = group_paths_by_month(cleaned)
        if complete_months_only:
            from core.period_gaps import complete_calendar_month_keys

            allowed = set(complete_calendar_month_keys(cleaned.keys()))
            rolled = {key: paths for key, paths in rolled.items() if key in allowed}
        return rolled
    return dict(sorted(cleaned.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True))


def period_group_label(key: str, *, granularity: str, file_count: int, kind: str = "JSON") -> str:
    from core.evidence_policy import format_period_day_label, period_combo_label

    mode = str(granularity or "day").strip().casefold()
    if is_range_period_key(key):
        start, end = parse_range_period_key(key)
        if start and end:
            label = f"{format_period_day_label(start)} – {format_period_day_label(end)}"
            suffix = f"{file_count:,} {kind} files" if file_count != 1 else f"1 {kind} file"
            return f"{label} ({suffix})"
    if mode.startswith("month") and key != "undated" and len(key) == 7:
        year, month = key.split("-", 1)
        label = f"{month}/{year}"
        suffix = f"{file_count:,} {kind} files" if file_count != 1 else f"1 {kind} file"
        return f"{label} ({suffix})"
    return period_combo_label(key, file_count, kind=kind)
