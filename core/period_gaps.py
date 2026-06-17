from __future__ import annotations

import calendar
from datetime import date, timedelta
from typing import Iterable

from core.evidence_policy import format_period_day_label
from core.period_groups import month_key


def normalize_period_day(value: str) -> str:
    text = str(value or "").strip()
    if len(text) >= 10 and text[4] == "-" and text[7] == "-":
        return text[:10]
    return ""


def calendar_days_between(first_day: str, last_day: str) -> list[str]:
    first = normalize_period_day(first_day)
    last = normalize_period_day(last_day)
    if not first or not last:
        return []
    start = date.fromisoformat(first)
    end = date.fromisoformat(last)
    if end < start:
        start, end = end, start
    out: list[str] = []
    current = start
    while current <= end:
        out.append(current.isoformat())
        current += timedelta(days=1)
    return out


def missing_period_days(present_days: Iterable[str]) -> dict[str, object]:
    """Return calendar gaps between earliest and latest indexed day."""
    normalized = sorted({day for day in (normalize_period_day(item) for item in present_days) if day})
    if not normalized:
        return {
            "first_day": "",
            "last_day": "",
            "present_days": [],
            "missing_days": [],
            "present_count": 0,
            "expected_count": 0,
            "missing_count": 0,
        }

    expected = calendar_days_between(normalized[0], normalized[-1])
    present_set = set(normalized)
    missing = [day for day in expected if day not in present_set]
    return {
        "first_day": normalized[0],
        "last_day": normalized[-1],
        "present_days": normalized,
        "missing_days": missing,
        "present_count": len(present_set),
        "expected_count": len(expected),
        "missing_count": len(missing),
    }


def is_month_period_key(value: str) -> bool:
    text = str(value or "").strip()
    return len(text) == 7 and text[4] == "-"


def calendar_days_in_month(month: str) -> list[str]:
    text = str(month or "").strip()
    if not is_month_period_key(text):
        return []
    year = int(text[:4])
    month_num = int(text[5:7])
    last_day = calendar.monthrange(year, month_num)[1]
    return [f"{year:04d}-{month_num:02d}-{day:02d}" for day in range(1, last_day + 1)]


def indexed_days_for_month(month: str, present_days: Iterable[str]) -> list[str]:
    prefix = f"{str(month or '').strip()}-"
    if not is_month_period_key(month):
        return []
    return sorted(
        {
            normalize_period_day(day)
            for day in present_days
            if normalize_period_day(day).startswith(prefix)
        }
    )


def missing_calendar_month_days(month: str, present_days: Iterable[str]) -> list[str]:
    expected = calendar_days_in_month(month)
    if not expected:
        return []
    present = set(indexed_days_for_month(month, present_days))
    return [day for day in expected if day not in present]


def is_complete_calendar_month(month: str, present_days: Iterable[str]) -> bool:
    if not is_month_period_key(month):
        return False
    return not missing_calendar_month_days(month, present_days)


def complete_calendar_month_keys(present_days: Iterable[str]) -> list[str]:
    months = sorted({month_key(day) for day in present_days if normalize_period_day(day)})
    return [month for month in months if month != "undated" and is_complete_calendar_month(month, present_days)]


def summarize_partial_months(present_days: Iterable[str], *, preview: int = 3) -> str:
    partial: list[str] = []
    seen: set[str] = set()
    for day in sorted({normalize_period_day(item) for item in present_days if normalize_period_day(item)}):
        month = month_key(day)
        if month in seen or month == "undated" or is_complete_calendar_month(month, present_days):
            if month != "undated":
                seen.add(month)
            continue
        seen.add(month)
        indexed = indexed_days_for_month(month, present_days)
        expected = len(calendar_days_in_month(month))
        partial.append(f"{month[5:7]}/{month[:4]} ({len(indexed)}/{expected} days)")
    if not partial:
        return ""
    shown = ", ".join(partial[:preview])
    extra = max(0, len(partial) - preview)
    if extra:
        shown = f"{shown} (+{extra:,} more)"
    return f"Partial months (Day view only): {shown}"


def format_period_gap_summary(
    present_days: Iterable[str],
    *,
    granularity: str = "day",
    preview: int = 6,
) -> str:
    mode = str(granularity or "day").strip().casefold()
    keys = [str(day or "").strip() for day in present_days if str(day or "").strip()]
    if mode.startswith("month") or any(is_month_period_key(key) for key in keys):
        count = len(keys)
        if count == 0:
            return "No indexed periods yet."
        if count == 1:
            return f"Month view: 1 period indexed. Switch to Day view for missing-day detection."
        return f"Month view: {count:,} periods indexed. Switch to Day view for missing-day detection."
    return format_missing_days_summary(missing_period_days(keys), preview=preview)


def missing_days_in_range(
    present_days: Iterable[str],
    start_day: str,
    end_day: str,
) -> list[str]:
    expected = calendar_days_between(start_day, end_day)
    if not expected:
        return []
    present = {normalize_period_day(day) for day in present_days if normalize_period_day(day)}
    return [day for day in expected if day not in present]


def format_missing_days_summary(gap: dict[str, object], *, preview: int = 6) -> str:
    missing = list(gap.get("missing_days") or [])
    first = format_period_day_label(str(gap.get("first_day") or ""))
    last = format_period_day_label(str(gap.get("last_day") or ""))
    present_count = int(gap.get("present_count") or 0)
    expected_count = int(gap.get("expected_count") or 0)

    if not first or not last:
        return "No indexed days yet."

    if not missing:
        return f"Period coverage complete: {first} – {last} ({present_count:,}/{expected_count:,} days)"

    labels = [format_period_day_label(day) or day for day in missing[:preview]]
    extra = max(0, len(missing) - len(labels))
    joined = ", ".join(labels)
    if extra:
        joined = f"{joined} (+{extra:,} more)"
    return (
        f"{first} – {last}: {present_count:,}/{expected_count:,} days indexed · "
        f"{len(missing):,} internal gap{'s' if len(missing) != 1 else ''}: {joined}"
    )
