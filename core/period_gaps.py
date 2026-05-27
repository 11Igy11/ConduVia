from __future__ import annotations

from datetime import date, timedelta
from typing import Iterable

from core.evidence_policy import format_period_day_label


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


def format_missing_days_summary(gap: dict[str, object], *, preview: int = 6) -> str:
    missing = list(gap.get("missing_days") or [])
    first = format_period_day_label(str(gap.get("first_day") or ""))
    last = format_period_day_label(str(gap.get("last_day") or ""))
    present_count = int(gap.get("present_count") or 0)
    expected_count = int(gap.get("expected_count") or 0)

    if not first or not last:
        return "No indexed PCAP days yet."

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
