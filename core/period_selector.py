"""Shared day/month/range period selector state and rebuild logic (no Qt)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from core.period_groups import (
    is_range_period_key,
    parse_range_period_key,
    period_group_label,
    rollup_day_groups,
)

PERIOD_MODE_OPTIONS: tuple[tuple[str, str], ...] = (
    ("Day", "day"),
    ("Month", "month"),
    ("Selected period", "range"),
)


def normalize_period_mode(mode: str) -> str:
    text = str(mode or "day").strip().casefold()
    if text in {"range", "selected", "selected period", "selected_period"}:
        return "range"
    if text.startswith("month"):
        return "month"
    return "day"


def pick_range_button_visible(*, granularity: str, has_periods: bool) -> bool:
    return normalize_period_mode(granularity) == "range" and has_periods


def month_view_available(day_keys: Iterable[str]) -> bool:
    from core.period_gaps import complete_calendar_month_keys

    return bool(complete_calendar_month_keys(day_keys))


def infer_default_range_bounds(day_groups_raw: dict[str, list[str]]) -> tuple[str, str]:
    from core.period_gaps import normalize_period_day

    days = sorted(
        normalize_period_day(day)
        for day in day_groups_raw.keys()
        if normalize_period_day(day)
    )
    if len(days) < 2:
        return "", ""
    return days[0], days[-1]


@dataclass
class PeriodSelectorState:
    granularity: str = "day"
    range_start: str = ""
    range_end: str = ""
    day_groups_raw: dict[str, list[str]] = field(default_factory=dict)
    day_groups: dict[str, list[str]] = field(default_factory=dict)
    active_key: str = ""

    def clear(self, *, keep_raw: bool = False) -> None:
        if not keep_raw:
            self.day_groups_raw = {}
        self.day_groups = {}
        self.active_key = ""
        if not keep_raw:
            self.range_start = ""
            self.range_end = ""
            self.granularity = "day"

    def leaving_range_mode(self) -> None:
        self.range_start = ""
        self.range_end = ""


def restore_range_from_raw_keys(state: PeriodSelectorState) -> bool:
    """If raw groups contain a range key, restore range mode and bounds."""
    for key in state.day_groups_raw:
        if not is_range_period_key(key):
            continue
        start, end = parse_range_period_key(key)
        if not start or not end:
            continue
        state.range_start = start
        state.range_end = end
        state.granularity = "range"
        return True
    return False


def ensure_range_bounds(state: PeriodSelectorState) -> None:
    if normalize_period_mode(state.granularity) != "range":
        return
    if state.range_start and state.range_end:
        return
    start, end = infer_default_range_bounds(state.day_groups_raw)
    if start and end:
        state.range_start = start
        state.range_end = end


def compute_period_day_groups(
    day_groups_raw: dict[str, list[str]],
    *,
    granularity: str,
    range_start: str = "",
    range_end: str = "",
    sort_day_view: bool = False,
) -> tuple[dict[str, list[str]], str, bool]:
    """Roll up raw day groups.

    Returns ``(groups, effective_granularity, granularity_changed)``.
  """
    if not day_groups_raw:
        return {}, normalize_period_mode(granularity), False

    mode = normalize_period_mode(granularity)
    rolled = rollup_day_groups(
        day_groups_raw,
        granularity=mode,
        range_start=range_start,
        range_end=range_end,
    )
    if mode == "day" and sort_day_view:
        groups = dict(
            sorted(rolled.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True)
        )
    else:
        groups = rolled

    changed = False
    if not groups and mode == "month":
        mode = "day"
        changed = True
        rolled = rollup_day_groups(day_groups_raw, granularity="day")
        if sort_day_view:
            groups = dict(
                sorted(rolled.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True)
            )
        else:
            groups = rolled

    if not groups:
        groups = {
            str(day): list(paths or [])
            for day, paths in day_groups_raw.items()
        }

    return groups, mode, changed


def try_recover_range_groups(
    day_groups_raw: dict[str, list[str]],
    *,
    granularity: str,
    range_start: str,
    range_end: str,
) -> dict[str, list[str]]:
    if normalize_period_mode(granularity) != "range":
        return {}
    if not range_start or not range_end:
        return {}
    return rollup_day_groups(
        day_groups_raw,
        granularity="range",
        range_start=range_start,
        range_end=range_end,
    )


def build_period_combo_entries(
    day_groups: dict[str, list[str]],
    *,
    granularity: str,
    kind: str,
    label_saved_empty: bool = False,
) -> list[tuple[str, str, list[str]]]:
    from core.evidence_policy import format_period_day_label

    entries: list[tuple[str, str, list[str]]] = []
    for key, paths in day_groups.items():
        path_list = list(paths or [])
        label = period_group_label(
            key,
            granularity=granularity,
            file_count=len(path_list) or 1,
            kind=kind,
        )
        if label_saved_empty and not path_list:
            label = f"{format_period_day_label(key) or key} (saved)"
        entries.append((key, label, path_list))
    return entries


def pick_active_period_key(
    day_groups: dict[str, list[str]],
    *,
    active_key: str = "",
    previous_key: str = "",
) -> str:
    preferred = str(previous_key or active_key or "").strip()
    if preferred and preferred in day_groups:
        return preferred
    if day_groups:
        return next(iter(day_groups))
    return ""


def rebuild_period_selector(
    state: PeriodSelectorState,
    *,
    kind: str,
    sort_day_view: bool = False,
    recover_empty_range: bool = False,
    previous_key: str = "",
) -> list[str]:
    """Rebuild rolled groups and combo entries on ``state``.

    Returns file paths for the active period, or an empty list when nothing is selectable.
    """
    if not state.day_groups_raw:
        state.clear(keep_raw=False)
        return []

    groups, granularity, changed = compute_period_day_groups(
        state.day_groups_raw,
        granularity=state.granularity,
        range_start=state.range_start,
        range_end=state.range_end,
        sort_day_view=sort_day_view,
    )
    if changed:
        state.granularity = granularity

    if not groups and recover_empty_range:
        restore_range_from_raw_keys(state)
        ensure_range_bounds(state)
        groups = try_recover_range_groups(
            state.day_groups_raw,
            granularity=state.granularity,
            range_start=state.range_start,
            range_end=state.range_end,
        )

    if not groups:
        state.clear(keep_raw=True)
        return []

    state.day_groups = groups
    state.granularity = granularity
    state.active_key = pick_active_period_key(
        groups,
        active_key=state.active_key,
        previous_key=previous_key,
    )
    return list(groups.get(state.active_key, []))
