"""Calendar-day normalization for JSON flows and PCAP summaries."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from core.period_gaps import normalize_period_day
from core.timeutils import LOCAL_TZ, parse_timestamp

FLOW_TIMESTAMP_FIELDS: tuple[str, ...] = (
    "bidirectional_first_seen_ms",
    "bidirectional_last_seen_ms",
    "first_seen",
    "timestamp",
)


def calendar_day_bounds(day: str) -> tuple[datetime, datetime] | None:
    normalized = normalize_period_day(day)
    if not normalized or normalized == "undated":
        return None
    try:
        start = datetime.strptime(normalized, "%Y-%m-%d").replace(tzinfo=LOCAL_TZ)
    except ValueError:
        return None
    return start, start + timedelta(days=1)


def adjacent_calendar_days(day: str) -> list[str]:
    bounds = calendar_day_bounds(day)
    if bounds is None:
        return []
    start, _end = bounds
    days: list[str] = []
    for delta in (-1, 1):
        days.append((start + timedelta(days=delta)).strftime("%Y-%m-%d"))
    return days


def flow_timestamps_on_calendar_day(flow: dict[str, Any], day: str) -> list[datetime]:
    bounds = calendar_day_bounds(day)
    if bounds is None:
        return []
    start, end = bounds
    timestamps: list[datetime] = []
    for field in FLOW_TIMESTAMP_FIELDS:
        dt = parse_timestamp(flow.get(field))
        if dt is not None and start <= dt < end:
            timestamps.append(dt)
    return timestamps


def flow_on_calendar_day(flow: dict[str, Any], day: str) -> bool:
    return bool(flow_timestamps_on_calendar_day(flow, day))


def filter_flows_to_calendar_day(
    flows: list[dict[str, Any]],
    day: str,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    total = len(flows or [])
    if not day or not total:
        return list(flows or []), {"kept": total, "dropped": 0, "total": total}
    kept = [flow for flow in flows if flow_on_calendar_day(flow, day)]
    return kept, {"kept": len(kept), "dropped": total - len(kept), "total": total}


def expand_day_group_paths(day_groups: dict[str, list[str]], day: str) -> list[str]:
    """Include adjacent file buckets so midnight-spanning flows can be filtered by timestamp."""
    normalized = normalize_period_day(day)
    if not normalized or normalized == "undated":
        return list(day_groups.get(day, []) or [])

    paths: list[str] = []
    for key in [normalized, *adjacent_calendar_days(normalized)]:
        for path in day_groups.get(key, []) or []:
            if path not in paths:
                paths.append(path)
    return paths


def _format_summary_timestamp(dt: datetime) -> str:
    local = dt.astimezone(LOCAL_TZ).replace(tzinfo=None)
    return local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def format_calendar_day_window(day: str) -> tuple[str, str]:
    """Full calendar-day window for day-mode display (00:00:00.000 - 23:59:59.999)."""
    bounds = calendar_day_bounds(day)
    if bounds is None:
        return "", ""
    start, end = bounds
    display_end = end - timedelta(microseconds=1)
    return _format_summary_timestamp(start), _format_summary_timestamp(display_end)


def calendar_day_duration_seconds(day: str) -> float:
    bounds = calendar_day_bounds(day)
    if bounds is None:
        return 0.0
    start, end = bounds
    return max(0.0, (end - start).total_seconds())


def calendar_day_flow_bounds(
    flows: list[dict[str, Any]],
    day: str,
) -> tuple[str, str, float]:
    """First/last observed traffic timestamps inside the selected calendar day."""
    timestamps: list[datetime] = []
    for flow in flows or []:
        timestamps.extend(flow_timestamps_on_calendar_day(flow, day))
    if not timestamps:
        return "", "", 0.0
    first = min(timestamps)
    last = max(timestamps)
    duration_seconds = max(0.0, (last - first).total_seconds())
    return _format_summary_timestamp(first), _format_summary_timestamp(last), duration_seconds


def calendar_day_coverage_note(flows: list[dict[str, Any]], day: str) -> str:
    bounds = calendar_day_bounds(day)
    if bounds is None or not flows:
        return ""

    start, end = bounds
    timestamps: list[datetime] = []
    for flow in flows:
        timestamps.extend(flow_timestamps_on_calendar_day(flow, day))
    if not timestamps:
        return "No flow timestamps mapped to this calendar day."

    first = min(timestamps)
    last = max(timestamps)
    lead = max(0, int((first - start).total_seconds() // 60))
    trail = max(0, int((end - timedelta(seconds=1) - last).total_seconds() // 60))
    activity_start = first.astimezone(LOCAL_TZ).strftime("%H:%M:%S")
    activity_end = last.astimezone(LOCAL_TZ).strftime("%H:%M:%S")
    parts = [f"Traffic observed {activity_start}–{activity_end}."]
    if lead >= 5:
        parts.append(f"No flows in the first {lead} minutes of the day.")
    if trail >= 5:
        parts.append(f"No flows in the last {trail} minutes of the day.")
    return " ".join(parts)


def refine_pcap_summary_for_calendar_day(
    summary: Any,
    day: str,
    *,
    bucket_paths: list[str] | None = None,
) -> tuple[Any, str]:
    """Restrict PCAP flow-derived indicators to one calendar day."""
    from core.pcap_analyzer import PcapSummary, build_communication_rows

    if not isinstance(summary, PcapSummary) or not day:
        return summary, ""

    flows = list(summary.flows or [])
    filtered, stats = filter_flows_to_calendar_day(flows, day)
    note = calendar_day_coverage_note(filtered, day)

    if not filtered:
        return replace(
            summary,
            flows=[],
            communication_rows=[],
            total_flows=0,
            packet_count=0,
            wire_bytes=0,
            duration_seconds=0.0,
            first_seen="",
            last_seen="",
            source_paths=[str(path) for path in (bucket_paths or []) if str(path or "").strip()],
            notes=[*(summary.notes or []), "No flows mapped to the selected calendar day."],
        ), note

    first_seen, last_seen = format_calendar_day_window(day)
    duration_seconds = calendar_day_duration_seconds(day)
    packet_count = sum(int(flow.get("bidirectional_packets") or 0) for flow in filtered)
    wire_bytes = sum(int(flow.get("bidirectional_bytes") or 0) for flow in filtered)

    notes = list(summary.notes or [])
    if stats["dropped"] > 0:
        notes.append(
            f"Calendar-day filter kept {stats['kept']:,} of {stats['total']:,} flow summaries."
        )

    display_paths = [str(path) for path in (bucket_paths or []) if str(path or "").strip()]
    if not display_paths:
        display_paths = list(summary.source_paths or [])

    return replace(
        summary,
        flows=filtered,
        communication_rows=build_communication_rows(filtered),
        total_flows=len(filtered),
        packet_count=packet_count,
        wire_bytes=wire_bytes,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
        source_paths=display_paths,
        notes=notes,
    ), note
