"""Shared narrative heuristics for JSON and PCAP investigation snapshots."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from core.formatters import format_flow_datetime, format_pcap_datetime, human_bytes
from core.service_classification import SOCIAL_MEDIA_SERVICES, classify_behavior_service, match_service
from core.timeutils import parse_flow_timestamp, parse_timestamp


def format_hour_label(hour: int | None) -> str:
    if hour is None:
        return ""
    try:
        value = int(hour)
    except (TypeError, ValueError):
        return ""
    if 0 <= value <= 23:
        return f"{value:02d}:00"
    return ""


def peak_hour_share_pct(hour_hist: list[int], peak_hour: int | None) -> float:
    if peak_hour is None:
        return 0.0
    total = sum(int(v or 0) for v in hour_hist)
    if total <= 0:
        return 0.0
    try:
        peak = int(hour_hist[int(peak_hour)] or 0)
    except (IndexError, TypeError, ValueError):
        return 0.0
    return (peak / total) * 100.0


def burst_hour_labels(
    hour_hist: list[int],
    *,
    min_flows: int = 5,
    ratio: float = 1.75,
    limit: int = 3,
) -> list[str]:
    if not hour_hist:
        return []
    candidates = [(hour, int(hour_hist[hour] or 0)) for hour in range(min(24, len(hour_hist))) if int(hour_hist[hour] or 0) >= min_flows]
    if not candidates:
        return []
    average = sum(count for _, count in candidates) / len(candidates)
    threshold = max(min_flows * 2, average * ratio)
    bursts = [(hour, count) for hour, count in candidates if count >= threshold]
    bursts.sort(key=lambda item: item[1], reverse=True)
    labels: list[str] = []
    for hour, count in bursts[:limit]:
        label = format_hour_label(hour)
        if label:
            labels.append(f"{label} ({count:,} flows)")
    return labels


def flow_activity_window(flows: list[dict[str, Any]]) -> tuple[datetime | None, datetime | None]:
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    for flow in flows or []:
        if not isinstance(flow, dict):
            continue
        dt = parse_flow_timestamp(flow)
        if dt is None:
            continue
        if first_seen is None or dt < first_seen:
            first_seen = dt
        if last_seen is None or dt > last_seen:
            last_seen = dt
    return first_seen, last_seen


def format_activity_window(first_seen: Any, last_seen: Any) -> str:
    start = parse_timestamp(first_seen) if not isinstance(first_seen, datetime) else first_seen
    end = parse_timestamp(last_seen) if not isinstance(last_seen, datetime) else last_seen
    if start is None or end is None:
        return ""
    start_text = format_flow_datetime(start, milliseconds=True)
    end_text = format_flow_datetime(end, milliseconds=True)
    if not start_text or not end_text:
        return ""
    return f"{start_text} – {end_text}"


def service_groups_from_flows(
    flows: list[dict[str, Any]],
    *,
    limit: int = 5,
) -> list[tuple[str, int, int]]:
    """Return (service label, flow count, bytes) sorted by bytes."""
    counts: Counter[str] = Counter()
    bytes_by_service: dict[str, int] = defaultdict(int)
    for flow in flows or []:
        if not isinstance(flow, dict):
            continue
        text = " ".join(
            str(flow.get(key) or "")
            for key in ("application_name", "requested_server_name", "http_host", "dns_query")
        )
        service = classify_behavior_service(text) or match_service(text)
        if not service:
            app = str(flow.get("application_name") or "").strip()
            service = app if app and app.lower() != "unknown" else ""
        if not service:
            continue
        counts[service] += 1
        bytes_by_service[service] += int(flow.get("bidirectional_bytes") or 0)

    ranked = sorted(bytes_by_service.items(), key=lambda item: item[1], reverse=True)
    return [(name, int(counts[name]), int(total_bytes)) for name, total_bytes in ranked[:limit]]


def messaging_and_social_lines(
    service_groups: list[tuple[str, int, int]],
    *,
    total_bytes: int,
) -> tuple[list[str], list[str]]:
    messaging: list[str] = []
    social: list[str] = []
    for name, flow_count, byte_count in service_groups:
        share = (byte_count / total_bytes * 100.0) if total_bytes > 0 else 0.0
        line = f"{name} ({human_bytes(byte_count, precision=2)}, {flow_count:,} flows, {share:.1f}%)"
        if name in SOCIAL_MEDIA_SERVICES:
            social.append(line)
        elif name in {
            "WhatsApp",
            "Telegram",
            "Viber",
            "Signal",
            "Facebook / Meta",
            "Apple / iCloud",
            "Microsoft / Teams",
            "Snapchat",
            "X / Twitter",
        }:
            messaging.append(line)
    return messaging, social


def largest_flow_narrative(flow: dict[str, Any] | None, *, outbound: bool = False) -> str:
    if not flow:
        return ""
    app = str(flow.get("application_name") or "").strip()
    sni = str(flow.get("sni") or flow.get("requested_server_name") or "").strip()
    service = classify_behavior_service(" ".join(part for part in (app, sni) if part))
    label = service or app or sni or "one large flow"
    volume = human_bytes(int(flow.get("bytes") or 0), precision=2)
    when = format_flow_datetime(flow.get("first_seen"), milliseconds=True)
    parts = [f"Largest {'outbound ' if outbound else ''}flow: {label} ({volume})"]
    if when:
        parts.append(f"around {when}")
    return " ".join(parts) + "."


def communication_lead_line(row: dict[str, Any]) -> str:
    service = str(row.get("service") or "Unknown service").strip()
    indicator = str(row.get("activity_label") or row.get("activity_type") or "indicator").strip()
    confidence = str(row.get("confidence") or "unknown").strip()
    sessions = int(row.get("sessions") or 1)
    volume = human_bytes(int(row.get("bytes") or 0), precision=2)
    first = format_pcap_datetime(row.get("first_seen")) or ""
    last = format_pcap_datetime(row.get("last_seen")) or ""
    time_part = ""
    if first and last and first != last:
        time_part = f", {first} – {last}"
    elif first:
        time_part = f", {first}"
    session_part = f", {sessions:,} sessions" if sessions > 1 else ""
    return (
        f"{service}: {indicator} ({confidence} confidence, {volume}{session_part}{time_part})."
    )


def pcap_peak_hour_label(hourly_rows: list[dict[str, Any]]) -> tuple[str, float]:
    if not hourly_rows:
        return "", 0.0
    peak = max(hourly_rows, key=lambda row: int(row.get("packets") or row.get("count") or 0))
    bucket = str(peak.get("hour") or "").strip()
    if " " in bucket:
        label = bucket.rsplit(" ", 1)[-1]
    else:
        label = bucket
    values = [int(row.get("packets") or row.get("count") or 0) for row in hourly_rows]
    total = sum(values)
    share = 0.0
    if total > 0:
        share = (max(values) / total) * 100.0
    return label, share


def rhythm_label(*, night_share: float, business_share: float) -> str:
    if night_share >= 55:
        return "evening- and night-heavy"
    if business_share >= 55:
        return "business-hours-heavy"
    if night_share >= 35:
        return "mixed with noticeable night use"
    return "spread across the day"
