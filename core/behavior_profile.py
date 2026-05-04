from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from core.formatters import human_bytes, safe_int
from core.timeutils import parse_timestamp


SERVICE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Facebook / Meta", ("facebook", "fbcdn", "fb.com", "instagram", "edge-mqtt", "messenger")),
    ("WhatsApp", ("whatsapp", "wa.me")),
    ("Google / YouTube", ("youtube", "ytimg", "googlevideo", "googleapis", "googleusercontent")),
    ("TikTok", ("tiktok", "byteoversea", "pangle")),
    ("Telegram", ("telegram", "t.me")),
    ("Viber", ("viber",)),
    ("Snapchat", ("snapchat",)),
    ("X / Twitter", ("twitter", "x.com", "twimg")),
    ("Spotify", ("spotify",)),
    ("Travel / Booking", ("booking", "airbnb", "tripadvisor")),
    ("Advertising / tracking", ("doubleclick", "googlesyndication", "adservice", "analytics", "ads.")),
)


def build_flow_behavior_profile(flows: list[dict[str, Any]] | None, *, limit: int = 10) -> dict[str, Any]:
    flows = [flow for flow in (flows or []) if isinstance(flow, dict)]
    service_counts: Counter[str] = Counter()
    service_bytes: Counter[str] = Counter()
    service_examples: dict[str, str] = {}
    domain_counts: Counter[str] = Counter()
    domain_bytes: Counter[str] = Counter()
    hour_counts: Counter[int] = Counter()
    hour_bytes: Counter[int] = Counter()

    total_bytes = 0
    timestamp_count = 0

    for flow in flows:
        byte_count = _flow_bytes(flow)
        total_bytes += byte_count

        domain = _flow_domain(flow)
        app = str(flow.get("application_name") or "")
        service = _service_label(domain or app)
        if service:
            service_counts[service] += 1
            service_bytes[service] += byte_count
            service_examples.setdefault(service, domain or app)

        if domain:
            domain_counts[domain] += 1
            domain_bytes[domain] += byte_count

        dt = parse_timestamp(_flow_timestamp(flow))
        if dt is not None:
            timestamp_count += 1
            hour_counts[dt.hour] += 1
            hour_bytes[dt.hour] += byte_count

    service_rows = _service_rows(service_counts, service_bytes, service_examples, total_bytes, limit)
    domain_rows = _domain_rows(domain_counts, domain_bytes, total_bytes, limit)
    hour_rows = _hour_rows(hour_counts, hour_bytes, total_bytes)

    return {
        "flow_count": len(flows),
        "timestamp_count": timestamp_count,
        "total_bytes": total_bytes,
        "total_bytes_label": human_bytes(total_bytes, precision=2),
        "service_rows": service_rows,
        "domain_rows": domain_rows,
        "hour_rows": hour_rows,
        "routine_lines": _routine_lines(hour_counts, timestamp_count),
    }


def _flow_bytes(flow: dict[str, Any]) -> int:
    for key in ("bidirectional_bytes", "bytes", "octets", "total_bytes"):
        value = safe_int(flow.get(key))
        if value:
            return value
    return 0


def _flow_domain(flow: dict[str, Any]) -> str:
    for key in ("requested_server_name", "server_name", "sni", "host", "http_host"):
        value = str(flow.get(key) or "").strip().lower().rstrip(".")
        if value and "." in value and not _looks_like_ip(value):
            return value
    return ""


def _flow_timestamp(flow: dict[str, Any]) -> Any:
    for key in ("bidirectional_first_seen_ms", "first_seen", "timestamp", "time"):
        value = flow.get(key)
        if value:
            return value
    return None


def _service_label(value: str) -> str:
    text = (value or "").lower()
    if not text:
        return ""
    for label, needles in SERVICE_RULES:
        if any(needle in text for needle in needles):
            return label
    return "Other visible services" if "." in text else ""


def _service_rows(
    counts: Counter[str],
    byte_counts: Counter[str],
    examples: dict[str, str],
    total_bytes: int,
    limit: int,
) -> list[dict[str, Any]]:
    rows = []
    for label, count in counts.most_common(limit):
        bytes_value = byte_counts[label]
        rows.append({
            "label": label,
            "count": count,
            "bytes": bytes_value,
            "bytes_label": human_bytes(bytes_value, precision=2),
            "share": _share(bytes_value, total_bytes),
            "example": examples.get(label, ""),
        })
    return rows


def _domain_rows(
    counts: Counter[str],
    byte_counts: Counter[str],
    total_bytes: int,
    limit: int,
) -> list[dict[str, Any]]:
    rows = []
    for domain, count in byte_counts.most_common(limit):
        bytes_value = byte_counts[domain]
        rows.append({
            "label": domain,
            "count": counts[domain],
            "bytes": bytes_value,
            "bytes_label": human_bytes(bytes_value, precision=2),
            "share": _share(bytes_value, total_bytes),
        })
    return rows


def _hour_rows(hour_counts: Counter[int], byte_counts: Counter[int], total_bytes: int) -> list[dict[str, Any]]:
    rows = []
    for hour in range(24):
        count = hour_counts[hour]
        bytes_value = byte_counts[hour]
        if not count and not bytes_value:
            continue
        rows.append({
            "label": f"{hour:02d}:00",
            "count": count,
            "bytes": bytes_value,
            "bytes_label": human_bytes(bytes_value, precision=2),
            "share": _share(bytes_value, total_bytes),
        })
    return rows


def _routine_lines(hour_counts: Counter[int], timestamp_count: int) -> list[str]:
    if not timestamp_count:
        return ["No timestamps available for activity rhythm."]

    peak_hour, peak_count = hour_counts.most_common(1)[0]
    quiet_hours = [hour for hour in range(24) if hour_counts[hour] == 0]
    night_count = sum(hour_counts[hour] for hour in list(range(0, 6)) + [22, 23])
    day_count = sum(hour_counts[hour] for hour in range(8, 18))

    lines = [
        f"Most active hour: {peak_hour:02d}:00 ({peak_count} flows).",
        f"Night/late activity share: {_share(night_count, timestamp_count):.1f}% of timestamped flows.",
        f"Business-hour activity share: {_share(day_count, timestamp_count):.1f}% of timestamped flows.",
    ]
    if quiet_hours:
        lines.append(f"Quiet hours with no observed flows: {_compact_hours(quiet_hours)}.")
    else:
        lines.append("No completely quiet hour was observed in the loaded dataset.")
    lines.append("Treat quiet/active periods as device activity indicators, not proof that a person was awake or asleep.")
    return lines


def _compact_hours(hours: list[int]) -> str:
    if not hours:
        return "-"
    ranges: list[str] = []
    start = prev = hours[0]
    for hour in hours[1:]:
        if hour == prev + 1:
            prev = hour
            continue
        ranges.append(_format_hour_range(start, prev))
        start = prev = hour
    ranges.append(_format_hour_range(start, prev))
    return ", ".join(ranges)


def _format_hour_range(start: int, end: int) -> str:
    if start == end:
        return f"{start:02d}:00"
    return f"{start:02d}:00-{end:02d}:59"


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() for part in parts)


def _share(value: int, total: int) -> float:
    return round((value / total) * 100, 1) if total else 0.0
