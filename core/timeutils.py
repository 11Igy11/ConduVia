# core/timeutils.py
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable
from zoneinfo import ZoneInfo

LOCAL_TZ = ZoneInfo("Europe/Zagreb")

DEFAULT_TS_FIELDS: tuple[str, ...] = (
    "bidirectional_first_seen_ms",
    "first_seen",
    "timestamp",
)

# podrži i nDPI-style alternative ako zatreba kasnije:
# DEFAULT_TS_FIELDS += ("first_seen_ms", "flow_start_ms", ...)


def parse_timestamp(value: Any) -> datetime | None:
    """
    Canonical timestamp parser.
    - Naive strings are interpreted as Europe/Zagreb local time.
    - Epoch (s/ms) is interpreted as UTC epoch and converted to Europe/Zagreb.
    - Returns timezone-aware datetime in Europe/Zagreb, or None.
    """
    if value is None:
        return None

    # treat 0 / "0" as missing (seen in your dataset)
    if value == 0 or value == "0":
        return None

    # datetime passthrough
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=LOCAL_TZ)
        return value.astimezone(LOCAL_TZ)

    # numeric epoch
    if isinstance(value, (int, float)):
        return _dt_from_epoch(value)

    # strings
    if isinstance(value, str):
        s = value.strip()
        if not s or s == "0":
            return None

        # numeric string epoch
        dt_num = _try_parse_numeric_epoch_string(s)
        if dt_num is not None:
            return dt_num

        # normalize ISO 'Z'
        iso = s.replace("Z", "+00:00")

        # try ISO first (handles +00:00 offsets)
        try:
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                # IMPORTANT: your strings are local time
                dt = dt.replace(tzinfo=LOCAL_TZ)
            return dt.astimezone(LOCAL_TZ)
        except Exception:
            pass

        # common nDPI string formats (your sample)
        for fmt in (
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                dt2 = datetime.strptime(iso, fmt)
                return dt2.replace(tzinfo=LOCAL_TZ)
            except Exception:
                continue

        return None

    return None


def parse_flow_timestamp(
    flow: dict[str, Any],
    fields: Iterable[str] = DEFAULT_TS_FIELDS,
) -> datetime | None:
    for field in fields:
        if field in flow:
            dt = parse_timestamp(flow.get(field))
            if dt is not None:
                return dt
    return None


def date_key(dt: datetime) -> str:
    # local date key: YYYY-MM-DD (matches your old slicing)
    return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%d")


def hour_key(dt: datetime) -> str:
    # local hour key: YYYY-MM-DD HH (matches your old slicing)
    return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H")


def _dt_from_epoch(x: float) -> datetime | None:
    try:
        v = float(x)
        if v <= 0:
            return None
        # heuristic: ms epoch usually > 1e12
        seconds = (v / 1000.0) if v > 1_000_000_000_000 else v
        return datetime.fromtimestamp(seconds, tz=timezone.utc).astimezone(LOCAL_TZ)
    except Exception:
        return None


def _try_parse_numeric_epoch_string(s: str) -> datetime | None:
    try:
        return _dt_from_epoch(float(s))
    except Exception:
        return None