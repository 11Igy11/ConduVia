from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from core.analysis_limits import MAX_EVIDENCE_SNAPSHOT_ITEMS
from core.db import DEFAULT_DB_PATH, list_ingest_items, list_pcap_sources, list_recent_datasets
from core.evidence_policy import format_period_day_label
from core.formatters import format_pcap_datetime, human_bytes
from core.pcap_rollup import (
    PcapRollupTotals,
    collect_device_ip_stats,
    pcap_day_key,
    rollup_pcap_day_group,
    rollup_pcap_sources,
)
from core.period_groups import month_key
from core.project_datasets import count_project_json_datasets, list_project_json_dataset_files


def build_project_evidence_snapshot(
    project_id: int,
    *,
    db_path: Path = DEFAULT_DB_PATH,
    limit: int = MAX_EVIDENCE_SNAPSHOT_ITEMS,
) -> dict[str, Any]:
    """Single source of truth for saved JSON/PCAP evidence counts and day rows."""
    json_rows = list_project_json_dataset_files(project_id, limit=limit, db_path=db_path)
    json_count = count_project_json_datasets(project_id, limit=limit, db_path=db_path)
    dataset_sources = list_recent_datasets(project_id, limit=limit, db_path=db_path)
    available_json_files = [row for row in json_rows if row.get("status") == "Available"]

    sources = list_pcap_sources(project_id, limit=limit, db_path=db_path)
    rollup = rollup_pcap_sources(sources)
    device_ip_counts, device_ip_rows = collect_device_ip_stats(sources)

    ingest_done_paths = _ingest_pcap_paths(project_id, db_path=db_path, status="done")
    ingest_index_counts = _ingest_pcap_index_counts(project_id, db_path=db_path)
    pcap_indexed_file_count = sum(int(count or 0) for count in ingest_index_counts.values())
    pcap_indexed_day_count = len(ingest_index_counts)
    saved_period_days = _saved_period_days(sources)
    day_groups = _build_pcap_day_groups(sources, ingest_done_paths, saved_period_days)
    recent_day_rows = _build_pcap_recent_day_rows(sources, rollup, ingest_done_paths)
    profile_day_rows = _build_pcap_profile_day_rows(rollup)
    period_coverage = _build_pcap_period_coverage(ingest_index_counts, saved_period_days)
    capture_range = _build_capture_range(sources)
    json_day_rows = _build_json_recent_day_rows(project_id, db_path=db_path)

    return {
        "project_id": project_id,
        "json": {
            "count": json_count,
            "rows": json_rows,
            "json_day_rows": json_day_rows,
            "available_files": available_json_files,
            "dataset_sources": dataset_sources,
        },
        "pcap": {
            "sources": sources,
            "source_count": len(sources),
            "day_count": rollup.pcap_day_count,
            "indexed_file_count": pcap_indexed_file_count,
            "indexed_day_count": pcap_indexed_day_count,
            "indexed_day_counts": ingest_index_counts,
            "saved_period_days": saved_period_days,
            "day_groups": day_groups,
            "recent_day_rows": recent_day_rows,
            "day_rows": profile_day_rows,
            "device_ip_counts": dict(device_ip_counts),
            "device_ip_rows": device_ip_rows,
            "period_coverage": period_coverage,
            "rollup": rollup,
            "total_packets": rollup.total_packets,
            "total_bytes": rollup.total_bytes,
            "total_bytes_label": human_bytes(rollup.total_bytes, precision=2),
            "capture_range": capture_range,
        },
    }


def summarize_saved_json_evidence(
    project_id: int,
    *,
    limit: int = MAX_EVIDENCE_SNAPSHOT_ITEMS,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    return build_project_evidence_snapshot(project_id, limit=limit, db_path=db_path)["json"]


def count_saved_pcap_days(
    project_id: int,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> int:
    return build_project_evidence_snapshot(project_id, db_path=db_path)["pcap"]["day_count"]


def list_project_saved_pcap_day_rows(
    project_id: int,
    *,
    limit: int = 500,
    db_path: Path = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    rows = build_project_evidence_snapshot(project_id, db_path=db_path)["pcap"]["recent_day_rows"]
    return list(rows)[:limit]


def saved_pcap_device_ip_counts(
    project_id: int,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict[str, int]:
    return dict(build_project_evidence_snapshot(project_id, db_path=db_path)["pcap"]["device_ip_counts"])


def pcap_day_groups_from_ingest(
    project_id: int,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict[str, list[str]]:
    """Fast period-selector source: ingest index + saved-only days (no PCAP rollup)."""
    from core.db import list_saved_pcap_period_days

    by_day: dict[str, list[str]] = {}
    for item in list_ingest_items(project_id, file_type="pcap", limit=50000, db_path=db_path):
        day = str(item.observed_date or "").strip() or _day_from_name(item.file_name) or "undated"
        path = str(item.file_path or "").strip()
        if path:
            bucket = by_day.setdefault(day, [])
            if path not in bucket:
                bucket.append(path)
        else:
            by_day.setdefault(day, [])

    for day in list_saved_pcap_period_days(project_id, db_path=db_path):
        by_day.setdefault(str(day or "").strip(), [])

    if not by_day:
        for day in _ingest_pcap_index_counts(project_id, db_path=db_path):
            by_day.setdefault(day, [])

    return dict(sorted(by_day.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True))


def pcap_day_groups_for_selector(
    project_id: int,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict[str, list[str]]:
    """Day -> local PCAP file paths, including saved-only days with empty path lists."""
    return dict(build_project_evidence_snapshot(project_id, db_path=db_path)["pcap"]["day_groups"])


def get_saved_pcap_period_source(
    project_id: int,
    day: str,
    *,
    db_path: Path = DEFAULT_DB_PATH,
):
    day = str(day or "").strip()
    if not day:
        return None

    sources = build_project_evidence_snapshot(project_id, db_path=db_path)["pcap"]["sources"]
    matches = [
        source
        for source in sources
        if _saved_pcap_period_matches(source, day)
    ]
    if not matches:
        return None
    return max(matches, key=lambda row: int(getattr(row, "packet_count", 0) or 0))


def _saved_pcap_period_matches(source: Any, day: str) -> bool:
    period_day = str(getattr(source, "period_day", "") or "").strip()
    key = pcap_day_key(source)
    if period_day == day or key == day:
        return True
    # Month aggregate selector (YYYY-MM) matches daily saved periods in that month.
    if len(day) == 7 and day[4:5] == "-" and day.count("-") == 1:
        month_prefix = f"{day}-"
        if period_day.startswith(month_prefix):
            return True
        if key.startswith(month_prefix):
            return True
        if month_key(period_day) == day or month_key(key) == day:
            return True
    return False


def _saved_period_days(sources: list[Any]) -> list[str]:
    days = {
        str(getattr(source, "period_day", "") or "").strip()
        for source in sources
        if str(getattr(source, "period_day", "") or "").strip()
    }
    return sorted(days)


def _build_json_recent_day_rows(project_id: int, *, db_path: Path) -> list[dict[str, Any]]:
    by_day: dict[str, list[str]] = {}
    for item in list_ingest_items(project_id, file_type="json", limit=50000, db_path=db_path):
        path = str(item.file_path or "").strip()
        if not path:
            continue
        day = str(item.observed_date or "undated").strip() or "undated"
        if path not in by_day.setdefault(day, []):
            by_day[day].append(path)

    rows: list[dict[str, Any]] = []
    for day in sorted(by_day, reverse=True):
        paths = by_day[day]
        rows.append(
            {
                "day": day,
                "name": format_period_day_label(day) if day != "undated" else "Undated",
                "file_count": len(paths),
                "period": day if day != "undated" else "-",
                "paths": paths,
            }
        )
    return rows


def _ingest_pcap_paths(
    project_id: int,
    *,
    db_path: Path,
    status: str = "",
) -> dict[str, list[str]]:
    ingest_paths: dict[str, list[str]] = {}
    kwargs: dict[str, Any] = {"file_type": "pcap", "limit": 50000, "db_path": db_path}
    if status:
        kwargs["status"] = status
    for item in list_ingest_items(project_id, **kwargs):
        day = str(item.observed_date or "").strip() or _day_from_name(item.file_name) or "undated"
        path = str(item.file_path or "").strip()
        if not path or not Path(path).is_file():
            continue
        bucket = ingest_paths.setdefault(day, [])
        if path not in bucket:
            bucket.append(path)
    return ingest_paths


def _ingest_pcap_index_counts(project_id: int, *, db_path: Path) -> dict[str, int]:
    indexed: dict[str, int] = {}
    for item in list_ingest_items(project_id, file_type="pcap", limit=50000, db_path=db_path):
        day = str(item.observed_date or "").strip() or "undated"
        if day == "undated":
            continue
        indexed[day] = indexed.get(day, 0) + 1
    return indexed


def _build_pcap_day_groups(
    sources: list[Any],
    ingest_paths: dict[str, list[str]],
    saved_period_days: list[str],
) -> dict[str, list[str]]:
    by_day: dict[str, list[str]] = {day: list(paths) for day, paths in ingest_paths.items()}

    for source in sources:
        day = pcap_day_key(source) or "undated"
        path = str(getattr(source, "file_path", "") or "").strip()
        if not path or not Path(path).is_file():
            continue
        bucket = by_day.setdefault(day, [])
        if path not in bucket:
            bucket.append(path)

    for day in saved_period_days:
        by_day.setdefault(day, [])

    return dict(sorted(by_day.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True))


def _build_pcap_recent_day_rows(
    sources: list[Any],
    rollup: PcapRollupTotals,
    ingest_paths: dict[str, list[str]],
) -> list[dict[str, Any]]:
    by_day: dict[str, list[Any]] = {}
    for source in sources:
        day = pcap_day_key(source) or "undated"
        by_day.setdefault(day, []).append(source)

    rows: list[dict[str, Any]] = []
    for day in sorted(set(by_day) | set(ingest_paths), reverse=True):
        group = by_day.get(day, [])
        if day == "undated":
            packets = rollup.undated_packets
            wire_bytes = rollup.undated_bytes
        else:
            packets = int(rollup.day_packets.get(day, 0) or 0)
            wire_bytes = int(rollup.day_bytes.get(day, 0) or 0)

        _, _, day_ips = rollup_pcap_day_group(group) if group else (0, 0, Counter())
        device_ip = "-"
        if day_ips:
            device_ip = sorted(day_ips.items(), key=lambda item: (-item[1], item[0]))[0][0]

        first_seen = ""
        last_seen = ""
        source_paths: list[str] = []
        for source in group:
            first_seen = _min_text_time(first_seen, str(source.first_seen or ""))
            last_seen = _max_text_time(last_seen, str(source.last_seen or ""))
            path = str(source.file_path or "").strip()
            if path and Path(path).is_file() and path not in source_paths:
                source_paths.append(path)

        paths: list[str] = []
        seen_paths: set[str] = set()
        for path in list(ingest_paths.get(day, [])) + source_paths:
            if path and path not in seen_paths:
                seen_paths.add(path)
                paths.append(path)

        file_count = len(paths) or (1 if group else 0)
        period = " - ".join(
            value
            for value in (
                format_pcap_datetime(first_seen),
                format_pcap_datetime(last_seen),
            )
            if value
        )
        rows.append({
            "name": f"{_display_day(day)} ({file_count:,} PCAP files)",
            "file_count": file_count,
            "packets": f"{packets:,}",
            "volume": human_bytes(wire_bytes, precision=2),
            "device_ip": device_ip,
            "period": period or "-",
            "path": paths[0] if len(paths) == 1 else "",
            "paths": paths,
            "day": day,
        })
    return rows


def _build_pcap_profile_day_rows(rollup: PcapRollupTotals) -> list[dict[str, Any]]:
    rows = [
        {
            "label": format_period_day_label(day),
            "date": day,
            "count": packets,
            "bytes": rollup.day_bytes[day],
            "bytes_label": human_bytes(rollup.day_bytes[day], precision=2),
            "detail": f"{packets:,} packets / {human_bytes(rollup.day_bytes[day], precision=2)}",
        }
        for day, packets in sorted(rollup.day_packets.items())
    ]
    if rollup.undated_day_count:
        rows.append({
            "label": "Undated PCAP",
            "date": "",
            "count": rollup.undated_packets,
            "bytes": rollup.undated_bytes,
            "bytes_label": human_bytes(rollup.undated_bytes, precision=2),
            "detail": f"{rollup.undated_packets:,} packets / {human_bytes(rollup.undated_bytes, precision=2)}",
        })
    return rows


def _build_pcap_period_coverage(
    indexed: dict[str, int],
    saved_period_days: list[str],
) -> list[dict[str, Any]]:
    saved_days = set(saved_period_days)
    rows: list[dict[str, Any]] = []
    for day in sorted(indexed):
        file_count = indexed[day]
        rows.append({
            "label": format_period_day_label(day),
            "date": day,
            "count": file_count,
            "detail": f"{file_count:,} PCAP files indexed",
            "status": "Saved to project" if day in saved_days else "Not saved yet",
        })
    for day in sorted(saved_days - set(indexed)):
        rows.append({
            "label": format_period_day_label(day),
            "date": day,
            "count": 0,
            "detail": "Saved summary without indexed files",
            "status": "Saved to project",
        })
    return rows


def _build_capture_range(sources: list[Any]) -> dict[str, str]:
    capture_starts = [str(source.first_seen or "") for source in sources if source.first_seen]
    capture_ends = [str(source.last_seen or "") for source in sources if source.last_seen]
    capture_start = min(capture_starts) if capture_starts else ""
    capture_end = max(capture_ends) if capture_ends else ""
    start_label = format_pcap_datetime(capture_start) if capture_start else ""
    end_label = format_pcap_datetime(capture_end) if capture_end else ""
    if start_label and end_label:
        label = f"{start_label} to {end_label}"
    else:
        label = "-"
    return {
        "first_seen": capture_start,
        "last_seen": capture_end,
        "label": label,
    }


def _display_day(day: str) -> str:
    if day == "undated":
        return "Undated"
    return format_period_day_label(day) or day


def _day_from_name(value: str) -> str:
    text = str(value or "")
    for token in text.replace("\\", "_").replace("/", "_").split("_"):
        if len(token) >= 8 and token[:8].isdigit():
            raw = token[:8]
            return f"{raw[:4]}-{raw[4:6]}-{raw[6:8]}"
    return ""


def _min_text_time(current: str, candidate: str) -> str:
    if not candidate:
        return current or ""
    if not current:
        return candidate
    return min(str(current), str(candidate))


def _max_text_time(current: str, candidate: str) -> str:
    if not candidate:
        return current or ""
    if not current:
        return candidate
    return max(str(current), str(candidate))
