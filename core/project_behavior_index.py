from __future__ import annotations

from pathlib import Path
from typing import Callable

from core.behavior_profile import BehaviorProfileAccumulator
from core.analysis_limits import MAX_BEHAVIOR_INDEX_JSON_FILES
from core.db import (
    DEFAULT_DB_PATH,
    get_project_behavior_profile,
    list_ingest_items,
    list_recent_dataset_sources,
    save_project_behavior_profile,
)
from core.loader import load_json_file
from core.project_evidence import get_project_evidence_totals
from core.project_datasets import selected_ingest_items_for_source


ProgressCallback = Callable[[int, int, str], None]

MAX_INGEST_ITEMS_FOR_DATE_RANGE = 50000

def build_project_behavior_index(
    project_id: int,
    *,
    db_path: Path = DEFAULT_DB_PATH,
    progress: ProgressCallback | None = None,
) -> dict:
    """Build and persist a project-level behavior snapshot from saved JSON sources."""
    files, skipped_json_file_count = _project_json_files(project_id, db_path=db_path)
    expected_json_file_count = len(files) + skipped_json_file_count
    source_key = _source_key(files, skipped_json_file_count=skipped_json_file_count)
    cached = get_project_behavior_profile(project_id, db_path=db_path)
    if (
        cached.get("source_key") == source_key
        and int(cached.get("json_file_count") or 0) == expected_json_file_count
        and int(cached.get("loaded_json_file_count") or 0) == len(files)
        and int(cached.get("skipped_json_file_count") or 0) == skipped_json_file_count
    ):
        cached_flow_count = int(cached.get("flow_count") or 0)
        cached_failed_count = int(cached.get("failed_json_file_count") or 0)
        # Older beta builds could persist a structurally current but empty
        # profile while the selected JSON files were still loadable. Rebuild
        # those snapshots so Profile does not stay stuck on an empty cache.
        if cached_flow_count or not files or cached_failed_count >= len(files):
            cached["project_id"] = project_id
            return cached

    accumulator = BehaviorProfileAccumulator()
    failed = 0

    total = len(files)
    for idx, path in enumerate(files, start=1):
        if progress:
            progress(idx, total, str(path))
        try:
            accumulator.add_flows(load_json_file(path))
        except Exception:
            failed += 1

    profile = accumulator.to_profile()
    profile["project_id"] = project_id
    profile["json_file_count"] = expected_json_file_count
    profile["loaded_json_file_count"] = total
    profile["skipped_json_file_count"] = skipped_json_file_count
    profile["failed_json_file_count"] = failed
    profile["source_key"] = source_key
    totals = get_project_evidence_totals(project_id, db_path=db_path)
    profile["indexed_file_count"] = int(totals.get("json_file_count") or expected_json_file_count)
    profile["indexed_day_count"] = int(totals.get("json_day_count") or 0)
    previous = get_project_behavior_profile(project_id, db_path=db_path) or {}
    pcap_rows = [
        row
        for row in (previous.get("public_ip_rows") or [])
        if str(row.get("source") or "") == "pcap"
    ]
    if pcap_rows:
        from core.osint.public_ips import merge_public_ip_row_lists

        profile["public_ip_rows"] = merge_public_ip_row_lists(profile.get("public_ip_rows"), pcap_rows)
    save_project_behavior_profile(
        project_id,
        profile,
        source_key=str(profile["source_key"]),
        json_file_count=expected_json_file_count,
        db_path=db_path,
    )
    return profile


def _project_json_files(project_id: int, *, db_path: Path = DEFAULT_DB_PATH) -> tuple[list[Path], int]:
    """Collect JSON files from saved project ingest; fall back to legacy dataset sources."""
    ingest_files, skipped_json_file_count, ingest_count = _json_files_from_saved_ingest(
        project_id,
        db_path=db_path,
    )
    if ingest_files or ingest_count:
        return ingest_files, skipped_json_file_count

    rows = list_recent_dataset_sources(project_id, limit=50000, db_path=db_path)
    out: list[Path] = []
    seen: set[str] = set()
    skipped_json_file_count = 0

    for row in rows:
        source = Path(str(row["folder_path"] or ""))
        candidates: list[Path] = []
        if source.is_file() and source.suffix.lower() == ".json":
            candidates = [source]
        elif source.is_dir():
            cached_count = _row_int(row, "json_file_count")
            try:
                selected, selected_skipped = _selected_json_files_for_source(
                    project_id,
                    source,
                    source_row=row,
                    db_path=db_path,
                )
                if selected or selected_skipped:
                    candidates = selected
                    skipped_json_file_count += selected_skipped
                    truncated = False
                elif _should_skip_indexed_folder(row, cached_count):
                    skipped_json_file_count += cached_count
                    continue
                else:
                    candidates, truncated = _limited_json_files_recursive(
                        source,
                        max_files=MAX_BEHAVIOR_INDEX_JSON_FILES + 1,
                    )
                    if not candidates and _has_index_metadata(row) and cached_count:
                        skipped_json_file_count += cached_count
                        continue
                if truncated:
                    skipped_json_file_count += max(cached_count, len(candidates))
                    continue
            except Exception:
                candidates = []

        for path in candidates:
            key = _path_key(path)
            if key and key not in seen:
                seen.add(key)
                out.append(path)

    return sorted(out, key=lambda path: (path.name.casefold(), str(path).casefold())), skipped_json_file_count


def _json_files_from_saved_ingest(
    project_id: int,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> tuple[list[Path], int, int]:
    """Saved project evidence from ingest_items — no dataset-source date filters."""
    try:
        done_items = list_ingest_items(
            project_id,
            file_type="json",
            status="done",
            limit=MAX_BEHAVIOR_INDEX_JSON_FILES + 1,
            db_path=db_path,
        )
        items = done_items or list_ingest_items(
            project_id,
            file_type="json",
            limit=MAX_BEHAVIOR_INDEX_JSON_FILES + 1,
            db_path=db_path,
        )
    except Exception:
        return [], 0, 0
    if not items:
        return [], 0, 0

    files: list[Path] = []
    file_keys: set[str] = set()
    for item in items[:MAX_BEHAVIOR_INDEX_JSON_FILES]:
        path = Path(str(getattr(item, "file_path", "") or ""))
        key = _path_key(path)
        if not key or key in file_keys:
            continue
        if path.is_file() and path.suffix.lower() == ".json":
            file_keys.add(key)
            files.append(path)

    selected_count = len(items)
    skipped = max(0, selected_count - len(files))
    return sorted(files, key=lambda path: (path.name.casefold(), str(path).casefold())), skipped, selected_count


def _json_files_from_ingest_items(
    project_id: int,
    source_rows,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> tuple[list[Path], int, int]:
    return _json_files_from_saved_ingest(project_id, db_path=db_path)


def _select_ingest_items(items, filters, *, ignore_date_range: bool) -> list:
    selected = []
    selected_keys: set[str] = set()
    for item in items:
        item_path = Path(str(getattr(item, "file_path", "") or ""))
        item_key = _path_key(item_path)
        if not item_key or item_key in selected_keys:
            continue
        if filters and not _ingest_item_matches_filters(
            item,
            item_key,
            filters,
            ignore_date_range=ignore_date_range,
        ):
            continue
        selected_keys.add(item_key)
        selected.append(item)
    return selected


def _source_filters(source_rows) -> list[tuple[str, str, str]]:
    filters: list[tuple[str, str, str]] = []
    for row in source_rows:
        source_text = _row_text(row, "folder_path")
        if not source_text:
            continue
        source_key = _path_key(Path(source_text)).rstrip("\\/")
        if not source_key:
            continue
        filters.append((source_key, _row_text(row, "first_observed"), _row_text(row, "last_observed")))
    return filters


def _ingest_item_matches_filters(
    item,
    item_key: str,
    filters: list[tuple[str, str, str]],
    *,
    ignore_date_range: bool = False,
) -> bool:
    observed = str(getattr(item, "observed_date", "") or "")
    for source_key, first, last in filters:
        if not (
            item_key == source_key
            or item_key.startswith(source_key + "\\")
            or item_key.startswith(source_key + "/")
        ):
            continue
        if observed and not ignore_date_range:
            if first and observed < first:
                continue
            if last and observed > last:
                continue
        return True
    return False


def _source_key(files: list[Path], *, skipped_json_file_count: int = 0) -> str:
    parts = []
    for path in files:
        try:
            stat = path.stat()
            parts.append(f"{path.resolve()}:{stat.st_mtime_ns}:{stat.st_size}")
        except Exception:
            parts.append(f"{path}:missing")
    if skipped_json_file_count:
        parts.append(f"skipped-indexed-json:{skipped_json_file_count}")
    return "|".join(parts)


def _path_key(path: Path) -> str:
    try:
        return str(path.resolve()).casefold()
    except Exception:
        return str(path).casefold()


def _limited_json_files_recursive(folder: Path, *, max_files: int) -> tuple[list[Path], bool]:
    files: list[Path] = []
    for item in folder.rglob("*.json"):
        if not item.is_file():
            continue
        files.append(item)
        if len(files) >= max_files:
            return sorted(files, key=lambda path: (path.name.casefold(), str(path).casefold())), True
    return sorted(files, key=lambda path: (path.name.casefold(), str(path).casefold())), False


def _selected_json_files_for_source(
    project_id: int,
    source_path: Path,
    *,
    source_row=None,
    db_path: Path,
) -> tuple[list[Path], int]:
    first = _row_text(source_row, "first_observed")
    last = _row_text(source_row, "last_observed")
    limit = MAX_INGEST_ITEMS_FOR_DATE_RANGE if (first or last) else MAX_BEHAVIOR_INDEX_JSON_FILES + 1
    items = selected_ingest_items_for_source(
        project_id,
        source_path,
        file_type="json",
        limit=limit,
        db_path=db_path,
    )

    if not any(str(getattr(item, "status", "") or "").lower() == "done" for item in items):
        items = _filter_items_to_source_range(items, first=first, last=last)
    selected_count = len(items)
    files: list[Path] = []
    seen: set[str] = set()
    for item in items[:MAX_BEHAVIOR_INDEX_JSON_FILES]:
        path = Path(item.file_path)
        key = _path_key(path)
        if not key or key in seen:
            continue
        if path.is_file() and path.suffix.lower() == ".json":
            seen.add(key)
            files.append(path)
    skipped = max(0, selected_count - len(files))
    return sorted(files, key=lambda path: (path.name.casefold(), str(path).casefold())), skipped


def _filter_items_to_source_range(items, *, first: str = "", last: str = "") -> list:
    if not (first or last):
        return list(items)

    out = []
    for item in items:
        observed = str(getattr(item, "observed_date", "") or "")
        if not observed:
            out.append(item)
            continue
        if first and observed < first:
            continue
        if last and observed > last:
            continue
        out.append(item)
    return out


def _row_text(row, name: str) -> str:
    try:
        if row is None or name not in row.keys():
            return ""
        return str(row[name] or "").strip()
    except Exception:
        return ""


def _row_int(row, name: str) -> int:
    try:
        if name not in row.keys():
            return 0
        return max(0, int(row[name] or 0))
    except Exception:
        return 0


def _should_skip_indexed_folder(row, cached_count: int) -> bool:
    if cached_count <= 0:
        return False
    return cached_count > MAX_BEHAVIOR_INDEX_JSON_FILES


def _has_index_metadata(row) -> bool:
    return bool(
        _row_text(row, "indexed_at")
        or _row_text(row, "first_observed")
        or _row_text(row, "last_observed")
    )
