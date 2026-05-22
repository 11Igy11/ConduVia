from __future__ import annotations

from pathlib import Path
from typing import Any

from core.db import DEFAULT_DB_PATH, list_ingest_items, list_recent_dataset_sources
from core.loader import load_json_file

MAX_AUTO_PROFILE_JSON_FILES = 500
MAX_FOLDER_SCAN_FOR_PROJECT_OPEN = MAX_AUTO_PROFILE_JSON_FILES + 1
MAX_INGEST_ITEMS_FOR_DATE_RANGE = 50000


def load_project_dataset_flows(
    project_id: int,
    *,
    limit: int = 1000,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    source_rows_db = list_recent_dataset_sources(project_id, limit=limit, db_path=db_path)
    deduped = _dedupe_paths([str(row["folder_path"] or "") for row in source_rows_db])
    source_meta = {
        _path_key(Path(str(row["folder_path"] or ""))): row
        for row in source_rows_db
    }
    flows: list[dict[str, Any]] = []
    source_rows: list[dict[str, Any]] = []
    missing_rows: list[dict[str, Any]] = []
    cache_parts: list[str] = []
    json_file_count = 0
    loaded_json_file_count = 0

    for path_text in deduped:
        path = Path(path_text)
        meta_row = source_meta.get(_path_key(path))
        cached_json_count = int(meta_row["json_file_count"] or 0) if meta_row and "json_file_count" in meta_row.keys() else 0
        row = {
            "path": path_text,
            "type": _path_type(path),
            "status": "missing",
            "flow_count": 0,
            "message": "",
        }
        cache_parts.append(_cache_part(path))

        if not path.exists():
            row["message"] = "Path not found."
            missing_rows.append(dict(row))
            source_rows.append(row)
            continue

        try:
            if path.is_file():
                if path.suffix.lower() == ".json":
                    json_file_count += 1
                loaded = load_json_file(path, debug=False)
                row["type"] = "file"
                if path.suffix.lower() == ".json":
                    loaded_json_file_count += 1
            elif path.is_dir():
                selected_files, selected_skipped, selected_count = _selected_json_files_for_source(
                    project_id,
                    path,
                    source_row=meta_row,
                    db_path=db_path,
                )
                if selected_files or selected_count:
                    files = selected_files
                    truncated = False
                elif _should_use_indexed_folder_row(meta_row, cached_json_count):
                    json_file_count += cached_json_count
                    row["type"] = "folder"
                    row["status"] = "indexed"
                    row["message"] = (
                        f"{cached_json_count:,} JSON files indexed. "
                        "Large source is not auto-loaded into Profile behavior charts."
                    )
                    source_rows.append(row)
                    continue
                else:
                    files, truncated = _limited_json_files_recursive(path, max_files=MAX_FOLDER_SCAN_FOR_PROJECT_OPEN)
                    selected_count = len(files)
                if truncated:
                    json_file_count += max(cached_json_count, selected_count)
                    row["type"] = "folder"
                    row["status"] = "indexed"
                    row["message"] = (
                        f"More than {MAX_AUTO_PROFILE_JSON_FILES:,} JSON files detected. "
                        "Large source is not auto-loaded when opening the project."
                    )
                    source_rows.append(row)
                    continue
                json_file_count += selected_count or len(files)
                loaded = []
                for fp in files:
                    cache_parts.append(_cache_part(fp))
                    loaded.extend(load_json_file(fp, debug=False))
                row["type"] = "folder"
                loaded_json_file_count += len(files)
                if selected_skipped:
                    row["message"] = (
                        f"Loaded first {len(files):,} selected JSON files; "
                        f"{selected_skipped:,} additional selected files remain indexed."
                    )
            else:
                loaded = []
                row["message"] = "Unsupported dataset path."

            row["status"] = "loaded"
            row["flow_count"] = len(loaded)
            flows.extend(loaded)
        except Exception as exc:
            row["status"] = "error"
            row["message"] = str(exc)
            missing_rows.append(dict(row))

        source_rows.append(row)

    return {
        "flows": flows,
        "source_rows": source_rows,
        "missing_rows": missing_rows,
        "source_count": len(source_rows),
        "loaded_source_count": sum(1 for row in source_rows if row.get("status") == "loaded"),
        "json_file_count": json_file_count,
        "loaded_json_file_count": loaded_json_file_count,
        "saved_path_count": len(source_rows_db),
        "deduped_path_count": len(deduped),
        "flow_count": len(flows),
        "cache_key": "|".join(cache_parts),
    }


def list_project_json_dataset_files(
    project_id: int,
    *,
    limit: int = 1000,
    db_path: Path = DEFAULT_DB_PATH,
) -> list[dict[str, Any]]:
    """Return unique JSON files represented by saved project dataset paths.

    The database stores a user-selected source path, which may be either one
    JSON file or a folder containing many JSON files. The profile/dashboard
    should count the real JSON files, not the saved folder reference.
    """
    source_rows = list_recent_dataset_sources(project_id, limit=limit, db_path=db_path)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    for source_row in source_rows:
        path_text = str(source_row["folder_path"] or "")
        path = Path(path_text)
        cached_json_count = int(source_row["json_file_count"] or 0) if "json_file_count" in source_row.keys() else 0

        if path.is_file() and path.suffix.lower() == ".json":
            candidates = [path]
            source_kind = "JSON file"
        elif path.is_dir():
            try:
                selected_files, selected_skipped, selected_count = _selected_json_files_for_source(
                    project_id,
                    path,
                    source_row=source_row,
                    db_path=db_path,
                )
                if selected_files or selected_count:
                    candidates = selected_files
                    truncated = False
                elif _should_use_indexed_folder_row(source_row, cached_json_count) or cached_json_count > limit:
                    key = _path_key(path)
                    if key and key not in seen:
                        seen.add(key)
                        rows.append({
                            "status": "Available",
                            "name": path.name or str(path_text),
                            "kind": "Folder index",
                            "path": str(path_text),
                            "source_path": str(path_text),
                            "file_count": cached_json_count,
                            "message": f"{cached_json_count:,} JSON files indexed",
                    })
                    continue
                else:
                    candidates, truncated = _limited_json_files_recursive(path, max_files=min(limit + 1, MAX_FOLDER_SCAN_FOR_PROJECT_OPEN))
                if truncated:
                    key = _path_key(path)
                    if key and key not in seen:
                        seen.add(key)
                        rows.append({
                            "status": "Available",
                            "name": path.name or str(path_text),
                            "kind": "Folder index",
                            "path": str(path_text),
                            "source_path": str(path_text),
                            "file_count": len(candidates),
                            "message": f"More than {MAX_AUTO_PROFILE_JSON_FILES:,} JSON files detected",
                        })
                    continue
            except Exception:
                candidates = []
            source_kind = "Folder"
        else:
            candidates = []
            source_kind = "Missing"

        if not candidates:
            key = _path_key(path)
            if key and key not in seen:
                seen.add(key)
                rows.append({
                    "status": "Missing" if not path.exists() else "No JSON files",
                    "name": path.name or str(path_text),
                    "kind": source_kind,
                    "path": str(path_text),
                    "source_path": str(path_text),
                    "file_count": 0,
                })
            continue

        for json_path in candidates:
            key = _path_key(json_path)
            if not key or key in seen:
                continue
            seen.add(key)
            rows.append({
                "status": "Available" if json_path.exists() else "Missing",
                "name": json_path.name,
                "kind": source_kind,
                "path": str(json_path),
                "source_path": str(path_text),
                "file_count": 1,
            })

    return rows


def count_project_json_datasets(
    project_id: int,
    *,
    limit: int = 1000,
    db_path: Path = DEFAULT_DB_PATH,
) -> int:
    rows = list_recent_dataset_sources(project_id, limit=limit, db_path=db_path)
    total = 0

    for row in rows:
        path_text = str(row["folder_path"] or "")
        path = Path(path_text)
        cached_json_count = int(row["json_file_count"] or 0) if "json_file_count" in row.keys() else 0

        if path.is_dir():
            selected_files, _selected_skipped, selected_count = _selected_json_files_for_source(
                project_id,
                path,
                source_row=row,
                db_path=db_path,
            )
            if selected_files or selected_count:
                total += selected_count or len(selected_files)
                continue

        if path.is_file() and path.suffix.lower() == ".json":
            total += 1
        elif cached_json_count:
            total += cached_json_count
        elif path.is_dir():
            try:
                files, truncated = _limited_json_files_recursive(path, max_files=MAX_FOLDER_SCAN_FOR_PROJECT_OPEN)
                total += len(files)
            except Exception:
                pass

    return total


def _dedupe_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        text = str(raw or "").strip()
        if not text:
            continue
        key = _path_key(Path(text))
        if key in seen:
            continue
        seen.add(key)
        out.append(text)
    return out


def _path_key(path: Path) -> str:
    try:
        return str(path.resolve()).casefold()
    except Exception:
        return str(path).casefold()


def _path_type(path: Path) -> str:
    if path.is_file():
        return "file"
    if path.is_dir():
        return "folder"
    return "missing"


def _cache_part(path: Path) -> str:
    try:
        stat = path.stat()
        return f"{path.resolve()}:{int(stat.st_mtime_ns)}:{int(stat.st_size)}"
    except Exception:
        return f"{path}:missing"


def _limited_json_files_recursive(folder: Path, *, max_files: int) -> tuple[list[Path], bool]:
    files: list[Path] = []
    try:
        iterator = folder.rglob("*.json")
        for item in iterator:
            if not item.is_file():
                continue
            files.append(item)
            if len(files) >= max_files:
                return sorted(files, key=lambda x: (x.name.casefold(), str(x).casefold())), True
    except Exception:
        raise

    return sorted(files, key=lambda x: (x.name.casefold(), str(x).casefold())), False


def _selected_json_files_for_source(
    project_id: int,
    source_path: Path,
    *,
    source_row=None,
    db_path: Path,
) -> tuple[list[Path], int, int]:
    first = _row_text(source_row, "first_observed")
    last = _row_text(source_row, "last_observed")
    limit = MAX_INGEST_ITEMS_FOR_DATE_RANGE if (first or last) else MAX_FOLDER_SCAN_FOR_PROJECT_OPEN
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
    for item in items[:MAX_AUTO_PROFILE_JSON_FILES]:
        path = Path(item.file_path)
        key = _path_key(path)
        if not key or key in seen:
            continue
        if path.is_file() and path.suffix.lower() == ".json":
            seen.add(key)
            files.append(path)
    skipped = max(0, selected_count - len(files))
    return sorted(files, key=lambda x: (x.name.casefold(), str(x).casefold())), skipped, selected_count


def selected_ingest_items_for_source(
    project_id: int,
    source_path: Path,
    *,
    file_type: str,
    limit: int,
    db_path: Path = DEFAULT_DB_PATH,
) -> list:
    """Return indexed files for a source even when stored source_root differs slightly."""
    done = _ingest_items_for_source(
        project_id,
        source_path,
        file_type=file_type,
        status="done",
        limit=limit,
        db_path=db_path,
    )
    if done:
        return done

    return _ingest_items_for_source(
        project_id,
        source_path,
        file_type=file_type,
        status="",
        limit=limit,
        db_path=db_path,
    )


def _ingest_items_for_source(
    project_id: int,
    source_path: Path,
    *,
    file_type: str,
    status: str,
    limit: int,
    db_path: Path = DEFAULT_DB_PATH,
) -> list:
    try:
        exact = list_ingest_items(
            project_id,
            source_root=str(source_path),
            file_type=file_type,
            status=status,
            limit=limit,
            db_path=db_path,
        )
        if exact:
            return list(exact)
    except Exception:
        pass

    try:
        items = list_ingest_items(
            project_id,
            file_type=file_type,
            status=status,
            limit=limit,
            db_path=db_path,
        )
    except Exception:
        return []

    source_key = _path_key(source_path).rstrip("\\/")
    out = []
    for item in items:
        item_path = Path(str(getattr(item, "file_path", "") or ""))
        item_key = _path_key(item_path)
        if item_key == source_key or item_key.startswith(source_key + "\\") or item_key.startswith(source_key + "/"):
            out.append(item)
    return out


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


def _should_use_indexed_folder_row(row, cached_json_count: int) -> bool:
    if cached_json_count <= 0:
        return False
    return cached_json_count > MAX_AUTO_PROFILE_JSON_FILES
