from __future__ import annotations

from pathlib import Path
from typing import Any

from core.db import DEFAULT_DB_PATH, list_recent_datasets
from core.loader import list_json_files, load_folder, load_json_file


def load_project_dataset_flows(
    project_id: int,
    *,
    limit: int = 1000,
    db_path: Path = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    paths = list_recent_datasets(project_id, limit=limit, db_path=db_path)
    deduped = _dedupe_paths(paths)
    flows: list[dict[str, Any]] = []
    source_rows: list[dict[str, Any]] = []
    missing_rows: list[dict[str, Any]] = []
    cache_parts: list[str] = []
    json_file_count = 0
    loaded_json_file_count = 0

    for path_text in deduped:
        path = Path(path_text)
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
                files = list_json_files(path)
                json_file_count += len(files)
                _files, loaded = load_folder(path, debug=False)
                row["type"] = "folder"
                loaded_json_file_count += len(files)
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
        "saved_path_count": len(paths),
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
    paths = list_recent_datasets(project_id, limit=limit, db_path=db_path)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    for path_text in _dedupe_paths(paths):
        path = Path(path_text)

        if path.is_file() and path.suffix.lower() == ".json":
            candidates = [path]
            source_kind = "JSON file"
        elif path.is_dir():
            try:
                candidates = list_json_files(path)
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
            })

    return rows


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
