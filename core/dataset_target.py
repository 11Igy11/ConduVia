"""Helpers for deciding when dataset target confirmation is needed."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from core.db import DEFAULT_DB_PATH, _dataset_path_key, ingest_status_map, list_recent_dataset_sources


def dataset_target_check_skippable(
    project_id: int,
    source_path: str,
    file_paths: Iterable[str] | None = None,
    *,
    db_path: Path = DEFAULT_DB_PATH,
) -> bool:
    """Return True when this JSON source/files were already accepted in the project."""
    if project_id is None:
        return False

    source_key = _dataset_path_key(str(source_path or "").strip())
    if source_key:
        for row in list_recent_dataset_sources(int(project_id), limit=100, db_path=db_path):
            if _dataset_path_key(str(row["folder_path"] or "")) == source_key:
                return True

    paths = [str(path or "").strip() for path in (file_paths or []) if str(path or "").strip()]
    if not paths:
        return False

    statuses = ingest_status_map(int(project_id), paths, db_path=db_path)
    if not statuses:
        return False
    return all(statuses.get(path) == "done" for path in paths)
