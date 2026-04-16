from __future__ import annotations

from pathlib import Path


WORKSPACE_SUBFOLDERS = (
    "datasets",
    "exports",
    "findings",
    "notes",
    "reports",
)


def ensure_workspace_structure(base_folder: str) -> None:
    folder = (base_folder or "").strip()
    if not folder:
        return

    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)

    for name in WORKSPACE_SUBFOLDERS:
        (root / name).mkdir(parents=True, exist_ok=True)


def get_workspace_subfolder(base_folder: str, name: str) -> Path | None:
    folder = (base_folder or "").strip()
    if not folder:
        return None

    if name not in WORKSPACE_SUBFOLDERS:
        raise ValueError(f"Unsupported workspace subfolder: {name}")

    return Path(folder) / name


def write_project_notes_backup(base_folder: str, text: str) -> None:
    notes_dir = get_workspace_subfolder(base_folder, "notes")
    if notes_dir is None:
        return

    notes_dir.mkdir(parents=True, exist_ok=True)
    notes_file = notes_dir / "project_notes.txt"
    notes_file.write_text(text or "", encoding="utf-8")