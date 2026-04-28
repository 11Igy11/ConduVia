from __future__ import annotations

from pathlib import Path
import shutil
import re


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

def make_safe_project_folder_name(project_name: str) -> str:
    name = (project_name or "").strip()
    if not name:
        raise ValueError("Project name is required.")

    # zamijeni nedozvoljene znakove s "_"
    name = re.sub(r'[<>:"/\\|?*]+', "_", name)

    # zamijeni višestruke whitespace znakove s "_"
    name = re.sub(r"\s+", "_", name)

    # ukloni višestruke underscoreove
    name = re.sub(r"_+", "_", name)

    # makni točke i underscoreove s krajeva
    name = name.strip("._ ")

    if not name:
        raise ValueError("Project name produced an empty folder name.")

    return name

def build_workspace_path(parent_folder: str, project_name: str) -> Path:
    parent = (parent_folder or "").strip()
    if not parent:
        raise ValueError("Parent folder is required.")

    parent_path = Path(parent)
    safe_name = make_safe_project_folder_name(project_name)

    return parent_path / safe_name

def move_workspace_folder(current_workspace: str, new_workspace: str) -> None:
    current = Path((current_workspace or "").strip())
    target = Path((new_workspace or "").strip())

    if not current.exists() or not current.is_dir():
        raise FileNotFoundError(f"Current workspace folder not found: {current}")

    if current.resolve() == target.resolve():
        return

    if target.exists():
        raise FileExistsError(f"Target workspace folder already exists: {target}")

    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(current), str(target))

def delete_workspace_folder(base_folder: str) -> None:
    folder = (base_folder or "").strip()
    if not folder:
        return

    root = Path(folder)
    if not root.exists() or not root.is_dir():
        return

    shutil.rmtree(root)

def looks_like_vianyquist_workspace(base_folder: str) -> bool:
    folder = (base_folder or "").strip()
    if not folder:
        return False

    root = Path(folder)
    if not root.exists() or not root.is_dir():
        return False

    return any((root / name).exists() and (root / name).is_dir() for name in WORKSPACE_SUBFOLDERS)