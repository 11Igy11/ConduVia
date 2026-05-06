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

WORKSPACE_MARKER = ".vianyquist-workspace"


def ensure_workspace_structure(base_folder: str) -> None:
    folder = (base_folder or "").strip()
    if not folder:
        return

    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    (root / WORKSPACE_MARKER).write_text("ViaNyquist workspace\n", encoding="utf-8")

    for name in WORKSPACE_SUBFOLDERS:
        (root / name).mkdir(parents=True, exist_ok=True)


def get_workspace_subfolder(base_folder: str, name: str) -> Path | None:
    folder = (base_folder or "").strip()
    if not folder:
        return None

    if name not in WORKSPACE_SUBFOLDERS:
        raise ValueError(f"Unsupported workspace subfolder: {name}")

    return Path(folder) / name


def workspace_export_path(base_folder: str, default_name: str) -> Path:
    name = Path((default_name or "").strip() or "export.html").name
    exports_dir = get_workspace_subfolder(base_folder, "exports")
    if exports_dir is None:
        return Path(name)

    exports_dir.mkdir(parents=True, exist_ok=True)
    return exports_dir / name


def write_project_notes_backup(base_folder: str, text: str) -> None:
    notes_dir = get_workspace_subfolder(base_folder, "notes")
    if notes_dir is None:
        return

    notes_dir.mkdir(parents=True, exist_ok=True)
    notes_file = notes_dir / "project_notes.txt"
    notes_file.write_text(text or "", encoding="utf-8")


def write_workspace_text_file(base_folder: str, subfolder: str, filename: str, text: str) -> Path | None:
    target_dir = get_workspace_subfolder(base_folder, subfolder)
    if target_dir is None:
        return None

    safe_name = Path((filename or "").strip() or "workspace.txt").name
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / safe_name
    target.write_text(text or "", encoding="utf-8")
    return target


def write_project_workspace_manifest(
    base_folder: str,
    *,
    project_name: str = "",
    project_id: int | str = "",
    subject: str = "",
    identifiers: str = "",
    json_datasets: list[str] | tuple[str, ...] | None = None,
    pcap_sources: list[str] | tuple[str, ...] | None = None,
) -> None:
    folder = (base_folder or "").strip()
    if not folder:
        return

    ensure_workspace_structure(folder)
    json_items = [str(item) for item in (json_datasets or []) if str(item or "").strip()]
    pcap_items = [str(item) for item in (pcap_sources or []) if str(item or "").strip()]

    lines = [
        "ViaNyquist project workspace",
        "",
        f"Project: {(project_name or '-').strip() or '-'}",
        f"Project ID: {project_id or '-'}",
        f"Subject: {(subject or '-').strip() or '-'}",
        f"Known identifiers: {(identifiers or '-').strip() or '-'}",
        "",
        f"JSON datasets: {len(json_items)}",
        f"PCAP sources: {len(pcap_items)}",
        "",
        "Workspace folders:",
    ]
    lines.extend(f"- {name}/" for name in WORKSPACE_SUBFOLDERS)
    lines.extend([
        "",
        "Notes:",
        "- project_manifest.txt is a lightweight case index.",
        "- datasets/json_datasets.txt lists saved JSON dataset references.",
        "- datasets/pcap_sources.txt lists saved PCAP source references.",
        "- notes/project_notes.txt is maintained from ViaNyquist Notes.",
    ])

    Path(folder, "project_manifest.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_workspace_text_file(
        folder,
        "datasets",
        "json_datasets.txt",
        "\n".join(json_items) + ("\n" if json_items else ""),
    )
    write_workspace_text_file(
        folder,
        "datasets",
        "pcap_sources.txt",
        "\n".join(pcap_items) + ("\n" if pcap_items else ""),
    )

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

    return (root / WORKSPACE_MARKER).exists()
