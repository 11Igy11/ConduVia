from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtWidgets import QFileDialog, QWidget

from core.db import get_project
from core.exporters.notes_exporter import export_notes_docx
from core.workspace import workspace_export_path, write_project_notes_backup
from ui.controllers.notes_controller import NotesController
from ui.notes_page import NotesPage


@dataclass(frozen=True)
class NotesExportResult:
    exported: bool
    file_path: str = ""
    error: str = ""
    cancelled: bool = False


def load_project_notes(
    *,
    project_id: int | None,
    notes_controller: NotesController,
    notes_page: NotesPage,
) -> None:
    if project_id is None:
        notes_page.set_notes("")
        notes_page.set_project_active(False)
        return

    notes_page.set_project_active(True)
    notes_page.set_notes(notes_controller.load_notes(project_id))


def save_project_notes(
    *,
    project_id: int | None,
    notes_controller: NotesController,
    notes_page: NotesPage,
) -> bool:
    if project_id is None:
        return False

    text = notes_page.notes_text()
    plain_text = notes_page.notes_plain_text()
    notes_controller.save_notes(project_id, text)

    try:
        project = get_project(project_id)
        if project and project.base_folder:
            write_project_notes_backup(project.base_folder, plain_text)
    except Exception:
        pass

    return True


def export_notes_word(
    parent: QWidget,
    *,
    project_id: int | None,
    project_name: str | None,
    notes_page: NotesPage,
) -> NotesExportResult:
    if project_id is None:
        return NotesExportResult(exported=False, error="Open an active project first.")

    project = get_project(project_id)
    default_name = f"{project_name or 'project'}-notes.docx"
    default_path = (
        str(workspace_export_path(project.base_folder, default_name, category="notes"))
        if project and project.base_folder
        else default_name
    )

    file_path, _ = QFileDialog.getSaveFileName(
        parent,
        "Export notes to Word",
        default_path,
        "Word documents (*.docx)",
    )
    if not file_path:
        return NotesExportResult(exported=False, cancelled=True)
    if not file_path.lower().endswith(".docx"):
        file_path += ".docx"

    try:
        export_notes_docx(
            file_path,
            title=f"Project notes: {project_name or 'Project'}",
            notes_text=notes_page.notes_plain_text(),
            notes_html=notes_page.notes_text(),
        )
    except Exception as exc:
        return NotesExportResult(exported=False, error=str(exc))

    return NotesExportResult(exported=True, file_path=file_path)
