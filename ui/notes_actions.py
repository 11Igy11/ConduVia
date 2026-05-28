from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from PySide6.QtGui import QTextDocument
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import QFileDialog, QWidget

from core.db import get_project
from core.exporters.notes_exporter import export_notes_docx, export_notes_html
from core.workspace import workspace_export_path, write_project_notes_backup
from ui.notes_charts import available_notes_charts, render_notes_chart
from ui.notes_page import NotesPage

if TYPE_CHECKING:
    from ui.controllers.notes_controller import NotesController


@dataclass(frozen=True)
class NotesExportResult:
    exported: bool
    file_path: str = ""
    error: str = ""
    cancelled: bool = False


@dataclass(frozen=True)
class NotesChartResult:
    inserted: bool
    error: str = ""
    details: str = ""
    cancelled: bool = False
    no_data: bool = False


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


def insert_notes_chart(
    *,
    parent: QWidget,
    project_id: int | None,
    notes_page: NotesPage,
    profile: dict[str, Any] | None,
    pcap_summary: Any,
    choose_chart: Callable[[list[str]], tuple[str, bool]],
) -> NotesChartResult:
    if project_id is None:
        return NotesChartResult(inserted=False, error="Open an active project first.")

    behavior = (profile or {}).get("behavior_profile") or {}
    charts = available_notes_charts(profile or {}, behavior, pcap_summary)
    choices = [chart["name"] for chart in charts]
    choice, ok = choose_chart(choices)
    if not ok:
        return NotesChartResult(inserted=False, cancelled=True)

    chart = next((item for item in charts if item["name"] == choice), None)
    if not chart:
        return NotesChartResult(inserted=False, cancelled=True)

    rows = list(chart.get("rows") or [])
    if not rows:
        return NotesChartResult(
            inserted=False,
            no_data=True,
            error="No chart data is available yet.",
            details=str(chart.get("empty_text") or "Save datasets/PCAP captures to the active project, then try again."),
        )

    project = get_project(project_id)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"{chart['filename']}-{timestamp}.png"
    chart_path = (
        workspace_export_path(project.base_folder, default_name, category="notes")
        if project and project.base_folder
        else Path(default_name)
    )

    try:
        render_notes_chart(chart_path, chart, rows)
        notes_page.insert_image_file(str(chart_path))
    except Exception as exc:
        return NotesChartResult(inserted=False, error="Failed to insert chart.", details=str(exc))

    return NotesChartResult(inserted=True)


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


def export_notes_html_action(
    parent: QWidget,
    *,
    project_id: int | None,
    project_name: str | None,
    notes_page: NotesPage,
) -> NotesExportResult:
    if project_id is None:
        return NotesExportResult(exported=False, error="Open an active project first.")

    project = get_project(project_id)
    default_name = f"{project_name or 'project'}-notes.html"
    default_path = (
        str(workspace_export_path(project.base_folder, default_name, category="notes"))
        if project and project.base_folder
        else default_name
    )

    file_path, _ = QFileDialog.getSaveFileName(
        parent,
        "Export notes to HTML",
        default_path,
        "HTML documents (*.html)",
    )
    if not file_path:
        return NotesExportResult(exported=False, cancelled=True)
    if not file_path.lower().endswith(".html"):
        file_path += ".html"

    try:
        export_notes_html(
            file_path,
            title=f"Project notes: {project_name or 'Project'}",
            notes_text=notes_page.notes_plain_text(),
            notes_html=notes_page.notes_text(),
        )
    except Exception as exc:
        return NotesExportResult(exported=False, error=str(exc))

    return NotesExportResult(exported=True, file_path=file_path)


def export_notes_pdf(
    parent: QWidget,
    *,
    project_id: int | None,
    project_name: str | None,
    notes_page: NotesPage,
) -> NotesExportResult:
    if project_id is None:
        return NotesExportResult(exported=False, error="Open an active project first.")

    project = get_project(project_id)
    default_name = f"{project_name or 'project'}-notes.pdf"
    default_path = (
        str(workspace_export_path(project.base_folder, default_name, category="notes"))
        if project and project.base_folder
        else default_name
    )

    file_path, _ = QFileDialog.getSaveFileName(
        parent,
        "Export notes to PDF",
        default_path,
        "PDF documents (*.pdf)",
    )
    if not file_path:
        return NotesExportResult(exported=False, cancelled=True)
    if not file_path.lower().endswith(".pdf"):
        file_path += ".pdf"

    try:
        printer = QPrinter(QPrinter.HighResolution)
        printer.setOutputFormat(QPrinter.PdfFormat)
        printer.setOutputFileName(file_path)
        document = QTextDocument()
        document.setHtml(notes_page.notes_text())
        document.print_(printer)
    except Exception as exc:
        return NotesExportResult(exported=False, error=str(exc))

    return NotesExportResult(exported=True, file_path=file_path)
