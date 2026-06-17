from __future__ import annotations

from typing import Any

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot
from PySide6.QtWidgets import QFileDialog, QMessageBox, QProgressDialog, QTableView, QWidget

from core.db import get_app_settings, get_project
from core.exporters.listing_exporter import export_listing_csv, export_listing_excel
from core.exporters.table_exporter import export_table_html
from core.protocols import format_ip_proto
from core.workspace import workspace_export_path

LARGE_EXPORT_ROW_THRESHOLD = 5000


def table_export_data(table: QTableView) -> tuple[list[str], list[list[str]]]:
    model = table.model()
    if model is None:
        return [], []

    headers = [
        str(model.headerData(col, Qt.Horizontal, Qt.DisplayRole) or "")
        for col in range(model.columnCount())
    ]
    rows: list[list[str]] = []
    for row in range(model.rowCount()):
        rows.append([
            str(model.index(row, col).data(Qt.DisplayRole) or "")
            for col in range(model.columnCount())
        ])
    return headers, rows


def flows_to_export_rows(
    flows: list[dict[str, Any]],
    *,
    columns: list[tuple[str, str]] | None = None,
) -> tuple[list[str], list[list[str]]]:
    from ui.explore_models import FlowTableModel

    cols = columns or FlowTableModel.COLUMNS
    headers = [title for _, title in cols]
    rows: list[list[str]] = []
    for flow in flows:
        if not isinstance(flow, dict):
            continue
        row: list[str] = []
        for key, _ in cols:
            val = flow.get(key, "")
            if key == "protocol":
                val = format_ip_proto(val)
            row.append("" if val is None else str(val))
        rows.append(row)
    return headers, rows


def table_export_default_path(
    title: str,
    suffix: str,
    *,
    project_id: int | None = None,
    category: str = "json",
) -> str:
    safe_title = "".join(ch if ch.isalnum() else "_" for ch in (title or "table_export").lower())
    safe_title = "_".join(part for part in safe_title.split("_") if part) or "table_export"
    base_name = f"{safe_title}.{suffix}"
    if project_id is not None:
        project = get_project(project_id)
        if project and project.base_folder:
            return str(workspace_export_path(project.base_folder, base_name, category=category))
    return base_name


def export_table_file(
    file_path: str,
    title: str,
    headers: list[str],
    rows: list[list[str]],
    export_format: str,
    *,
    project_id: int | None = None,
    project_name: str = "",
    source_label: str = "",
    report_language: str | None = None,
) -> None:
    lang = report_language or get_app_settings().get("output_language", "hr")
    project = get_project(project_id) if project_id is not None else None

    if export_format == "csv":
        export_listing_csv(file_path, headers, rows)
        return
    if export_format == "xlsx":
        export_listing_excel(file_path, headers, rows, sheet_title=title)
        return
    if export_format == "html":
        export_table_html(
            file_path,
            title,
            headers,
            rows,
            lang=lang,
            project=project,
            project_name=project_name,
            source_label=source_label,
        )
        return
    raise ValueError(f"Unsupported export format: {export_format}")


class TableExportWorker(QObject):
    finished = Signal(str)
    error = Signal(str)

    def __init__(
        self,
        file_path: str,
        title: str,
        export_format: str,
        *,
        headers: list[str] | None = None,
        rows: list[list[str]] | None = None,
        flows: list[dict[str, Any]] | None = None,
        project_id: int | None = None,
        project_name: str = "",
        source_label: str = "",
        report_language: str | None = None,
    ):
        super().__init__()
        self.file_path = file_path
        self.title = title
        self.headers = headers or []
        self.rows = rows or []
        self.flows = flows
        self.export_format = export_format
        self.project_id = project_id
        self.project_name = project_name
        self.source_label = source_label
        self.report_language = report_language

    @Slot()
    def run(self) -> None:
        try:
            headers = self.headers
            rows = self.rows
            if self.flows is not None:
                headers, rows = flows_to_export_rows(self.flows)
            export_table_file(
                self.file_path,
                self.title,
                headers,
                rows,
                self.export_format,
                project_id=self.project_id,
                project_name=self.project_name,
                source_label=self.source_label,
                report_language=self.report_language,
            )
            self.finished.emit(self.file_path)
        except Exception as exc:
            self.error.emit(str(exc))


def _run_export_in_background(
    parent: QWidget,
    *,
    file_path: str,
    title: str,
    export_format: str,
    project_id: int | None,
    project_name: str,
    source_label: str,
    report_language: str | None,
    headers: list[str] | None = None,
    rows: list[list[str]] | None = None,
    flows: list[dict[str, Any]] | None = None,
) -> None:
    row_hint = len(flows) if flows is not None else len(rows or [])
    progress = QProgressDialog(f"Exporting {row_hint:,} rows...", None, 0, 0, parent)
    progress.setWindowTitle(f"Export {title}")
    progress.setWindowModality(Qt.WindowModal)
    progress.setMinimumDuration(0)
    progress.setCancelButton(None)
    progress.show()

    thread = QThread(parent)
    worker = TableExportWorker(
        file_path,
        title,
        export_format,
        headers=headers,
        rows=rows,
        flows=flows,
        project_id=project_id,
        project_name=project_name,
        source_label=source_label,
        report_language=report_language,
    )
    worker.moveToThread(thread)
    thread.started.connect(worker.run)

    def _cleanup() -> None:
        progress.close()
        thread.quit()

    def _on_finished(path: str) -> None:
        _cleanup()
        QMessageBox.information(parent, "Export table", f"Exported:\n{path}")

    def _on_error(message: str) -> None:
        _cleanup()
        QMessageBox.critical(parent, "Export table failed", message)

    worker.finished.connect(_on_finished, Qt.QueuedConnection)
    worker.error.connect(_on_error, Qt.QueuedConnection)
    worker.finished.connect(worker.deleteLater)
    worker.error.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)
    thread.start()


def export_table_dialog(
    parent: QWidget,
    title: str,
    table: QTableView,
    export_format: str,
    *,
    project_id: int | None = None,
    category: str = "json",
    source_label: str = "",
    report_language: str | None = None,
    rows_override: list[list[str]] | None = None,
    headers_override: list[str] | None = None,
    flows_override: list[dict[str, Any]] | None = None,
) -> None:
    if flows_override is not None:
        headers, rows = [], []
    elif rows_override is not None and headers_override is not None:
        headers, rows = headers_override, rows_override
    else:
        headers, rows = table_export_data(table)
    if flows_override is None and (not headers or not rows):
        QMessageBox.information(parent, "Export table", "No rows are loaded.")
        return
    if flows_override is not None and not flows_override:
        QMessageBox.information(parent, "Export table", "No rows are loaded.")
        return

    filters = {
        "csv": "CSV files (*.csv)",
        "xlsx": "Excel files (*.xlsx)",
        "html": "HTML files (*.html)",
    }
    suffix = "xlsx" if export_format == "xlsx" else export_format
    file_path, _ = QFileDialog.getSaveFileName(
        parent,
        f"Export {title}",
        table_export_default_path(title, suffix, project_id=project_id, category=category),
        filters.get(export_format, "All files (*.*)"),
    )
    if not file_path:
        return

    project_name = ""
    app = getattr(parent, "app", None)
    if app is not None:
        project_name = getattr(app, "current_project_name", "") or ""
        if project_id is None:
            project_id = getattr(app, "current_project_id", None)

    row_count = len(flows_override) if flows_override is not None else len(rows)
    if row_count >= LARGE_EXPORT_ROW_THRESHOLD:
        _run_export_in_background(
            parent,
            file_path=file_path,
            title=title,
            headers=headers if flows_override is None else None,
            rows=rows if flows_override is None else None,
            flows=flows_override,
            export_format=export_format,
            project_id=project_id,
            project_name=project_name,
            source_label=source_label,
            report_language=report_language,
        )
        return

    try:
        export_table_file(
            file_path,
            title,
            headers,
            rows,
            export_format,
            project_id=project_id,
            project_name=project_name,
            source_label=source_label,
            report_language=report_language,
        )
    except Exception as exc:
        QMessageBox.critical(parent, "Export table failed", str(exc))
        return

    QMessageBox.information(parent, "Export table", f"Exported:\n{file_path}")
