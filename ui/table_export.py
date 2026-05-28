from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QMessageBox, QTableView, QWidget

from core.db import get_project
from core.exporters.listing_exporter import export_listing_csv, export_listing_excel
from core.exporters.table_exporter import export_table_html
from core.workspace import workspace_export_path


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


def export_table_dialog(
    parent: QWidget,
    title: str,
    table: QTableView,
    export_format: str,
    *,
    project_id: int | None = None,
    category: str = "json",
) -> None:
    headers, rows = table_export_data(table)
    if not headers or not rows:
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

    try:
        if export_format == "csv":
            export_listing_csv(file_path, headers, rows)
        elif export_format == "xlsx":
            export_listing_excel(file_path, headers, rows)
        elif export_format == "html":
            export_table_html(file_path, title, headers, rows)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
    except Exception as exc:
        QMessageBox.critical(parent, "Export table failed", str(exc))
        return

    QMessageBox.information(parent, "Export table", f"Exported:\n{file_path}")
