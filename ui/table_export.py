from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QTableView, QWidget

from core.db import get_project
from core.exporters.listing_exporter import export_listing_csv, export_listing_excel
from core.exporters.table_exporter import export_table_html
from core.protocols import format_ip_proto
from core.workspace import workspace_export_path
from ui.dialogs import message_dialog
from ui.export_menu import connect_table_export_dropdown, make_export_table_button


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
) -> None:
    project = get_project(project_id) if project_id is not None else None

    if export_format == "csv":
        export_listing_csv(
            file_path,
            headers,
            rows,
            project=project,
            project_name=project_name,
        )
        return
    if export_format == "xlsx":
        export_listing_excel(
            file_path,
            headers,
            rows,
            sheet_title=title,
            project=project,
            project_name=project_name,
        )
        return
    if export_format == "html":
        export_table_html(
            file_path,
            title,
            headers,
            rows,
            project=project,
            project_name=project_name,
            source_label=source_label,
        )
        return
    raise ValueError(f"Unsupported export format: {export_format}")


def resolve_export_project(parent: QWidget, project_id: int | None = None) -> tuple[int | None, str]:
    project_name = ""
    app = getattr(parent, "app", None)
    if app is not None:
        project_name = getattr(app, "current_project_name", "") or ""
        if project_id is None:
            project_id = getattr(app, "current_project_id", None)
    return project_id, project_name


def notify_export_empty(parent: QWidget, *, title: str = "Export table") -> None:
    message_dialog(parent, title, "No rows are loaded.", width=400)


def notify_export_success(parent: QWidget, file_path: str, *, title: str = "Export table") -> None:
    message_dialog(
        parent,
        title,
        "Export completed successfully.",
        details=f"File:\n{file_path}",
        width=460,
    )


def notify_export_error(parent: QWidget, message: str, *, title: str = "Export failed") -> None:
    message_dialog(parent, title, "Export failed.", details=message, width=480)


def append_table_export_dropdown(
    parent: QWidget,
    footer_layout: QHBoxLayout,
    *,
    title: str,
    table: QTableView,
    button_text: str = "Export table",
    project_id: int | None = None,
    category: str = "json",
    source_label: str = "",
) -> QWidget:
    button = make_export_table_button(button_text)

    def _export(export_format: str) -> None:
        export_table_dialog(
            parent,
            title,
            table,
            export_format,
            project_id=project_id,
            category=category,
            source_label=source_label,
        )

    connect_table_export_dropdown(button, _export)
    footer_layout.addWidget(button)
    return button


def append_table_export_footer(
    parent: QWidget,
    footer_layout: QHBoxLayout,
    *,
    title: str,
    table: QTableView,
    project_id: int | None = None,
    category: str = "json",
    source_label: str = "",
    button_text: str = "Export table",
) -> QWidget:
    """Add an Export table dropdown to a dialog footer row."""
    return append_table_export_dropdown(
        parent,
        footer_layout,
        title=title,
        table=table,
        button_text=button_text,
        project_id=project_id,
        category=category,
        source_label=source_label,
    )


# Backward-compatible alias for older imports.
append_table_export_buttons = append_table_export_dropdown


def export_table_dialog(
    parent: QWidget,
    title: str,
    table: QTableView,
    export_format: str,
    *,
    project_id: int | None = None,
    category: str = "json",
    source_label: str = "",
    flows_override: list[dict[str, Any]] | None = None,
) -> None:
    if flows_override is not None:
        headers, rows = flows_to_export_rows(flows_override)
    else:
        headers, rows = table_export_data(table)
    if not headers or not rows:
        notify_export_empty(parent)
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

    project_id, project_name = resolve_export_project(parent, project_id)

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
        )
    except Exception as exc:
        notify_export_error(parent, str(exc))
        return

    notify_export_success(parent, file_path)
