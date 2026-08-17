from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableView,
    QVBoxLayout,
)

from core.project_evidence import list_project_saved_pcap_day_rows, resolve_saved_pcap_day_row
from ui.buttons import make_dialog_button
from ui.dict_table_model import DictTableModel
from ui.explore_widgets import CopyableTableView
from ui.table_export import append_table_export_buttons

if TYPE_CHECKING:
    from ui.app import App


def open_project_rows_dialog(
    app: App,
    title: str,
    columns: list[tuple[str, str]],
    rows: list[dict[str, Any]],
    on_double_click: Callable[[dict[str, Any], QDialog], None] | None = None,
    *,
    multi_select: bool = False,
    action_label: str = "Load selected",
    on_action: Callable[[list[dict[str, Any]], QDialog], None] | None = None,
    show_delete: bool = False,
    delete_label: str = "Delete selected",
    on_delete: Callable[[list[dict[str, Any]], QDialog], None] | None = None,
    export_category: str = "json",
    export_source_label: str = "",
    show_export: bool = True,
) -> None:
    if not rows:
        app._message_dialog(title, "No rows are loaded.", width=380)
        return

    dlg = QDialog(app)
    dlg.setWindowTitle(title)
    screen = QGuiApplication.primaryScreen()
    if screen is not None:
        available = screen.availableGeometry()
        dlg.resize(min(1180, available.width() - 120), min(680, available.height() - 120))
    else:
        dlg.resize(1080, 640)

    layout = QVBoxLayout(dlg)
    layout.setContentsMargins(14, 14, 14, 28)
    layout.setSpacing(10)

    hint_text = "Expanded table view. Sort columns, export, or right-click to copy values."
    if multi_select and on_action is not None:
        hint_text += " Select one or more rows, then use Load selected (or double-click one row)."
    if show_delete and on_delete is not None:
        hint_text += " Use Delete selected to remove imported evidence from the project."
    hint = QLabel(hint_text)
    hint.setObjectName("Muted")
    hint.setWordWrap(True)
    layout.addWidget(hint)

    table = CopyableTableView(app)
    table.setModel(DictTableModel(columns, rows))
    table.setSortingEnabled(True)
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QTableView.SelectRows)
    table.setSelectionMode(
        QAbstractItemView.ExtendedSelection if multi_select and on_action else QAbstractItemView.SingleSelection
    )
    table.setEditTriggers(QTableView.NoEditTriggers)
    table.verticalHeader().setVisible(False)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
    table.setMinimumHeight(480)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

    if on_double_click is not None:
        def handle_double_click(index):
            model = table.model()
            if not isinstance(model, DictTableModel) or not index.isValid():
                return
            row_idx = index.row()
            if 0 <= row_idx < len(model.rows):
                on_double_click(model.rows[row_idx], dlg)

        table.doubleClicked.connect(handle_double_click)

    for idx, (key, label) in enumerate(columns):
        name = f"{key} {label}".lower()
        width = 140
        if "detail" in name:
            width = 620
        elif "path" in name:
            width = 520
        elif "event" in name:
            width = 320
        elif "period" in name:
            width = 300
        elif "time" in name or "created" in name:
            width = 220
        elif "name" in name:
            width = 260
        table.setColumnWidth(idx, width)

    layout.addWidget(table, 1)

    footer = QHBoxLayout()
    if multi_select and on_action is not None:
        btn_action = make_dialog_button(action_label)

        def _load_selected() -> None:
            model = table.model()
            if not isinstance(model, DictTableModel):
                return
            indexes = table.selectionModel().selectedRows()
            if not indexes:
                app._message_dialog(title, "Select at least one row.", width=380)
                return
            selected_rows = [model.rows[index.row()] for index in indexes if 0 <= index.row() < len(model.rows)]
            if selected_rows:
                on_action(selected_rows, dlg)

        btn_action.clicked.connect(_load_selected)
        footer.addWidget(btn_action)

    if show_delete and on_delete is not None:
        btn_select_all = make_dialog_button("Select all")

        def _select_all_rows() -> None:
            table.selectAll()

        btn_select_all.clicked.connect(_select_all_rows)
        footer.addWidget(btn_select_all)

        btn_delete = make_dialog_button(delete_label)

        def _delete_selected() -> None:
            model = table.model()
            if not isinstance(model, DictTableModel):
                return
            indexes = table.selectionModel().selectedRows()
            if not indexes:
                app._message_dialog(title, "Select at least one row to delete.", width=380)
                return
            selected_rows = [model.rows[index.row()] for index in indexes if 0 <= index.row() < len(model.rows)]
            if selected_rows:
                on_delete(selected_rows, dlg)

        btn_delete.clicked.connect(_delete_selected)
        footer.addWidget(btn_delete)
    if show_export:
        append_table_export_buttons(
            dlg,
            footer,
            title=title,
            table=table,
            project_id=getattr(app, "current_project_id", None),
            category=export_category,
            source_label=export_source_label,
        )
    footer.addStretch()
    btn_close = make_dialog_button("Close")
    btn_close.clicked.connect(dlg.accept)
    footer.addWidget(btn_close)
    layout.addSpacing(6)
    layout.addLayout(footer)
    dlg.exec()


def open_json_dataset_row(app: App, row: dict[str, Any], dialog: QDialog) -> None:
    paths = [str(path) for path in (row.get("paths") or []) if str(path or "").strip()]
    if paths:
        dialog.accept()
        source = str(getattr(app.dataset_controller, "_json_day_source", "") or "")
        if not source and paths:
            source = str(Path(paths[0]).parent)
        app.dataset_controller._set_json_day_groups(source, {str(row.get("day") or "undated"): paths})
        app.dataset_controller.load_dataset_files(source, paths)
        app.go_to_json_tab(0)
        return

    path_text = str(row.get("path") or "")
    path = Path(path_text)
    if not path_text or not path.exists():
        app._message_dialog("JSON dataset", "Path not found.", path_text or "-", width=460)
        return
    dialog.accept()
    if path.is_file():
        app.dataset_controller.load_dataset_file(str(path))
    elif path.is_dir():
        app.dataset_controller.load_dataset_path(str(path))
    app.go_to_json_tab(0)


def resolve_project_pcap_row(app: App, row: dict[str, Any]) -> dict[str, Any]:
    paths = [str(path) for path in (row.get("paths") or []) if str(path or "").strip()]
    if any(Path(path).is_file() for path in paths):
        return row

    project_id = getattr(app, "current_project_id", None)
    if project_id is None:
        return row

    row_day = str(row.get("day") or "").strip()
    if row_day:
        resolved = resolve_saved_pcap_day_row(project_id, day=row_day)
        if resolved:
            merged = dict(row)
            merged.update(resolved)
            return merged

    row_name = str(row.get("name") or "").strip()
    row_path = str(row.get("path") or "").strip()
    try:
        candidates = list_project_saved_pcap_day_rows(project_id)
    except Exception:
        return row

    for candidate in candidates:
        candidate_day = str(candidate.get("day") or "").strip()
        candidate_name = str(candidate.get("name") or "").strip()
        labels = {value for value in (row_day, row_name, row_path) if value}
        if (
            (row_day and row_day == candidate_day)
            or (row_name and row_name == candidate_name)
            or (row_path and row_path == candidate_name)
            or (candidate_day and candidate_day in labels)
        ):
            merged = dict(row)
            merged.update({
                "day": candidate.get("day") or row.get("day"),
                "name": candidate.get("name") or row.get("name"),
                "paths": candidate.get("paths") or row.get("paths") or [],
                "file_count": candidate.get("file_count") or row.get("file_count"),
            })
            candidate_path = str(candidate.get("path") or "")
            row_path_obj = Path(row_path) if row_path else None
            if candidate_path or not (row_path_obj and row_path_obj.is_file()):
                merged["path"] = candidate_path
            return merged
    return row


def open_pcap_dataset_row(app: App, row: dict[str, Any], dialog: QDialog) -> None:
    row = resolve_project_pcap_row(app, row)
    paths = [str(path) for path in (row.get("paths") or []) if str(path or "").strip()]
    existing_paths = [path for path in paths if Path(path).is_file()]
    if existing_paths:
        dialog.accept()
        app.go_page(app.IDX_PCAP, app._nav_pcap)
        if hasattr(app, "pcap_page"):
            label = str(row.get("name") or "")
            app.pcap_page._load_pcap_files(existing_paths, label=label)
        return

    path_text = str(row.get("path") or "")
    path = Path(path_text)
    if not path_text or not path.is_file():
        if row.get("day") or str(row.get("name") or "").strip():
            app._message_dialog(
                "PCAP dataset",
                "Saved PCAP day cannot be opened because the original source files are not available at their saved paths.",
                str(row.get("name") or row.get("day") or path_text or "-"),
                width=560,
            )
            return
        app._message_dialog("PCAP dataset", "PCAP file not found.", path_text or "-", width=460)
        return
    dialog.accept()
    app.go_page(app.IDX_PCAP, app._nav_pcap)
    if hasattr(app, "pcap_page"):
        app.pcap_page.load_pcap(str(path))


def load_selected_json_dataset_rows(app: App, rows: list[dict[str, Any]], dialog: QDialog) -> None:
    day_groups: dict[str, list[str]] = {}
    all_paths: list[str] = []
    source = str(getattr(app.dataset_controller, "_json_day_source", "") or "")
    for row in rows:
        paths = [str(path) for path in (row.get("paths") or []) if str(path or "").strip()]
        if not paths:
            continue
        day = str(row.get("day") or "undated")
        bucket = day_groups.setdefault(day, [])
        for path in paths:
            if path not in bucket:
                bucket.append(path)
            if path not in all_paths:
                all_paths.append(path)
        if not source:
            source = str(Path(paths[0]).parent)
    if not all_paths:
        app._message_dialog("Recent JSON files", "Selected rows have no loadable JSON paths.", width=420)
        return
    dialog.accept()
    app.dataset_controller._set_json_day_groups(source, day_groups)
    app.dataset_controller.load_dataset_files(source, all_paths)
    app.go_to_json_tab(0)


def load_selected_pcap_dataset_rows(app: App, rows: list[dict[str, Any]], dialog: QDialog) -> None:
    all_paths: list[str] = []
    for row in rows:
        resolved = resolve_project_pcap_row(app, row)
        for path in [str(item) for item in (resolved.get("paths") or []) if str(item or "").strip()]:
            if Path(path).is_file() and path not in all_paths:
                all_paths.append(path)
    if not all_paths:
        app._message_dialog(
            "Recent PCAP days",
            "Selected rows have no PCAP files available at their saved paths.",
            width=480,
        )
        return
    dialog.accept()
    app.go_page(app.IDX_PCAP, app._nav_pcap)
    if hasattr(app, "pcap_page"):
        label = f"{len(rows):,} selected period(s)"
        app.pcap_page._load_pcap_files(all_paths, label=label)


def _collect_row_paths(rows: list[dict[str, Any]]) -> list[str]:
    paths: list[str] = []
    for row in rows:
        for path in [str(item) for item in (row.get("paths") or []) if str(item or "").strip()]:
            if path not in paths:
                paths.append(path)
        path_text = str(row.get("path") or "").strip()
        if path_text and path_text not in paths:
            paths.append(path_text)
    return paths


def delete_selected_json_dataset_rows(app: App, rows: list[dict[str, Any]], dialog: QDialog) -> None:
    project_id = getattr(app, "current_project_id", None)
    if project_id is None:
        app._message_dialog("Recent JSON files", "Open an active project first.", width=420)
        return
    paths = _collect_row_paths(rows)
    if not paths:
        app._message_dialog("Recent JSON files", "Selected rows have no indexed JSON paths.", width=420)
        return
    if not app._confirm_dialog(
        title="Delete JSON evidence",
        message=f"Remove {len(rows):,} selected period(s) from this project?",
        details=f"{len(paths):,} indexed JSON file(s) will be removed from the project ingest index.",
        ok_text="Delete",
        cancel_text="Cancel",
        width=520,
    ):
        return

    from core.db import delete_ingest_items_for_paths, touch_project

    delete_ingest_items_for_paths(int(project_id), paths)
    touch_project(int(project_id))
    from core.project_audit import record_project_activity

    record_project_activity(
        int(project_id),
        "evidence_deleted",
        f"JSON | {len(rows):,} period(s), {len(paths):,} file(s)",
    )
    dialog.accept()
    if hasattr(app.dataset_controller, "_invalidate_ingest_day_groups_cache"):
        app.dataset_controller._invalidate_ingest_day_groups_cache(int(project_id))
    if hasattr(app, "notes_controller"):
        app.notes_controller.refresh_activity_ui_for_project(int(project_id))
    if hasattr(app, "projects_ui_controller"):
        app.projects_ui_controller.refresh_recent_datasets(project_id)
        app.projects_ui_controller.refresh_case_dashboard()
    if hasattr(app, "refresh_activity_profile_ui"):
        app.refresh_activity_profile_ui()
    if hasattr(app.dataset_controller, "sync_json_periods_from_project"):
        app.dataset_controller.sync_json_periods_from_project(project_id)


def delete_selected_pcap_dataset_rows(app: App, rows: list[dict[str, Any]], dialog: QDialog) -> None:
    project_id = getattr(app, "current_project_id", None)
    if project_id is None:
        app._message_dialog("Recent PCAP days", "Open an active project first.", width=420)
        return
    paths: list[str] = []
    period_days: list[str] = []
    for row in rows:
        resolved = resolve_project_pcap_row(app, row)
        for path in [str(item) for item in (resolved.get("paths") or []) if str(item or "").strip()]:
            if path not in paths:
                paths.append(path)
        day = str(resolved.get("day") or "").strip()
        if day and day not in period_days:
            period_days.append(day)

    if not paths and not period_days:
        app._message_dialog("Recent PCAP days", "Selected rows have nothing to remove.", width=420)
        return
    if not app._confirm_dialog(
        title="Delete PCAP evidence",
        message=f"Remove {len(rows):,} selected PCAP period(s) from this project?",
        details="Indexed PCAP files and saved PCAP period summaries for the selection will be removed.",
        ok_text="Delete",
        cancel_text="Cancel",
        width=520,
    ):
        return

    from core.db import (
        delete_ingest_items_for_paths,
        delete_pcap_sources_for_paths,
        delete_pcap_sources_for_period_days,
        touch_project,
    )

    if paths:
        delete_ingest_items_for_paths(int(project_id), paths)
        delete_pcap_sources_for_paths(int(project_id), paths)
    if period_days:
        delete_pcap_sources_for_period_days(int(project_id), period_days)
    touch_project(int(project_id))
    from core.project_audit import record_project_activity

    record_project_activity(
        int(project_id),
        "evidence_deleted",
        (
            f"PCAP | {len(rows):,} period(s), {len(paths):,} file(s), "
            f"{len(period_days):,} saved period(s)"
        ),
    )
    dialog.accept()
    if hasattr(app.dataset_controller, "_invalidate_ingest_day_groups_cache"):
        app.dataset_controller._invalidate_ingest_day_groups_cache(int(project_id))
    if hasattr(app, "notes_controller"):
        app.notes_controller.refresh_activity_ui_for_project(int(project_id))
    if hasattr(app, "projects_ui_controller"):
        app.projects_ui_controller.refresh_recent_datasets(project_id)
        app.projects_ui_controller.refresh_case_dashboard()
    if hasattr(app, "refresh_activity_profile_ui"):
        app.refresh_activity_profile_ui()
    if hasattr(app.dataset_controller, "sync_pcap_periods_from_project"):
        app.dataset_controller.sync_pcap_periods_from_project(project_id)
