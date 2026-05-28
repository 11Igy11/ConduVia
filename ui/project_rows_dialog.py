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
    QPushButton,
    QTableView,
    QVBoxLayout,
)

from core.project_evidence import list_project_saved_pcap_day_rows
from ui.explore_widgets import CopyableTableView

if TYPE_CHECKING:
    from ui.app import App
    from ui.pcap_page import DictTableModel


def open_project_rows_dialog(
    app: App,
    title: str,
    columns: list[tuple[str, str]],
    rows: list[dict[str, Any]],
    on_double_click: Callable[[dict[str, Any], QDialog], None] | None = None,
) -> None:
    from ui.pcap_page import DictTableModel

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

    hint = QLabel("Expanded project view. Sort columns or right-click to copy values.")
    hint.setObjectName("Muted")
    hint.setWordWrap(True)
    layout.addWidget(hint)

    table = CopyableTableView(app)
    table.setModel(DictTableModel(columns, rows))
    table.setSortingEnabled(True)
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QTableView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
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
    footer.addStretch()
    btn_close = QPushButton("Close")
    btn_close.setMinimumHeight(42)
    btn_close.clicked.connect(dlg.accept)
    footer.addWidget(btn_close)
    layout.addSpacing(6)
    layout.addLayout(footer)
    dlg.exec()


def open_json_dataset_row(app: App, row: dict[str, Any], dialog: QDialog) -> None:
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
