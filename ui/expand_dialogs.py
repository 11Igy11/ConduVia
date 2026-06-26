"""Shared expanded-table and missing-period dialogs for PCAP and JSON views."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSplitter,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QHeaderView,
    QWidget,
)

from ui.dict_table_model import DictTableModel
from ui.explore_widgets import CopyableTableView

ExportFooterFn = Callable[[QHBoxLayout, QTableView], None]
DetailTextFn = Callable[[dict[str, Any]], str]
EmptyMessageFn = Callable[[str, str], None]
DayLabelFn = Callable[[str], str]


def expand_dialog_size(preferred_width: int, preferred_height: int) -> tuple[int, int]:
    screen = QApplication.primaryScreen()
    if screen is None:
        return preferred_width, preferred_height
    available = screen.availableGeometry()
    width = min(preferred_width, max(760, available.width() - 120))
    height = min(preferred_height, max(520, available.height() - 120))
    return width, height


def expanded_column_width(column: tuple[str, str], current_width: int) -> int:
    key, title = column
    name = f"{key} {title}".lower()
    preferred = 140
    if "time" in name or "seen" in name:
        preferred = 190
    if "source" in name or "destination" in name or "endpoint" in name:
        preferred = 210
    if "host" in name or "signal" in name or "query" in name:
        preferred = 300
    if "value" in name or "evidence" in name or "detail" in name:
        preferred = 380
    if "packet" in name or "count" in name or "port" in name:
        preferred = 120
    return max(preferred, max(110, min(440, current_width)))


def build_dict_table(
    parent: QWidget,
    columns: list[tuple[str, str]],
    *,
    stretch_last: bool = False,
    fixed_widths: dict[int, int] | None = None,
    stretch_columns: list[int] | None = None,
    min_height: int = 210,
) -> CopyableTableView:
    table = CopyableTableView(parent)
    table.setModel(DictTableModel(columns))
    table.setSortingEnabled(True)
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QTableView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QTableView.NoEditTriggers)
    table.setWordWrap(False)
    table.verticalHeader().setVisible(False)
    table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
    table.setMinimumHeight(min_height)
    header = table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.Interactive)
    header.setStretchLastSection(stretch_last)
    fixed_widths = fixed_widths or {}
    for idx, width in fixed_widths.items():
        if 0 <= idx < len(columns):
            table.setColumnWidth(idx, width)
    for idx in stretch_columns or []:
        if 0 <= idx < len(columns):
            header.setSectionResizeMode(idx, QHeaderView.Stretch)
    return table


def set_dict_table_rows(table: QTableView, rows: list[dict[str, Any]]) -> None:
    model = table.model()
    if not isinstance(model, DictTableModel):
        return
    model.set_rows(rows)
    section = table.horizontalHeader().sortIndicatorSection()
    order = table.horizontalHeader().sortIndicatorOrder()
    if table.isSortingEnabled() and section >= 0:
        model.sort(section, order)


def open_missing_period_days_dialog(
    parent: QWidget,
    *,
    title: str,
    missing_days: list[str],
    first_day_label: str,
    last_day_label: str,
    evidence_kind: str,
    format_day_label: DayLabelFn | None = None,
    on_empty: EmptyMessageFn | None = None,
    append_export_footer: ExportFooterFn | None = None,
) -> None:
    if not missing_days:
        message = "No internal gaps in the indexed period range."
        if on_empty is not None:
            on_empty(title, message)
        return

    label_for = format_day_label or (lambda day: day)
    rows = [{"label": label_for(day), "day": day} for day in missing_days]

    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.resize(720, 560)
    layout = QVBoxLayout(dlg)
    layout.setContentsMargins(14, 14, 14, 28)
    hint = QLabel(
        f"{len(missing_days):,} indexed days missing between {first_day_label} and {last_day_label}. "
        f"These are internal gaps — calendar days inside the imported period with no {evidence_kind} files."
    )
    hint.setWordWrap(True)
    layout.addWidget(hint)

    table = build_dict_table(
        [("label", "Missing day"), ("day", "ISO date")],
        fixed_widths={0: 180, 1: 140},
        min_height=480,
    )
    set_dict_table_rows(table, rows)
    layout.addWidget(table, 1)

    footer = QHBoxLayout()
    if append_export_footer is not None:
        append_export_footer(footer, table)
    footer.addStretch()
    close_btn = QPushButton("Close")
    close_btn.setMinimumHeight(42)
    close_btn.clicked.connect(dlg.accept)
    footer.addWidget(close_btn)
    layout.addLayout(footer)
    dlg.exec()


def open_dict_table_expand_dialog(
    parent: QWidget,
    *,
    title: str,
    source_table: QTableView,
    on_empty: EmptyMessageFn | None = None,
    append_export_footer: ExportFooterFn | None = None,
    hint_text: str = "Expanded table view. Sort columns, select rows, or right-click to copy values.",
) -> None:
    source_model = source_table.model()
    if not isinstance(source_model, DictTableModel) or not source_model.rows:
        if on_empty is not None:
            on_empty(title, "No rows are loaded.")
        return

    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.resize(*expand_dialog_size(1180, 720))

    layout = QVBoxLayout(dlg)
    layout.setContentsMargins(14, 14, 14, 28)
    layout.setSpacing(10)

    hint = QLabel(hint_text)
    hint.setObjectName("MutedLabel")
    hint.setWordWrap(True)
    layout.addWidget(hint)

    fixed_widths = {
        idx: expanded_column_width(source_model.columns[idx], source_table.columnWidth(idx))
        for idx in range(source_model.columnCount())
    }
    table = build_dict_table(
        dlg,
        source_model.columns,
        fixed_widths=fixed_widths,
        stretch_columns=[],
        min_height=520,
    )
    table.verticalHeader().setDefaultSectionSize(max(34, source_table.verticalHeader().defaultSectionSize()))
    set_dict_table_rows(table, list(source_model.rows))
    layout.addWidget(table, 1)

    footer = QHBoxLayout()
    if append_export_footer is not None:
        append_export_footer(footer, table)
    footer.addStretch()
    btn_close = QPushButton("Close")
    btn_close.setMinimumHeight(42)
    btn_close.clicked.connect(dlg.accept)
    footer.addWidget(btn_close)
    layout.addSpacing(6)
    layout.addLayout(footer)
    dlg.exec()


def open_dict_rows_expand_dialog(
    parent: QWidget,
    *,
    title: str,
    columns: list[tuple[str, str]],
    rows: list[dict[str, Any]],
    on_empty: EmptyMessageFn | None = None,
    append_export_footer: ExportFooterFn | None = None,
    hint_text: str = "Sort columns or right-click to copy values.",
    stretch_columns: list[int] | None = None,
) -> None:
    if not rows:
        if on_empty is not None:
            on_empty(title, "No rows are loaded.")
        return

    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.resize(*expand_dialog_size(1180, 720))

    layout = QVBoxLayout(dlg)
    layout.setContentsMargins(14, 14, 14, 28)
    layout.setSpacing(10)

    hint = QLabel(hint_text)
    hint.setObjectName("MutedLabel")
    hint.setWordWrap(True)
    layout.addWidget(hint)

    table = build_dict_table(
        dlg,
        columns,
        stretch_columns=stretch_columns if stretch_columns is not None else list(range(len(columns))),
        min_height=520,
    )
    set_dict_table_rows(table, rows)
    layout.addWidget(table, 1)

    footer = QHBoxLayout()
    if append_export_footer is not None:
        append_export_footer(footer, table)
    footer.addStretch()
    btn_close = QPushButton("Close")
    btn_close.setMinimumHeight(42)
    btn_close.clicked.connect(dlg.accept)
    footer.addWidget(btn_close)
    layout.addLayout(footer)
    dlg.exec()


def open_communication_indicators_dialog(
    parent: QWidget,
    *,
    rows: list[dict[str, Any]],
    columns: list[tuple[str, str]],
    fixed_widths: dict[int, int],
    detail_text: DetailTextFn,
    on_empty: EmptyMessageFn | None = None,
    append_export_footer: ExportFooterFn | None = None,
) -> None:
    if not rows:
        if on_empty is not None:
            on_empty("Communication indicators", "No communication indicators are loaded.")
        return

    dlg = QDialog(parent)
    dlg.setWindowTitle("Communication indicators")
    dlg.resize(*expand_dialog_size(1180, 720))

    layout = QVBoxLayout(dlg)
    layout.setContentsMargins(14, 14, 14, 28)
    layout.setSpacing(10)

    hint = QLabel(
        "Metadata-based communication indicators. Sort columns, select rows, or right-click to copy values."
    )
    hint.setObjectName("MutedLabel")
    hint.setWordWrap(True)
    layout.addWidget(hint)

    table = build_dict_table(
        dlg,
        columns,
        fixed_widths=fixed_widths,
        stretch_columns=[3],
        min_height=520,
    )
    table.setMinimumWidth(980)
    table.verticalHeader().setDefaultSectionSize(42)
    set_dict_table_rows(table, list(rows))

    detail = QTextEdit()
    detail.setReadOnly(True)
    detail.setMinimumWidth(320)
    detail.setPlaceholderText("Select a communication indicator to see the evidence used for classification.")

    def update_detail(current: QModelIndex, previous: QModelIndex | None = None) -> None:
        table_model = table.model()
        if not isinstance(table_model, DictTableModel) or not current.isValid():
            detail.clear()
            return
        if current.row() < 0 or current.row() >= len(table_model.rows):
            detail.clear()
            return
        detail.setPlainText(detail_text(table_model.rows[current.row()]))

    table.selectionModel().currentRowChanged.connect(update_detail)

    detail_group = QGroupBox("Selected indicator evidence")
    detail_layout = QVBoxLayout(detail_group)
    detail_layout.addWidget(detail)

    splitter = QSplitter(Qt.Horizontal)
    splitter.addWidget(table)
    splitter.addWidget(detail_group)
    splitter.setStretchFactor(0, 5)
    splitter.setStretchFactor(1, 1)
    splitter.setCollapsible(0, False)
    splitter.setCollapsible(1, False)
    layout.addWidget(splitter, 1)
    table.selectRow(0)

    footer = QHBoxLayout()
    if append_export_footer is not None:
        append_export_footer(footer, table)
    footer.addStretch()
    btn_close = QPushButton("Close")
    btn_close.setMinimumHeight(42)
    btn_close.clicked.connect(dlg.accept)
    footer.addWidget(btn_close)
    layout.addSpacing(6)
    layout.addLayout(footer)
    dlg.exec()
