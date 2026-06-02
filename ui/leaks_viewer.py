from __future__ import annotations

import json

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.leaks.db import (
    dataset_layout,
    delete_dataset,
    delete_record,
    extra_field_names,
    get_dataset,
    list_datasets,
    populated_columns,
)
from core.leaks.search import search_records
from ui.create_dataset_dialog import CreateDatasetDialog
from ui.leak_record_dialog import LeakRecordDialog

PAGE_SIZE = 100

# Display order + labels for all candidate columns. Only the columns that
# actually hold data in the selected dataset(s) are shown.
_DISPLAY_LABELS = {
    "phone": "Phone",
    "first_name": "First name",
    "last_name": "Last name",
    "full_name": "Full name",
    "gender": "Gender",
    "birthday": "Born",
    "city": "City",
    "hometown": "Hometown",
    "employer": "Employer",
    "email": "Email",
    "fb_id": "Facebook ID",
    "oib": "OIB",
    "username": "Username",
    "address": "Address",
    "secret": "Password/Hash",
}
_DISPLAY_ORDER = [
    "phone", "first_name", "last_name", "gender", "birthday", "city",
    "hometown", "employer", "email", "fb_id", "oib", "username", "address", "secret",
]
_DEFAULT_COLUMNS = [("dataset_name", "Dataset"), ("phone", "Phone"),
                    ("first_name", "First name"), ("last_name", "Last name")]


class LeaksViewerDialog(QDialog):
    def __init__(self, app=None):
        super().__init__(app)
        self.app = app
        self.setWindowTitle("Repository")
        self.setMinimumSize(720, 480)
        # Non-modal so it can stay open beside the main window.
        self.setModal(False)
        self.setWindowFlag(Qt.Window, True)

        self._offset = 0
        self._total = 0
        self._rows: list = []
        self._columns: list[tuple[str, str]] = list(_DEFAULT_COLUMNS)

        root = QHBoxLayout(self)
        root.setContentsMargins(14, 14, 14, 14)
        root.setSpacing(12)

        # --- Left: dataset selector ---
        left = QVBoxLayout()
        left.setSpacing(6)
        self.lbl_datasets = QLabel("Datasets (double-click to open)")
        self.lbl_datasets.setWordWrap(True)
        left.addWidget(self.lbl_datasets)
        self.list_datasets = QListWidget()
        self.list_datasets.setMaximumWidth(260)
        self.list_datasets.itemDoubleClicked.connect(lambda *_: self._on_dataset_changed())
        left.addWidget(self.list_datasets, 1)

        ds_buttons = QHBoxLayout()
        ds_buttons.setSpacing(6)
        self.btn_new_dataset = QPushButton("New")
        self.btn_edit_dataset = QPushButton("Edit")
        self.btn_delete_dataset = QPushButton("Delete")
        for b in (self.btn_new_dataset, self.btn_edit_dataset, self.btn_delete_dataset):
            b.setObjectName("CompactButton")
            b.setCursor(Qt.PointingHandCursor)
        self.btn_delete_dataset.setStyleSheet(
            "QPushButton { color: #fca5a5; border: 1px solid #b91c1c; }"
            "QPushButton:hover { background: #7f1d1d; color: #ffffff; }"
        )
        self.btn_new_dataset.clicked.connect(self._new_dataset)
        self.btn_edit_dataset.clicked.connect(self._edit_dataset)
        self.btn_delete_dataset.clicked.connect(self._delete_dataset)
        ds_buttons.addWidget(self.btn_new_dataset)
        ds_buttons.addWidget(self.btn_edit_dataset)
        ds_buttons.addWidget(self.btn_delete_dataset)
        left.addLayout(ds_buttons)

        left_box = QWidget()
        left_box.setLayout(left)
        left_box.setMaximumWidth(270)
        root.addWidget(left_box)

        # --- Right: search + results ---
        right = QVBoxLayout()
        right.setSpacing(10)

        search_row = QHBoxLayout()
        search_row.setSpacing(6)
        self.edit_search = QLineEdit()
        self.edit_search.setPlaceholderText("Search all parameters (phone, email, OIB, name, city, employer…)")
        self.btn_search = QPushButton("Search")
        self.btn_clear = QPushButton("Clear")
        search_row.addWidget(self.edit_search, 1)
        search_row.addWidget(self.btn_search)
        search_row.addWidget(self.btn_clear)
        right.addLayout(search_row)

        # Results table
        self.table = QTableWidget()
        self.table.setColumnCount(len(self._columns))
        self.table.setHorizontalHeaderLabels([label for _, label in self._columns])
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        # Let the user drag column headers to reorder them.
        self.table.horizontalHeader().setSectionsMovable(True)
        self.table.horizontalHeader().setToolTip("Drag column headers to reorder")
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        right.addWidget(self.table, 1)

        # Pagination + actions
        bottom = QHBoxLayout()
        bottom.setSpacing(6)
        self.btn_prev = QPushButton("◀ Previous")
        self.btn_next = QPushButton("Next ▶")
        self.lbl_page = QLabel("0 results")
        self.btn_new = QPushButton("New record")
        self.btn_edit = QPushButton("Edit")
        self.btn_delete = QPushButton("Delete")
        self.btn_add_notes = QPushButton("Add to Notes")
        bottom.addWidget(self.btn_prev)
        bottom.addWidget(self.btn_next)
        bottom.addWidget(self.lbl_page)
        bottom.addStretch(1)
        bottom.addWidget(self.btn_new)
        bottom.addWidget(self.btn_edit)
        bottom.addWidget(self.btn_delete)
        bottom.addWidget(self.btn_add_notes)
        right.addLayout(bottom)

        # Use the same compact button style as the rest of the app.
        for button in (
            self.btn_search,
            self.btn_clear,
            self.btn_prev,
            self.btn_next,
            self.btn_new,
            self.btn_edit,
            self.btn_delete,
            self.btn_add_notes,
        ):
            button.setObjectName("CompactButton")
            button.setCursor(Qt.PointingHandCursor)
        # Keep Delete compact but tinted red (DangerButton would force a large size).
        self.btn_delete.setStyleSheet(
            "QPushButton { color: #fca5a5; border: 1px solid #b91c1c; }"
            "QPushButton:hover { background: #7f1d1d; color: #ffffff; }"
        )

        # Footer signature (bottom-right)
        footer = QHBoxLayout()
        footer.addStretch(1)
        self.lbl_signature = QLabel("by _Igy_")
        self.lbl_signature.setObjectName("Signature")
        footer.addWidget(self.lbl_signature)
        right.addLayout(footer)

        root.addLayout(right, 1)

        # Debounce timer for the global search box
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(350)
        self._debounce.timeout.connect(lambda: self._run_search(reset=True))
        self.edit_search.textChanged.connect(lambda *_: self._debounce.start())

        self.btn_search.clicked.connect(lambda: self._run_search(reset=True))
        self.btn_clear.clicked.connect(self._clear)
        self.btn_prev.clicked.connect(self._prev_page)
        self.btn_next.clicked.connect(self._next_page)
        self.btn_new.clicked.connect(self._new_record)
        self.btn_edit.clicked.connect(self._edit_record)
        self.btn_delete.clicked.connect(self._delete_record)
        self.btn_add_notes.clicked.connect(self._add_to_notes)
        self.table.doubleClicked.connect(lambda *_: self._edit_record())

        self.fit_to_screen()
        self.refresh_datasets()
        self._update_visible_columns()
        self._run_search(reset=True)

    def _on_dataset_changed(self) -> None:
        self._update_dataset_label()
        self._update_visible_columns()
        self._run_search(reset=True)

    def _update_dataset_label(self) -> None:
        item = self.list_datasets.currentItem()
        if item is None:
            self.lbl_datasets.setText("Datasets (double-click to open)")
        else:
            self.lbl_datasets.setText(f"Dataset: {item.text()}")

    def _update_visible_columns(self) -> None:
        dataset_id = self._selected_dataset_id()
        try:
            populated = set(populated_columns(dataset_id))
        except Exception:
            populated = set()
        try:
            extra_keys = set(extra_field_names(dataset_id))
        except Exception:
            extra_keys = set()
        try:
            layout = dataset_layout(dataset_id)
        except Exception:
            layout = []

        columns = [("dataset_name", "Dataset")]
        if layout:
            # Follow the exact order the user mapped at import time, hiding
            # any column that ended up with no data.
            for token in layout:
                if token in _DISPLAY_LABELS:
                    if token in populated:
                        columns.append((token, _DISPLAY_LABELS[token]))
                elif token in extra_keys:
                    columns.append((f"extra:{token}", token))
        else:
            # Older datasets without a stored layout: canonical first, then custom.
            for key in _DISPLAY_ORDER:
                if key in populated:
                    columns.append((key, _DISPLAY_LABELS[key]))
            for key in sorted(extra_keys):
                columns.append((f"extra:{key}", key))

        if len(columns) == 1:
            columns = list(_DEFAULT_COLUMNS)
        self._columns = columns
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels([label for _, label in columns])
        self.table.horizontalHeader().setStretchLastSection(True)

    def fit_to_screen(self) -> None:
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is None:
            return
        avail = screen.availableGeometry()
        width = min(1200, int(avail.width() * 0.9))
        height = min(800, int(avail.height() * 0.9))
        self.resize(width, height)
        self.move(
            avail.x() + (avail.width() - width) // 2,
            avail.y() + (avail.height() - height) // 2,
        )

    # ------------------------------------------------------------- datasets
    def refresh_datasets(self) -> None:
        self.list_datasets.blockSignals(True)
        self.list_datasets.clear()
        all_item = QListWidgetItem("All datasets")
        all_item.setData(Qt.UserRole, None)
        self.list_datasets.addItem(all_item)
        try:
            datasets = list_datasets()
        except Exception:
            datasets = []
        for row in datasets:
            count = int(row["record_count"] or 0)
            item = QListWidgetItem(f"{row['name']} ({count:,})")
            item.setData(Qt.UserRole, int(row["id"]))
            self.list_datasets.addItem(item)
        # Nothing is selected by default: the user double-clicks to load.
        self.list_datasets.setCurrentRow(-1)
        self.list_datasets.blockSignals(False)
        self._update_dataset_label()

    def _selected_dataset_id(self) -> int | None:
        item = self.list_datasets.currentItem()
        if item is None:
            return None
        return item.data(Qt.UserRole)

    # --------------------------------------------------------------- search
    def _run_search(self, *, reset: bool) -> None:
        if reset:
            self._offset = 0
        if self.list_datasets.currentItem() is None:
            self._rows = []
            self._total = 0
            self.table.setRowCount(0)
            self.lbl_page.setText("Double-click a dataset (or “All datasets”) to load records.")
            self.btn_prev.setEnabled(False)
            self.btn_next.setEnabled(False)
            return
        text = self.edit_search.text().strip()
        dataset_id = self._selected_dataset_id()
        try:
            rows, total = search_records(
                None,
                text,
                dataset_id=dataset_id,
                limit=PAGE_SIZE,
                offset=self._offset,
            )
        except Exception as exc:
            self.lbl_page.setText(f"Error: {exc}")
            return
        self._rows = rows
        self._total = total
        self._fill_table(rows)
        self._update_pagination()

    def _fill_table(self, rows: list) -> None:
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            extra_data: dict | None = None
            for c, (key, _label) in enumerate(self._columns):
                if key.startswith("extra:"):
                    if extra_data is None:
                        try:
                            extra_data = json.loads(row["extra"] or "{}")
                        except Exception:
                            extra_data = {}
                    value = extra_data.get(key[6:], "")
                else:
                    try:
                        value = row[key]
                    except (IndexError, KeyError):
                        value = ""
                item = QTableWidgetItem("" if value is None else str(value))
                self.table.setItem(r, c, item)
        self.table.resizeColumnsToContents()
        # Never truncate the header label: widen any column whose header text
        # is wider than its (possibly empty) data.
        fm = self.table.horizontalHeader().fontMetrics()
        for c, (_key, label) in enumerate(self._columns):
            needed = fm.horizontalAdvance(label) + 30
            if self.table.columnWidth(c) < needed:
                self.table.setColumnWidth(c, needed)

    def _update_pagination(self) -> None:
        if self._total == 0:
            self.lbl_page.setText("0 results")
        else:
            start = self._offset + 1
            end = min(self._offset + PAGE_SIZE, self._total)
            self.lbl_page.setText(f"{start:,}–{end:,} of {self._total:,}")
        self.btn_prev.setEnabled(self._offset > 0)
        self.btn_next.setEnabled(self._offset + PAGE_SIZE < self._total)

    def _prev_page(self) -> None:
        if self._offset > 0:
            self._offset = max(0, self._offset - PAGE_SIZE)
            self._run_search(reset=False)

    def _next_page(self) -> None:
        if self._offset + PAGE_SIZE < self._total:
            self._offset += PAGE_SIZE
            self._run_search(reset=False)

    def _clear(self) -> None:
        self.edit_search.clear()
        self._run_search(reset=True)

    # ----------------------------------------------------------- edit / add
    def _refresh_after_change(self, dataset_id: int | None) -> None:
        # Datasets' record counts may have changed; refresh list + columns + page.
        self.refresh_datasets()
        self._update_visible_columns()
        self._run_search(reset=False)

    def _select_dataset(self, dataset_id: int | None) -> None:
        for row in range(self.list_datasets.count()):
            item = self.list_datasets.item(row)
            if item.data(Qt.UserRole) == dataset_id:
                self.list_datasets.setCurrentRow(row)
                self._update_dataset_label()
                return

    def _new_dataset(self) -> None:
        dialog = CreateDatasetDialog(self)
        if dialog.exec() == QDialog.Accepted and dialog.created_dataset_id:
            self.refresh_datasets()
            self._select_dataset(int(dialog.created_dataset_id))
            self._update_visible_columns()
            self._run_search(reset=True)
            # Offer to start adding records right away.
            self._new_record()

    def _edit_dataset(self) -> None:
        dataset_id = self._selected_dataset_id()
        if dataset_id is None:
            self.lbl_page.setText("Select a specific dataset (not “All datasets”) to edit.")
            return
        dataset = get_dataset(int(dataset_id))
        if dataset is None:
            self.lbl_page.setText("Dataset not found.")
            return
        dialog = CreateDatasetDialog(self, dataset=dataset)
        if dialog.exec() == QDialog.Accepted and dialog.saved:
            self.refresh_datasets()
            self._select_dataset(int(dataset_id))
            self._update_visible_columns()
            self._run_search(reset=True)

    def _delete_dataset(self) -> None:
        dataset_id = self._selected_dataset_id()
        if dataset_id is None:
            self.lbl_page.setText("Select a specific dataset (not “All datasets”) to delete.")
            return
        from PySide6.QtWidgets import QMessageBox

        item = self.list_datasets.currentItem()
        label = item.text() if item is not None else "this dataset"
        confirm = QMessageBox.question(
            self,
            "Delete dataset",
            f"Delete '{label}' and all of its records permanently?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            delete_dataset(int(dataset_id))
        except Exception as exc:
            self.lbl_page.setText(f"Delete failed: {exc}")
            return
        self.refresh_datasets()
        self._update_visible_columns()
        self._run_search(reset=True)

    def _new_record(self) -> None:
        if not list_datasets():
            self.lbl_page.setText("Import a dataset before adding records.")
            return
        dialog = LeakRecordDialog(self, dataset_id=self._selected_dataset_id())
        if dialog.exec() == QDialog.Accepted and dialog.saved:
            self._refresh_after_change(dialog.affected_dataset_id)

    def _edit_record(self) -> None:
        row = self._current_row()
        if not row:
            self.lbl_page.setText("Select a row to edit.")
            return
        dialog = LeakRecordDialog(self, record=row)
        if dialog.exec() == QDialog.Accepted and dialog.saved:
            self._refresh_after_change(dialog.affected_dataset_id)

    def _delete_record(self) -> None:
        row = self._current_row()
        if not row or not row.get("id"):
            self.lbl_page.setText("Select a row to delete.")
            return
        from PySide6.QtWidgets import QMessageBox

        confirm = QMessageBox.question(
            self,
            "Delete record",
            "Delete the selected record permanently?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return
        try:
            delete_record(int(row["id"]))
        except Exception as exc:
            self.lbl_page.setText(f"Delete failed: {exc}")
            return
        self._refresh_after_change(self._selected_dataset_id())

    # -------------------------------------------------------------- actions
    def _current_row(self) -> dict | None:
        index = self.table.currentRow()
        if index < 0 or index >= len(self._rows):
            return None
        return {key: self._rows[index][key] for key in self._rows[index].keys()}

    def _row_summary(self, row: dict) -> str:
        order = [
            ("full_name", "Name"),
            ("phone", "Phone"),
            ("email", "Email"),
            ("oib", "OIB"),
            ("fb_id", "Facebook ID"),
            ("gender", "Gender"),
            ("birthday", "Born"),
            ("city", "City"),
            ("hometown", "Hometown"),
            ("employer", "Employer"),
            ("address", "Address"),
        ]
        lines = []
        for key, label in order:
            value = str(row.get(key) or "").strip()
            if value:
                lines.append(f"{label}: {value}")
        extra = row.get("extra")
        if extra:
            try:
                data = json.loads(extra)
                for key, value in data.items():
                    if value:
                        lines.append(f"{key}: {value}")
            except Exception:
                pass
        return "\n".join(lines)

    def _show_context_menu(self, pos) -> None:
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        self.table.selectRow(index.row())
        item = self.table.item(index.row(), index.column())
        cell_value = item.text() if item is not None else ""

        menu = QMenu(self)
        act_value = QAction("Copy value", self)
        act_value.triggered.connect(lambda: self._copy_value(cell_value))
        act_row = QAction("Copy row", self)
        act_row.triggered.connect(self._copy_row)
        menu.addAction(act_value)
        menu.addAction(act_row)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _copy_value(self, value: str) -> None:
        if self.app is not None and hasattr(self.app, "copy_text"):
            self.app.copy_text(value or "")

    def _copy_row(self) -> None:
        row = self._current_row()
        if not row:
            return
        text = self._row_summary(row)
        if self.app is not None and hasattr(self.app, "copy_text"):
            self.app.copy_text(text)

    def _add_to_notes(self) -> None:
        row = self._current_row()
        if not row:
            return
        block = "\n".join(
            [
                "=== REPOSITORY HIT ===",
                f"Dataset: {row.get('dataset_name') or ''}",
                self._row_summary(row),
                "Source: ViaNyquist repository (local import)",
            ]
        )
        if self.app is not None and hasattr(self.app, "notes_controller"):
            self.app.notes_controller.append_ai_text(block)
