from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core.leaks.db import create_dataset, dataset_layout, update_dataset
from core.leaks.schema import DEDICATED_FIELDS
from ui.leaks_import_dialog import _normalize_field_name


_ROW_H = 40
_INPUT_H = 36
_FIELD_STYLE = "padding: 4px 8px;"


class CreateDatasetDialog(QDialog):
    """Manually define a dataset's columns (create) or edit an existing one."""

    def __init__(self, parent=None, *, dataset=None):
        super().__init__(parent)
        self._dataset = dataset
        self._editing = dataset is not None
        self._dataset_id = int(dataset["id"]) if self._editing else None
        self.created_dataset_id: int | None = None
        self.saved = False

        self.setWindowTitle("Edit dataset" if self._editing else "Create dataset")
        self.setModal(True)
        self.setMinimumSize(580, 500)

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(6)

        meta = QHBoxLayout()
        meta.setSpacing(8)
        meta.addWidget(QLabel("Name:"))
        self.edit_name = QLineEdit()
        self.edit_name.setPlaceholderText("Dataset name")
        self.edit_name.setStyleSheet(_FIELD_STYLE)
        self.edit_name.setFixedHeight(_INPUT_H)
        meta.addWidget(self.edit_name, 1)
        meta.addWidget(QLabel("Source:"))
        self.edit_note = QLineEdit()
        self.edit_note.setPlaceholderText("Note / source (optional)")
        self.edit_note.setStyleSheet(_FIELD_STYLE)
        self.edit_note.setFixedHeight(_INPUT_H)
        meta.addWidget(self.edit_note, 1)
        root.addLayout(meta)

        root.addWidget(QLabel("Define columns (use ▲ ▼ to reorder, ✕ to remove):"))
        hint = QLabel(
            "Recognised names enable normalization & search: "
            + ", ".join(DEDICATED_FIELDS)
            + ". Any other name is stored as-is."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        root.addWidget(hint)
        if self._editing:
            rename_hint = QLabel(
                "Renaming a column moves existing data to the new name. "
                "Removing a column only hides it (data is kept)."
            )
            rename_hint.setObjectName("Muted")
            rename_hint.setWordWrap(True)
            root.addWidget(rename_hint)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setMinimumHeight(260)
        self.host = QWidget()
        self.col_layout = QVBoxLayout(self.host)
        self.col_layout.setContentsMargins(4, 4, 4, 4)
        self.col_layout.setSpacing(6)
        self.scroll.setWidget(self.host)
        root.addWidget(self.scroll, 1)

        self._entries: list[dict] = []

        self.lbl_status = QLabel("")
        self.lbl_status.setObjectName("Muted")
        self.lbl_status.setWordWrap(True)
        self.lbl_status.hide()
        root.addWidget(self.lbl_status)

        buttons = QHBoxLayout()
        buttons.setSpacing(6)
        self.btn_add_col = QPushButton("+ Add column")
        self.btn_add_col.setObjectName("CompactButton")
        self.btn_add_col.setFixedHeight(28)
        self.btn_add_col.clicked.connect(lambda: self._add_column(""))
        buttons.addWidget(self.btn_add_col)
        buttons.addStretch(1)
        self.btn_create = QPushButton("Save" if self._editing else "Create")
        self.btn_cancel = QPushButton("Cancel")
        for b in (self.btn_create, self.btn_cancel):
            b.setObjectName("CompactButton")
            b.setFixedHeight(28)
        self.btn_create.clicked.connect(self._save)
        self.btn_cancel.clicked.connect(self.reject)
        buttons.addWidget(self.btn_create)
        buttons.addWidget(self.btn_cancel)
        root.addLayout(buttons)

        if self._editing:
            self.edit_name.setText(str(dataset["name"] or ""))
            try:
                self.edit_note.setText(str(dataset["source_note"] or ""))
            except Exception:
                pass
            layout = dataset_layout(self._dataset_id)
            if not layout:
                layout = ["phone", "first_name", "last_name"]
            for token in layout:
                self._add_column(token, orig=token, render=False)
        else:
            for name in ("phone", "first_name", "last_name"):
                self._add_column(name, render=False)
        self._render()
        self._fit_to_screen()

    def _fit_to_screen(self) -> None:
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is None:
            self.resize(640, 600)
            return
        avail = screen.availableGeometry()
        width = min(660, avail.width() - 40)
        height = min(620, avail.height() - 40)
        self.resize(max(self.minimumWidth(), width), max(self.minimumHeight(), height))
        frame = self.frameGeometry()
        frame.moveCenter(avail.center())
        self.move(frame.topLeft())

    def _add_column(self, name: str, *, orig: str | None = None, render: bool = True) -> None:
        edit = QLineEdit()
        edit.setPlaceholderText("column name… (e.g. phone, employer, my_field)")
        edit.setStyleSheet(_FIELD_STYLE)
        edit.setFixedHeight(_INPUT_H)
        edit.setText(name)
        self._entries.append({"edit": edit, "orig": orig})
        if render:
            self._render()
            QTimer.singleShot(0, self._scroll_to_bottom)

    def _scroll_to_bottom(self) -> None:
        bar = self.scroll.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _render(self) -> None:
        for entry in self._entries:
            entry["edit"].setParent(None)
        while self.col_layout.count():
            item = self.col_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        for position, entry in enumerate(self._entries):
            self.col_layout.addWidget(self._make_row(position, entry))
        self.col_layout.addStretch(1)

    def _make_row(self, position: int, entry: dict) -> QWidget:
        row = QWidget()
        row.setFixedHeight(_ROW_H)
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(6)

        up = QToolButton()
        up.setArrowType(Qt.UpArrow)
        down = QToolButton()
        down.setArrowType(Qt.DownArrow)
        remove = QToolButton()
        remove.setText("✕")
        for btn in (up, down, remove):
            btn.setObjectName("CompactToolButton")
            btn.setFixedSize(28, 28)
            btn.setCursor(Qt.PointingHandCursor)
        up.setEnabled(position > 0)
        down.setEnabled(position < len(self._entries) - 1)
        up.clicked.connect(lambda _=False, e=entry: self._move(e, -1))
        down.clicked.connect(lambda _=False, e=entry: self._move(e, +1))
        remove.clicked.connect(lambda _=False, e=entry: self._remove(e))

        entry["edit"].setFixedHeight(_INPUT_H)
        num = QLabel(f"{position + 1}.")
        num.setFixedWidth(22)
        h.addWidget(num)
        h.addWidget(up)
        h.addWidget(down)
        h.addWidget(entry["edit"], 1)
        h.addWidget(remove)
        return row

    def _move(self, entry: dict, delta: int) -> None:
        try:
            index = self._entries.index(entry)
        except ValueError:
            return
        new_index = index + delta
        if 0 <= new_index < len(self._entries):
            self._entries[index], self._entries[new_index] = (
                self._entries[new_index],
                self._entries[index],
            )
            self._render()

    def _remove(self, entry: dict) -> None:
        if entry in self._entries:
            entry["edit"].setParent(None)
            self._entries.remove(entry)
            self._render()

    def _collect(self) -> tuple[list[str], dict[str, str]] | None:
        """Return (columns, rename_map) or None on validation error."""
        columns: list[str] = []
        seen: set[str] = set()
        rename_map: dict[str, str] = {}
        for entry in self._entries:
            token = _normalize_field_name(entry["edit"].text())
            if not token or token in seen:
                continue
            columns.append(token)
            seen.add(token)
            orig = entry.get("orig")
            if orig and orig != token:
                rename_map[orig] = token
        if not columns:
            self._set_status("Define at least one column.")
            return None
        return columns, rename_map

    def _set_status(self, text: str) -> None:
        self.lbl_status.setText(text)
        self.lbl_status.setVisible(bool(text))

    def _save(self) -> None:
        name = self.edit_name.text().strip()
        if not name:
            self._set_status("Enter a dataset name.")
            return
        collected = self._collect()
        if collected is None:
            return
        columns, rename_map = collected
        try:
            if self._editing:
                update_dataset(
                    int(self._dataset_id),
                    name=name,
                    source_note=self.edit_note.text().strip(),
                    columns=columns,
                    rename_map=rename_map,
                )
                self.created_dataset_id = int(self._dataset_id)
            else:
                self.created_dataset_id = create_dataset(
                    name, source_note=self.edit_note.text().strip(), columns=columns
                )
        except Exception as exc:
            self._set_status(("Save failed: " if self._editing else "Create failed: ") + str(exc))
            return
        self.saved = True
        self.accept()
