from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QVBoxLayout,
)

from ui.buttons import make_dialog_button
from ui.dialogs import _style_dialog_buttons
from ui.flow_columns import friendly_label


class ColumnPickerDialog(QDialog):
    def __init__(self, current_columns=None, all_columns=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Customize View")
        self.setMinimumWidth(860)
        self.setMinimumHeight(560)

        self.current_columns = list(current_columns or [])
        self.all_columns = list(all_columns or [])

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        self.lbl_title = QLabel("Customize visible columns")
        self.lbl_hint = QLabel("Move columns between lists and reorder them.")
        self.lbl_hint.setObjectName("Muted")

        layout.addWidget(self.lbl_title)
        layout.addWidget(self.lbl_hint)

        main_layout = QHBoxLayout()
        main_layout.setSpacing(12)

        left_layout = QVBoxLayout()
        self.lbl_available = QLabel("Available columns")
        self.list_available = QListWidget()
        left_layout.addWidget(self.lbl_available)
        left_layout.addWidget(self.list_available)

        center_layout = QVBoxLayout()
        center_layout.setSpacing(10)
        self.btn_add = make_dialog_button("Add →")
        self.btn_remove = make_dialog_button("← Remove")
        center_layout.addStretch()
        center_layout.addWidget(self.btn_add)
        center_layout.addWidget(self.btn_remove)
        center_layout.addStretch()

        right_layout = QVBoxLayout()
        self.lbl_selected = QLabel("Selected columns")
        self.list_selected = QListWidget()
        self.list_selected.setDragDropMode(QListWidget.InternalMove)
        right_layout.addWidget(self.lbl_selected)
        right_layout.addWidget(self.list_selected)

        main_layout.addLayout(left_layout, 3)
        main_layout.addLayout(center_layout, 1)
        main_layout.addLayout(right_layout, 3)
        layout.addLayout(main_layout)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        _style_dialog_buttons(self.buttons)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addSpacing(4)
        layout.addWidget(self.buttons)

        self.btn_add.clicked.connect(self._move_to_selected)
        self.btn_remove.clicked.connect(self._move_to_available)
        self.list_available.itemDoubleClicked.connect(lambda _: self._move_to_selected())
        self.list_selected.itemDoubleClicked.connect(lambda _: self._move_to_available())

        self._populate_lists()

    def _make_item(self, key: str) -> QListWidgetItem:
        item = QListWidgetItem(friendly_label(key))
        item.setData(Qt.UserRole, key)
        item.setToolTip(key)
        return item

    def _populate_lists(self) -> None:
        self.list_available.clear()
        self.list_selected.clear()

        selected_set = set(self.current_columns)
        for key in self.current_columns:
            self.list_selected.addItem(self._make_item(key))

        available_keys = [key for key in self.all_columns if key not in selected_set]
        available_keys.sort(key=lambda item: friendly_label(item).lower())
        for key in available_keys:
            self.list_available.addItem(self._make_item(key))

    def _move_to_selected(self) -> None:
        row = self.list_available.currentRow()
        if row < 0:
            return
        item = self.list_available.takeItem(row)
        self.list_selected.addItem(item)

    def _move_to_available(self) -> None:
        row = self.list_selected.currentRow()
        if row < 0:
            return
        item = self.list_selected.takeItem(row)
        self.list_available.addItem(item)

    def get_selected_columns(self) -> list[str] | None:
        selected: list[str] = []
        for index in range(self.list_selected.count()):
            item = self.list_selected.item(index)
            key = item.data(Qt.UserRole)
            if key:
                selected.append(str(key))
        return selected or None
