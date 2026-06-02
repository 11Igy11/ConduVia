from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from core.leaks.db import (
    dataset_layout,
    extra_field_names,
    insert_single_record,
    list_datasets,
    update_record,
)
from core.leaks.schema import DEDICATED_FIELDS, field_label

_DEFAULT_TOKENS = [
    "phone", "email", "oib", "fb_id", "first_name", "last_name",
    "gender", "birthday", "city", "hometown", "employer",
]


def _token_label(token: str) -> str:
    if token in DEDICATED_FIELDS:
        return field_label(token)
    return token


class LeakRecordDialog(QDialog):
    """Add a new record or edit an existing one in the leaks database."""

    def __init__(self, parent=None, *, record: dict | None = None, dataset_id: int | None = None):
        super().__init__(parent)
        self._record = record
        self._editing = record is not None
        self.saved = False
        self.affected_dataset_id: int | None = None

        self.setWindowTitle("Edit record" if self._editing else "New record")
        self.setModal(True)
        self.setMinimumWidth(480)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        # Dataset selector (target set the record belongs to).
        ds_row = QHBoxLayout()
        ds_row.addWidget(QLabel("Dataset:"))
        self.cmb_dataset = QComboBox()
        self._datasets = list(list_datasets())
        for row in self._datasets:
            self.cmb_dataset.addItem(f"{row['name']} ({int(row['record_count'] or 0):,})", int(row["id"]))
        ds_row.addWidget(self.cmb_dataset, 1)
        root.addLayout(ds_row)

        if self._editing:
            # Editing: dataset is fixed.
            rec_ds = int(record.get("dataset_id")) if record.get("dataset_id") else None
            idx = self.cmb_dataset.findData(rec_ds)
            if idx >= 0:
                self.cmb_dataset.setCurrentIndex(idx)
            self.cmb_dataset.setEnabled(False)
        elif dataset_id is not None:
            idx = self.cmb_dataset.findData(int(dataset_id))
            if idx >= 0:
                self.cmb_dataset.setCurrentIndex(idx)

        # Scrollable field form.
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.form_host = QWidget()
        self.form = QFormLayout(self.form_host)
        self.form.setLabelAlignment(Qt.AlignRight)
        self.scroll.setWidget(self.form_host)
        root.addWidget(self.scroll, 1)

        self._inputs: dict[str, QLineEdit] = {}
        self.lbl_status = QLabel("")
        self.lbl_status.setObjectName("Muted")
        self.lbl_status.setWordWrap(True)
        root.addWidget(self.lbl_status)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.btn_save = QPushButton("Save")
        self.btn_cancel = QPushButton("Cancel")
        self.btn_save.setObjectName("CompactButton")
        self.btn_cancel.setObjectName("CompactButton")
        self.btn_save.clicked.connect(self._save)
        self.btn_cancel.clicked.connect(self.reject)
        buttons.addWidget(self.btn_save)
        buttons.addWidget(self.btn_cancel)
        root.addLayout(buttons)

        if not self._editing:
            self.cmb_dataset.currentIndexChanged.connect(lambda *_: self._rebuild_fields())
        self._rebuild_fields()
        self._fit_to_screen()

    def _fit_to_screen(self) -> None:
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is None:
            return
        avail = screen.availableGeometry()
        height = min(640, avail.height() - 80)
        self.resize(max(self.minimumWidth(), 520), max(360, height))
        frame = self.frameGeometry()
        frame.moveCenter(avail.center())
        self.move(frame.topLeft())

    def _current_dataset_id(self) -> int | None:
        return self.cmb_dataset.currentData()

    def _tokens_for(self, dataset_id: int | None) -> list[str]:
        tokens: list[str] = []
        if dataset_id is not None:
            tokens = list(dataset_layout(dataset_id))
            if not tokens:
                seen = set()
                for token in _DEFAULT_TOKENS:
                    tokens.append(token)
                    seen.add(token)
                for key in extra_field_names(dataset_id):
                    if key not in seen:
                        tokens.append(key)
                        seen.add(key)
        if not tokens:
            tokens = list(_DEFAULT_TOKENS)
        return tokens

    def _record_value(self, token: str) -> str:
        if not self._record:
            return ""
        if token in DEDICATED_FIELDS:
            return str(self._record.get(token) or "")
        raw = self._record.get("extra")
        if raw:
            try:
                return str(json.loads(raw).get(token, "") or "")
            except Exception:
                return ""
        return ""

    def _rebuild_fields(self) -> None:
        while self.form.rowCount():
            self.form.removeRow(0)
        self._inputs = {}
        tokens = self._tokens_for(self._current_dataset_id())
        for token in tokens:
            edit = QLineEdit()
            edit.setText(self._record_value(token))
            self._inputs[token] = edit
            self.form.addRow(_token_label(token) + ":", edit)

    def _save(self) -> None:
        dataset_id = self._current_dataset_id()
        if dataset_id is None:
            self.lbl_status.setText("Choose a dataset first.")
            return
        values = {token: edit.text() for token, edit in self._inputs.items()}
        if not any(v.strip() for v in values.values()):
            self.lbl_status.setText("Fill in at least one field.")
            return

        oib_value = str(values.get("oib") or "").strip()
        if oib_value:
            from core.osint.normalize import is_valid_oib

            if not is_valid_oib(oib_value):
                self.lbl_status.setText(
                    "Invalid OIB: must be 11 digits with a valid checksum."
                )
                return

        try:
            if self._editing:
                update_record(int(self._record["id"]), values)
            else:
                new_id = insert_single_record(int(dataset_id), values)
                if new_id is None:
                    self.lbl_status.setText("A matching record already exists (duplicate phone + Facebook ID).")
                    return
        except Exception as exc:
            self.lbl_status.setText(f"Save failed: {exc}")
            return

        self.saved = True
        self.affected_dataset_id = int(dataset_id)
        self.accept()
