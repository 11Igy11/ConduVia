from __future__ import annotations

import re
from pathlib import Path

from PySide6.QtCore import Qt, QThread
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from core.leaks.detect import detect_delimiter, split_rows
from core.leaks.encoding import SUPPORTED_ENCODINGS
from core.leaks.readers import guess_encoding, is_supported, sample_lines
from core.leaks.schema import DEDICATED_FIELDS
from ui.leaks_worker import LeakImportWorker

_DELIMITERS = [
    (":", "colon  :"),
    (",", "comma  ,"),
    (";", "semicolon  ;"),
    ("\t", "tab"),
    ("|", "pipe  |"),
    (" ", "space"),
    (";;", "double semicolon  ;;"),
    ("::", "double colon  ::"),
    ("^", "caret  ^"),
    ("~", "tilde  ~"),
    ("#", "hash  #"),
    ("\\", "backslash  \\"),
]
_PREVIEW_ROWS = 25


def _normalize_field_name(text: str) -> str:
    """Turn a free-text column name into a storage token (blank = ignore)."""
    token = text.strip().lower().replace(" ", "_").replace("-", "_")
    return re.sub(r"[^a-z0-9_]", "", token)


class LeaksImportDialog(QDialog):
    def __init__(self, parent=None, *, path: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Import dataset")
        self.setMinimumSize(780, 480)
        self.setModal(True)

        self._path = path
        self._thread: QThread | None = None
        self._worker: LeakImportWorker | None = None
        self.imported_dataset_id: int | None = None

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(8)

        # --- File row ---
        file_row = QHBoxLayout()
        self.edit_path = QLineEdit(path)
        self.edit_path.setPlaceholderText("Choose a .txt / .csv / .tsv / .docx file…")
        btn_browse = QPushButton("Browse…")
        btn_browse.setObjectName("CompactButton")
        btn_browse.clicked.connect(self._browse)
        file_row.addWidget(QLabel("File:"))
        file_row.addWidget(self.edit_path, 1)
        file_row.addWidget(btn_browse)
        root.addLayout(file_row)

        # --- Parse options row ---
        opts = QHBoxLayout()
        self.cmb_encoding = QComboBox()
        for enc in SUPPORTED_ENCODINGS:
            self.cmb_encoding.addItem(enc, enc)
        self.cmb_delimiter = QComboBox()
        for value, label in _DELIMITERS:
            self.cmb_delimiter.addItem(label, value)
        self.cmb_encoding.currentIndexChanged.connect(self._reload_preview)
        self.cmb_delimiter.currentIndexChanged.connect(self._reload_preview)
        opts.addWidget(QLabel("Encoding:"))
        opts.addWidget(self.cmb_encoding)
        opts.addWidget(QLabel("Delimiter:"))
        opts.addWidget(self.cmb_delimiter)
        opts.addStretch(1)
        root.addLayout(opts)

        # --- Column mapping (reorderable list) ---
        root.addWidget(QLabel(
            "Columns are listed in display order. Use ▲ ▼ to reorder, and type "
            "the name you want for each column (blank = ignore)."
        ))
        hint = QLabel(
            "Recognised names enable normalization & search: "
            + ", ".join(DEDICATED_FIELDS)
            + ". Any other name is stored as-is."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        root.addWidget(hint)

        self.map_scroll = QScrollArea()
        self.map_scroll.setWidgetResizable(True)
        self.map_scroll.setMinimumHeight(200)
        self.map_host = QWidget()
        self.map_layout = QVBoxLayout(self.map_host)
        self.map_layout.setContentsMargins(4, 4, 4, 4)
        self.map_layout.setSpacing(6)
        self.map_scroll.setWidget(self.map_host)
        root.addWidget(self.map_scroll, 1)

        self._entries: list[dict] = []
        self._col_count = 0

        # --- Dataset meta ---
        meta = QHBoxLayout()
        self.edit_name = QLineEdit()
        self.edit_name.setPlaceholderText("Dataset name (e.g. Facebook 2019 HR)")
        self.edit_note = QLineEdit()
        self.edit_note.setPlaceholderText("Note / source (optional)")
        meta.addWidget(QLabel("Name:"))
        meta.addWidget(self.edit_name, 1)
        meta.addWidget(QLabel("Source:"))
        meta.addWidget(self.edit_note, 1)
        root.addLayout(meta)

        # --- Progress + buttons ---
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        root.addWidget(self.progress)

        self.lbl_status = QLabel("")
        self.lbl_status.setObjectName("ProfileSubtitle")
        self.lbl_status.setWordWrap(True)
        root.addWidget(self.lbl_status)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.btn_import = QPushButton("Import")
        self.btn_cancel = QPushButton("Close")
        self.btn_import.setObjectName("CompactButton")
        self.btn_cancel.setObjectName("CompactButton")
        self.btn_import.clicked.connect(self._start_import)
        self.btn_cancel.clicked.connect(self.reject)
        buttons.addWidget(self.btn_import)
        buttons.addWidget(self.btn_cancel)
        root.addLayout(buttons)

        if path:
            self._reload_preview()
        self._fit_to_screen()

    def _fit_to_screen(self) -> None:
        screen = self.screen() or QGuiApplication.primaryScreen()
        if screen is None:
            self.resize(940, 700)
            return
        avail = screen.availableGeometry()
        # Hard cap so the window can never grow past the screen (e.g. when the
        # progress bar appears during import and pushes the buttons off-screen).
        self.setMaximumHeight(avail.height() - 48)
        self.setMaximumWidth(avail.width() - 40)
        width = min(940, avail.width() - 60)
        height = min(720, avail.height() - 80)
        self.resize(max(self.minimumWidth(), width), max(self.minimumHeight(), height))
        frame = self.frameGeometry()
        frame.moveCenter(avail.center())
        self.move(frame.topLeft())

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._fit_to_screen()

    # ------------------------------------------------------------------ file
    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Choose data file",
            "",
            "Data files (*.txt *.csv *.tsv *.docx);;All files (*.*)",
        )
        if not path:
            return
        self.edit_path.setText(path)
        self._path = path
        if not self.edit_name.text().strip():
            self.edit_name.setText(Path(path).stem)
        guessed = guess_encoding(path)
        idx = self.cmb_encoding.findData(guessed)
        if idx >= 0:
            self.cmb_encoding.setCurrentIndex(idx)
        self._auto_delimiter()
        self._reload_preview()

    def _auto_delimiter(self) -> None:
        path = self.edit_path.text().strip()
        if not path or not Path(path).exists():
            return
        encoding = str(self.cmb_encoding.currentData() or "utf-8")
        lines = sample_lines(path, encoding, _PREVIEW_ROWS)
        delim = detect_delimiter(lines)
        idx = self.cmb_delimiter.findData(delim)
        if idx >= 0:
            self.cmb_delimiter.setCurrentIndex(idx)

    # --------------------------------------------------------------- preview
    def _current_sample_rows(self) -> list[list[str]]:
        path = self.edit_path.text().strip()
        if not path or not Path(path).exists():
            return []
        encoding = str(self.cmb_encoding.currentData() or "utf-8")
        delimiter = str(self.cmb_delimiter.currentData() or ":")
        lines = sample_lines(path, encoding, _PREVIEW_ROWS)
        return split_rows(lines, delimiter)

    def _reload_preview(self, *_args) -> None:
        rows = self._current_sample_rows()
        # Preserve names already typed for the same source column.
        previous = {e["src"]: e["edit"].text() for e in self._entries}
        self._entries = []
        if not rows:
            self._render_mapping()
            return

        self._col_count = max(len(r) for r in rows)
        for index in range(self._col_count):
            samples = [r[index] for r in rows if index < len(r) and r[index].strip()][:3]
            sample = ", ".join(samples)
            if len(sample) > 60:
                sample = sample[:57] + "…"
            edit = QLineEdit()
            edit.setPlaceholderText("type column name… (blank = ignore)")
            edit.setMinimumWidth(240)
            edit.setMaximumWidth(300)
            if index in previous:
                edit.setText(previous[index])
            self._entries.append({"src": index, "sample": sample, "edit": edit})
        self._render_mapping()

    def _render_mapping(self) -> None:
        # Detach the persistent name editors so they survive row deletion.
        for entry in self._entries:
            entry["edit"].setParent(None)
        while self.map_layout.count():
            item = self.map_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        for position, entry in enumerate(self._entries):
            self.map_layout.addWidget(self._make_row(position, entry))
        self.map_layout.addStretch(1)

    def _make_row(self, position: int, entry: dict) -> QWidget:
        row = QWidget()
        h = QHBoxLayout(row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(6)

        up = QToolButton()
        up.setArrowType(Qt.UpArrow)
        down = QToolButton()
        down.setArrowType(Qt.DownArrow)
        for btn in (up, down):
            btn.setObjectName("CompactToolButton")
            btn.setFixedSize(26, 26)
            btn.setCursor(Qt.PointingHandCursor)
        up.setEnabled(position > 0)
        down.setEnabled(position < len(self._entries) - 1)
        up.clicked.connect(lambda _=False, e=entry: self._move_entry(e, -1))
        down.clicked.connect(lambda _=False, e=entry: self._move_entry(e, +1))

        col_lbl = QLabel(f"Col {entry['src'] + 1}")
        col_lbl.setFixedWidth(48)
        sample = QLabel(entry["sample"] or "—")
        sample.setObjectName("Muted")
        sample.setTextInteractionFlags(Qt.TextSelectableByMouse)

        h.addWidget(up)
        h.addWidget(down)
        h.addWidget(col_lbl)
        h.addWidget(sample, 1)
        h.addWidget(entry["edit"])
        return row

    def _move_entry(self, entry: dict, delta: int) -> None:
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
            self._render_mapping()

    def _collect_columns(self) -> list[str]:
        """Positional mapping (by source column index) used for parsing."""
        columns = ["skip"] * self._col_count
        for entry in self._entries:
            token = _normalize_field_name(entry["edit"].text())
            if token:
                columns[entry["src"]] = token
        return columns

    def _display_columns(self) -> list[str]:
        """Column names in the order the user arranged them (for the viewer)."""
        names = []
        for entry in self._entries:
            token = _normalize_field_name(entry["edit"].text())
            if token:
                names.append(token)
        return names

    # ---------------------------------------------------------------- import
    def _start_import(self) -> None:
        path = self.edit_path.text().strip()
        if not path or not Path(path).exists():
            self.lbl_status.setText("Choose an existing file.")
            return
        if not is_supported(path):
            self.lbl_status.setText("Unsupported format. Use .txt / .csv / .tsv / .docx.")
            return
        name = self.edit_name.text().strip() or Path(path).stem
        columns = self._collect_columns()
        if not any(c != "skip" for c in columns):
            self.lbl_status.setText("Map at least one column.")
            return

        options = {
            "path": path,
            "name": name,
            "delimiter": str(self.cmb_delimiter.currentData() or ":"),
            "encoding": str(self.cmb_encoding.currentData() or "utf-8"),
            "columns": columns,
            "display_columns": self._display_columns(),
            "has_header": False,
            "source_note": self.edit_note.text().strip(),
            "keep_raw": True,
        }

        self.btn_import.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.lbl_status.setText("Import in progress…")

        self._thread = QThread(self)
        self._worker = LeakImportWorker(options)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._thread.start()

    def _on_progress(self, read: int, inserted: int) -> None:
        self.lbl_status.setText(f"Read {read:,} rows…")

    def _on_finished(self, summary: object) -> None:
        self._teardown_thread()
        self.progress.setVisible(False)
        self.btn_import.setEnabled(True)
        data = summary if isinstance(summary, dict) else {}
        self.imported_dataset_id = data.get("dataset_id") or None
        inserted = data.get("inserted", 0)
        duplicates = data.get("duplicates", 0)
        self.lbl_status.setText(
            f"Done: inserted {inserted:,} records, skipped {duplicates:,} duplicates."
        )
        self.accept()

    def _on_error(self, message: str) -> None:
        self._teardown_thread()
        self.progress.setVisible(False)
        self.btn_import.setEnabled(True)
        self.lbl_status.setText(f"Import error: {message}")

    def _teardown_thread(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(2000)
            self._thread = None
        self._worker = None

    def reject(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
        self._teardown_thread()
        super().reject()
