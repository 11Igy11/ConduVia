from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QImage, QTextCharFormat, QTextCursor, QTextImageFormat
from PySide6.QtWidgets import (
    QColorDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QGridLayout,
    QComboBox,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


def _looks_like_html(text: str) -> bool:
    value = (text or "").lstrip().lower()
    return value.startswith("<!doctype html") or value.startswith("<html") or "<body" in value[:500]


class NotesPage(QWidget):
    """Project notes page with a small rich-text editor toolbar."""

    MAX_IMAGE_WIDTH = 760
    MAX_IMAGE_HEIGHT = 460

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self._connect_signals()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        title_row = QHBoxLayout()
        self.title = QLabel("Project notes")
        self.title.setObjectName("SectionTitle")
        self.status = QLabel("Autosave")
        self.status.setObjectName("Muted")
        title_row.addWidget(self.title)
        title_row.addStretch()
        title_row.addWidget(self.status)
        root.addLayout(title_row)

        body = QHBoxLayout()
        body.setSpacing(12)

        self.font_box = QComboBox()
        self.font_box.addItems([
            "Segoe UI",
            "Arial",
            "Calibri",
            "Cambria",
            "Candara",
            "Consolas",
            "Courier New",
            "Georgia",
            "Tahoma",
            "Times New Roman",
            "Trebuchet MS",
            "Verdana",
        ])
        self.font_box.setMinimumWidth(160)
        self.size_box = QSpinBox()
        self.size_box.setRange(8, 36)
        self.size_box.setValue(11)
        self.size_box.setSingleStep(1)
        self.size_box.setFixedWidth(120)

        self.btn_bold = self._tool_button("B", "Bold")
        self.btn_bold.setCheckable(True)
        self.btn_italic = self._tool_button("I", "Italic")
        self.btn_italic.setCheckable(True)
        self.btn_underline = self._tool_button("U", "Underline")
        self.btn_underline.setCheckable(True)
        self.btn_color = self._tool_button("●", "Text color")
        self.btn_color.setObjectName("NotesColorButton")
        self.btn_align_left = self._tool_button("☰", "Align left")
        self.btn_align_center = self._tool_button("≡", "Align center")
        self.btn_align_right = self._tool_button("☷", "Align right")
        self.btn_align_justify = self._tool_button("▤", "Justify")
        self.btn_insert_image = self._tool_button("Image", "Insert picture / screenshot")
        self.btn_insert_chart = self._tool_button("Chart", "Insert chart from project profile")
        self.btn_export_word = self._tool_button("Word", "Export notes to Word document")

        self.editor = QTextEdit()
        self.editor.setAcceptRichText(True)
        self.editor.setPlaceholderText("Write case notes here... (autosave)")

        tools = QFrame()
        tools.setObjectName("NotesEditorPanel")
        tools.setMinimumWidth(230)
        tools.setMaximumWidth(270)
        tools_layout = QVBoxLayout(tools)
        tools_layout.setContentsMargins(10, 10, 10, 10)
        tools_layout.setSpacing(8)

        tools_title = QLabel("Editor")
        tools_title.setObjectName("SectionTitle")
        tools_layout.addWidget(tools_title)

        tools_layout.addWidget(self._panel_label("Type"))
        tools_layout.addWidget(self.font_box)
        tools_layout.addWidget(self.size_box)

        style_grid = QGridLayout()
        style_grid.setSpacing(6)
        style_grid.addWidget(self.btn_bold, 0, 0)
        style_grid.addWidget(self.btn_italic, 0, 1)
        style_grid.addWidget(self.btn_underline, 0, 2)
        style_grid.addWidget(self.btn_color, 0, 3)
        tools_layout.addWidget(self._panel_label("Style"))
        tools_layout.addLayout(style_grid)

        align_grid = QGridLayout()
        align_grid.setSpacing(6)
        align_grid.addWidget(self.btn_align_left, 0, 0)
        align_grid.addWidget(self.btn_align_center, 0, 1)
        align_grid.addWidget(self.btn_align_right, 0, 2)
        align_grid.addWidget(self.btn_align_justify, 0, 3)
        tools_layout.addWidget(self._panel_label("Align"))
        tools_layout.addLayout(align_grid)

        tools_layout.addWidget(self._panel_label("Insert"))
        image_note = QLabel(f"Images are inserted up to {self.MAX_IMAGE_WIDTH} x {self.MAX_IMAGE_HEIGHT}px.")
        image_note.setObjectName("Muted")
        image_note.setWordWrap(True)
        tools_layout.addWidget(image_note)
        tools_layout.addWidget(self.btn_insert_image)
        tools_layout.addWidget(self.btn_insert_chart)

        tools_layout.addWidget(self._panel_label("Export"))
        tools_layout.addWidget(self.btn_export_word)
        tools_layout.addStretch()

        body.addWidget(self.editor, 1)
        body.addWidget(tools)
        root.addLayout(body, 1)

    def _connect_signals(self) -> None:
        self.font_box.currentTextChanged.connect(lambda family: self._merge_format(fontFamily=family))
        self.size_box.valueChanged.connect(lambda size: self._merge_format(fontPointSize=float(size)))
        self.btn_bold.toggled.connect(lambda checked: self._merge_format(fontWeight=700 if checked else 400))
        self.btn_italic.toggled.connect(lambda checked: self._merge_format(fontItalic=checked))
        self.btn_underline.toggled.connect(lambda checked: self._merge_format(fontUnderline=checked))
        self.btn_color.clicked.connect(self._choose_color)
        self.btn_align_left.clicked.connect(lambda: self.editor.setAlignment(Qt.AlignLeft))
        self.btn_align_center.clicked.connect(lambda: self.editor.setAlignment(Qt.AlignCenter))
        self.btn_align_right.clicked.connect(lambda: self.editor.setAlignment(Qt.AlignRight))
        self.btn_align_justify.clicked.connect(lambda: self.editor.setAlignment(Qt.AlignJustify))
        self.btn_insert_image.clicked.connect(self._insert_image)
        self.editor.cursorPositionChanged.connect(self._sync_toolbar)

    def set_project_active(self, active: bool) -> None:
        self.editor.setEnabled(active)
        for widget in (
            self.font_box,
            self.size_box,
            self.btn_bold,
            self.btn_italic,
            self.btn_underline,
            self.btn_color,
            self.btn_align_left,
            self.btn_align_center,
            self.btn_align_right,
            self.btn_align_justify,
            self.btn_insert_image,
            self.btn_insert_chart,
            self.btn_export_word,
        ):
            widget.setEnabled(active)
        if active:
            self.editor.setPlaceholderText("Write case notes here... (autosave)")
            self.status.setText("Autosave")
        else:
            self.editor.setPlaceholderText("Select an active project to use Notes.")
            self.status.setText("No active project")

    def set_notes(self, text: str) -> None:
        if _looks_like_html(text):
            self.editor.setHtml(text or "")
        else:
            self.editor.setPlainText(text or "")
        self._sync_toolbar()

    def notes_text(self) -> str:
        return self.editor.toHtml()

    def notes_plain_text(self) -> str:
        return self.editor.toPlainText() or ""

    def append_block(self, block: str) -> None:
        block = (block or "").strip()
        if not block:
            return

        cursor = self.editor.textCursor()
        cursor.movePosition(QTextCursor.End)
        if self.editor.toPlainText().strip():
            cursor.insertBlock()
            cursor.insertBlock()
        cursor.insertText(block)
        cursor.insertBlock()
        self.editor.setTextCursor(cursor)

    def _tool_button(self, text: str, tooltip: str) -> QPushButton:
        button = QPushButton(text)
        button.setToolTip(tooltip)
        button.setObjectName("NotesToolButton")
        button.setMinimumHeight(24)
        return button

    def _panel_label(self, text: str) -> QLabel:
        label = QLabel(text.upper())
        label.setObjectName("NotesPanelLabel")
        return label

    def _merge_format(self, **kwargs) -> None:
        fmt = QTextCharFormat()
        for key, value in kwargs.items():
            if key == "fontFamily":
                fmt.setFontFamily(str(value))
            elif key == "fontPointSize":
                fmt.setFontPointSize(float(value))
            elif key == "fontWeight":
                fmt.setFontWeight(int(value))
            elif key == "fontItalic":
                fmt.setFontItalic(bool(value))
            elif key == "fontUnderline":
                fmt.setFontUnderline(bool(value))
            elif key == "foreground":
                fmt.setForeground(value)

        cursor = self.editor.textCursor()
        if not cursor.hasSelection():
            cursor.select(QTextCursor.WordUnderCursor)
        cursor.mergeCharFormat(fmt)
        self.editor.mergeCurrentCharFormat(fmt)
        self.editor.setFocus()

    def _choose_color(self) -> None:
        color = QColorDialog.getColor(QColor("#f9fafb"), self, "Text color")
        if color.isValid():
            self._merge_format(foreground=color)

    def _insert_image(self) -> None:
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Insert image",
            "",
            "Images (*.png *.jpg *.jpeg *.bmp *.gif)",
        )
        if not file_path:
            return
        self.insert_image_file(file_path)

    def insert_image_file(self, file_path: str) -> None:
        path = Path(file_path)
        image = QImage(str(path))
        if image.isNull():
            return
        width = image.width()
        height = image.height()
        if width > self.MAX_IMAGE_WIDTH or height > self.MAX_IMAGE_HEIGHT:
            scale = min(self.MAX_IMAGE_WIDTH / max(width, 1), self.MAX_IMAGE_HEIGHT / max(height, 1))
            width = max(1, int(width * scale))
            height = max(1, int(height * scale))

        image_format = QTextImageFormat()
        image_format.setName(str(path))
        image_format.setWidth(width)
        image_format.setHeight(height)

        cursor = self.editor.textCursor()
        cursor.insertImage(image_format)
        self.editor.setTextCursor(cursor)
        self.editor.setFocus()

    def _sync_toolbar(self) -> None:
        fmt = self.editor.currentCharFormat()
        font = fmt.font()
        self.font_box.blockSignals(True)
        self.size_box.blockSignals(True)
        self.btn_bold.blockSignals(True)
        self.btn_italic.blockSignals(True)
        self.btn_underline.blockSignals(True)

        if font.family():
            idx = self.font_box.findText(font.family())
            if idx >= 0:
                self.font_box.setCurrentIndex(idx)
        if font.pointSize() > 0:
            self.size_box.setValue(font.pointSize())
        self.btn_bold.setChecked(font.bold())
        self.btn_italic.setChecked(font.italic())
        self.btn_underline.setChecked(font.underline())

        self.font_box.blockSignals(False)
        self.size_box.blockSignals(False)
        self.btn_bold.blockSignals(False)
        self.btn_italic.blockSignals(False)
        self.btn_underline.blockSignals(False)
