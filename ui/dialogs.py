from PySide6.QtCore import QEvent, QObject, Qt, QDate, QSize, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QAbstractScrollArea,
    QCalendarWidget,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPushButton,
    QLabel,
    QComboBox,
    QPlainTextEdit,
    QFileDialog,
    QMessageBox,
    QScrollArea,
    QSizePolicy,
    QTableView,
    QVBoxLayout,
    QWidget,
)
from typing import Any, Callable

from core.project_identity import identifier_values_for_editor, is_valid_oib
from core.evidence_policy import format_period_day_label
from core.period_gaps import missing_days_in_range, normalize_period_day
from shiboken6 import isValid

from ui.font_utils import ensure_dialog_fonts, ensure_widget_point_font
from ui.buttons import make_dialog_button, style_action_button, style_dialog_button, style_inline_picker_button
from ui.ui_metrics import (
    DIALOG_BUTTON_HEIGHT,
    DIALOG_BUTTON_MIN_WIDTH,
    DIALOG_DEFAULT_WIDTH,
    DIALOG_FIELD_HEIGHT,
    DIALOG_FORM_WIDTH,
    DIALOG_MARGINS,
    DIALOG_SPACING,
    FINDING_DIALOG_HEIGHT,
    PROJECT_DIALOG_HEIGHT,
    PROJECT_DIALOG_WIDTH,
)


def _apply_dialog_layout(layout: QVBoxLayout) -> None:
    layout.setContentsMargins(*DIALOG_MARGINS)
    layout.setSpacing(DIALOG_SPACING)


def _fit_compact_dialog(dlg: QDialog, width: int) -> None:
    dlg.adjustSize()
    screen = dlg.screen().availableGeometry() if dlg.screen() else None
    max_w = max(width, 300)
    if screen:
        max_w = min(max_w, int(screen.width() * 0.92))
    w = max(dlg.sizeHint().width(), min(width, max_w))
    w = min(w, max_w)
    h = dlg.sizeHint().height()
    if screen:
        h = min(h, int(screen.height() * 0.82))
    dlg.setFixedSize(w, h)


def _style_dialog_button(button: QPushButton, *, destructive: bool = False) -> None:
    style_dialog_button(button, destructive=destructive)


def _style_choice_button(button: QPushButton) -> None:
    style_dialog_button(button)


def _style_inline_dialog_button(button: QPushButton) -> None:
    style_inline_picker_button(button)


def _add_choice_dialog_footer(layout: QVBoxLayout, btn_row: QHBoxLayout) -> None:
    separator = QFrame()
    separator.setFrameShape(QFrame.Shape.HLine)
    separator.setFrameShadow(QFrame.Shadow.Plain)
    separator.setObjectName("DialogChoiceSeparator")
    layout.addSpacing(10)
    layout.addWidget(separator)
    layout.addSpacing(8)
    layout.addLayout(btn_row)


def period_date_edit(value: QDate, minimum: QDate, maximum: QDate) -> QDateEdit:
    """Date picker with a sized calendar popup (matches import evidence dialog)."""
    edit = QDateEdit(value)
    edit.setCalendarPopup(True)
    edit.setDisplayFormat("dd.MM.yyyy")
    edit.setMinimumDate(minimum)
    edit.setMaximumDate(maximum)
    edit.setFixedWidth(220)
    calendar = QCalendarWidget(edit)
    calendar.setGridVisible(True)
    calendar.setFixedSize(430, 340)
    calendar.setVerticalHeaderFormat(QCalendarWidget.NoVerticalHeader)
    calendar.setHorizontalHeaderFormat(QCalendarWidget.ShortDayNames)
    ensure_widget_point_font(edit)
    ensure_widget_point_font(calendar)
    for child in calendar.findChildren(QWidget):
        ensure_widget_point_font(child)
    edit.setCalendarWidget(calendar)
    return edit


def _style_dialog_buttons(buttons: QDialogButtonBox, *, destructive_ok: bool = False) -> None:
    for button in buttons.buttons():
        is_ok = buttons.buttonRole(button) in {
            QDialogButtonBox.AcceptRole,
            QDialogButtonBox.YesRole,
        }
        _style_dialog_button(button, destructive=destructive_ok and is_ok)


def _add_dialog_buttons(layout: QVBoxLayout, buttons: QDialogButtonBox) -> None:
    layout.addSpacing(4)
    layout.addWidget(buttons)


def pick_rows_dialog(
    parent,
    title: str,
    columns: list[tuple[str, str]],
    rows: list[dict[str, Any]],
    *,
    on_pick: Callable[[dict[str, Any]], None] | None = None,
    hint: str = "Double-click a row to select it.",
) -> None:
    from PySide6.QtGui import QGuiApplication

    from ui.dict_table_model import DictTableModel

    if not rows:
        message_dialog(parent, title, "No saved values yet.", width=420)
        return

    pick_dlg = QDialog(parent)
    pick_dlg.setWindowTitle(title)
    screen = QGuiApplication.primaryScreen()
    if screen is not None:
        available = screen.availableGeometry()
        pick_dlg.resize(min(820, available.width() - 120), min(520, available.height() - 120))
    else:
        pick_dlg.resize(760, 480)

    layout = QVBoxLayout(pick_dlg)
    layout.setContentsMargins(14, 14, 14, 28)
    layout.setSpacing(10)

    hint_lbl = QLabel(hint)
    hint_lbl.setObjectName("Muted")
    hint_lbl.setWordWrap(True)
    layout.addWidget(hint_lbl)

    table = QTableView(pick_dlg)
    table.setModel(DictTableModel(columns, rows))
    table.setSortingEnabled(True)
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QTableView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.setEditTriggers(QTableView.NoEditTriggers)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    table.setMinimumHeight(320)
    layout.addWidget(table, 1)

    if on_pick is not None:
        def handle_double_click(index) -> None:
            model = table.model()
            if not isinstance(model, DictTableModel) or not index.isValid():
                return
            row_idx = index.row()
            if 0 <= row_idx < len(model.rows):
                on_pick(model.rows[row_idx])
                pick_dlg.accept()

        table.doubleClicked.connect(handle_double_click)

    buttons = QDialogButtonBox(QDialogButtonBox.Close)
    _style_dialog_buttons(buttons)
    buttons.rejected.connect(pick_dlg.reject)
    buttons.accepted.connect(pick_dlg.accept)
    _add_dialog_buttons(layout, buttons)
    pick_dlg.exec()


def period_range_dialog(
    parent,
    *,
    title: str = "Select period",
    first_day: str,
    last_day: str,
    present_days: list[str] | None = None,
    width: int = 560,
) -> tuple[str, str] | None:
    first = QDate.fromString(normalize_period_day(first_day), "yyyy-MM-dd")
    last = QDate.fromString(normalize_period_day(last_day), "yyyy-MM-dd")
    if not first.isValid() or not last.isValid():
        return None

    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setMinimumWidth(width)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    intro = QLabel(
        "Choose the calendar range to load. Days without indexed files can be imported afterward."
    )
    intro.setWordWrap(True)
    layout.addWidget(intro)

    detected = QLabel(
        f"Indexed span: {format_period_day_label(first_day)} – {format_period_day_label(last_day)}"
    )
    detected.setObjectName("Muted")
    detected.setWordWrap(True)
    layout.addWidget(detected)

    form = QFormLayout()
    start_edit = period_date_edit(first, first, last)
    end_edit = period_date_edit(last, first, last)
    form.addRow("From:", start_edit)
    form.addRow("To:", end_edit)
    layout.addLayout(form)

    summary = QLabel("")
    summary.setObjectName("Muted")
    summary.setWordWrap(True)
    layout.addWidget(summary)

    def update_summary() -> None:
        start = start_edit.date().toString("yyyy-MM-dd")
        end = end_edit.date().toString("yyyy-MM-dd")
        if start > end:
            start, end = end, start
        missing = missing_days_in_range(present_days or [], start, end)
        if missing:
            preview = ", ".join(format_period_day_label(day) or day for day in missing[:6])
            extra = max(0, len(missing) - 6)
            if extra:
                preview = f"{preview} (+{extra:,} more)"
            summary.setText(f"Missing indexed days in range: {len(missing):,} ({preview})")
        else:
            summary.setText("All days in the selected range are indexed.")

    start_edit.dateChanged.connect(lambda *_: update_summary())
    end_edit.dateChanged.connect(lambda *_: update_summary())
    update_summary()

    buttons = QDialogButtonBox()
    buttons.addButton("Apply range", QDialogButtonBox.AcceptRole)
    buttons.addButton("Cancel", QDialogButtonBox.RejectRole)
    _style_dialog_buttons(buttons)
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    _add_dialog_buttons(layout, buttons)

    if dlg.exec() != QDialog.Accepted:
        return None

    start = start_edit.date().toString("yyyy-MM-dd")
    end = end_edit.date().toString("yyyy-MM-dd")
    if start > end:
        start, end = end, start
    return start, end


def missing_range_import_dialog(
    parent,
    *,
    title: str,
    missing_days: list[str],
    import_label: str = "Import missing periods…",
) -> str | None:
    if not missing_days:
        return None
    preview = ", ".join(format_period_day_label(day) or day for day in missing_days[:12])
    extra = max(0, len(missing_days) - 12)
    details = preview + (f" (+{extra:,} more)" if extra else "")
    return choice_dialog(
        parent,
        title,
        f"{len(missing_days):,} day(s) in the selected range are not indexed yet:\n\n{details}",
        [import_label, "Continue without import", "Cancel"],
        width=620,
    )


def message_dialog(
    parent,
    title: str,
    message: str,
    details: str = "",
    width: int = DIALOG_DEFAULT_WIDTH,
) -> None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    lbl_message = QLabel(message)
    lbl_message.setWordWrap(True)
    lbl_message.setTextFormat(Qt.PlainText)
    lbl_message.setObjectName("DialogMessageLabel")
    layout.addWidget(lbl_message)

    if details:
        lbl_details = QLabel(details)
        lbl_details.setWordWrap(True)
        lbl_details.setTextFormat(Qt.PlainText)
        lbl_details.setObjectName("DialogDetailsLabel")
        layout.addWidget(lbl_details)

    buttons = QDialogButtonBox()
    btn_ok = buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    _style_dialog_button(btn_ok)

    buttons.accepted.connect(dlg.accept)
    _add_dialog_buttons(layout, buttons)

    _fit_compact_dialog(dlg, width)
    dlg.exec()


def choice_dialog(
    parent,
    title: str,
    message: str,
    choices: list[str],
    width: int = 480,
) -> str | None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    lbl = QLabel(message)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.PlainText)
    lbl.setObjectName("DialogMessageLabel")
    layout.addWidget(lbl)

    result = {"value": None}
    action_choices = [
        choice
        for choice in choices
        if str(choice or "").strip().casefold() != "cancel"
    ]

    footer = QHBoxLayout()
    footer.setSpacing(8)
    footer.addStretch(1)

    for choice in action_choices:
        btn = make_dialog_button(choice)

        def _make_handler(c=choice):
            def handler():
                result["value"] = c
                dlg.accept()
            return handler

        btn.clicked.connect(_make_handler())
        footer.addWidget(btn)

    if action_choices:
        footer.addSpacing(16)

    cancel_btn = make_dialog_button("Cancel")
    cancel_btn.clicked.connect(dlg.reject)
    footer.addWidget(cancel_btn)
    footer.addStretch(1)

    layout.addSpacing(12)
    layout.addLayout(footer)

    _fit_compact_dialog(dlg, width)
    ok = dlg.exec() == QDialog.Accepted
    return result["value"] if ok else None


def text_input_dialog(
    parent,
    title: str,
    label: str,
    text: str = "",
    width: int = 420,
):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    lbl = QLabel(label)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.PlainText)
    layout.addWidget(lbl)

    edit = QLineEdit()
    edit.setText(text)
    edit.selectAll()
    edit.setFixedHeight(DIALOG_FIELD_HEIGHT)
    layout.addWidget(edit)

    buttons = QDialogButtonBox()
    buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    buttons.addButton("Cancel", QDialogButtonBox.RejectRole)
    _style_dialog_buttons(buttons)

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    _add_dialog_buttons(layout, buttons)

    _fit_compact_dialog(dlg, width)
    ok = dlg.exec() == QDialog.Accepted
    return edit.text(), ok


def multiline_input_dialog(
    parent,
    title: str,
    label: str,
    text: str = "",
    width: int = 460,
    height: int = 220,
):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    lbl = QLabel(label)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.PlainText)
    layout.addWidget(lbl)

    edit = QPlainTextEdit()
    edit.setPlainText(text)
    edit.setMinimumHeight(max(120, height - 120))
    layout.addWidget(edit, 1)

    buttons = QDialogButtonBox()
    buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    buttons.addButton("Cancel", QDialogButtonBox.RejectRole)
    _style_dialog_buttons(buttons)

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    _add_dialog_buttons(layout, buttons)

    dlg.resize(width, height)
    ok = dlg.exec() == QDialog.Accepted
    return edit.toPlainText(), ok


def item_choice_dialog(
    parent,
    title: str,
    label: str,
    items: list[str],
    current_index: int = 0,
    width: int = 420,
):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setFixedWidth(width)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    lbl = QLabel(label)
    lbl.setWordWrap(True)
    layout.addWidget(lbl)

    combo = QComboBox()
    combo.addItems(items)
    combo.setCurrentIndex(max(0, min(current_index, len(items) - 1)))
    combo.setMinimumHeight(40)
    layout.addWidget(combo)

    buttons = QDialogButtonBox()
    buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    buttons.addButton("Cancel", QDialogButtonBox.RejectRole)
    _style_dialog_buttons(buttons)

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    _add_dialog_buttons(layout, buttons)

    ok = dlg.exec() == QDialog.Accepted
    return combo.currentText(), ok


def _dialog_panel(title: str) -> tuple[QFrame, QVBoxLayout]:
    panel = QFrame()
    panel.setObjectName("ProfilePanel")
    panel.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
    layout = QVBoxLayout(panel)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(10)
    title_label = QLabel(title)
    title_label.setObjectName("ProfilePanelTitle")
    layout.addWidget(title_label)
    return panel, layout


def _dialog_field_group(label_text: str, field: QWidget) -> QWidget:
    host = QWidget()
    host.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
    layout = QVBoxLayout(host)
    layout.setContentsMargins(0, 0, 0, 6)
    layout.setSpacing(6)
    label = QLabel(label_text)
    label.setObjectName("DialogFieldLabel")
    label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    layout.addWidget(label)
    layout.addWidget(field)
    return host


def _dialog_line_edit(value: str = "", *, placeholder: str = "") -> QLineEdit:
    edit = QLineEdit()
    edit.setObjectName("DialogField")
    edit.setText(value)
    edit.setPlaceholderText(placeholder)
    edit.setFixedHeight(DIALOG_FIELD_HEIGHT)
    edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    ensure_widget_point_font(edit)
    return edit


def _dialog_multiline_edit(value: str = "", *, placeholder: str = "", height: int = 72) -> QPlainTextEdit:
    edit = QPlainTextEdit()
    edit.setObjectName("DialogField")
    edit.setPlainText(value)
    edit.setPlaceholderText(placeholder)
    edit.setFixedHeight(height)
    ensure_widget_point_font(edit)
    return edit


class _DialogMultiValueEditor(QWidget):
    """Single-line rows with + / − controls for repeated identifier values."""

    def __init__(
        self,
        parent=None,
        *,
        initial_values: list[str] | None = None,
        placeholder: str = "",
        on_layout_changed: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        self._placeholder = placeholder
        self._on_layout_changed = on_layout_changed
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)
        self._values = list(initial_values or [""])
        if not self._values:
            self._values = [""]
        self._render()

    def _row_height(self) -> int:
        return DIALOG_FIELD_HEIGHT

    def _notify_layout_changed(self) -> None:
        self.updateGeometry()
        if self._on_layout_changed is not None:
            self._on_layout_changed()

    def minimumSizeHint(self) -> QSize:
        rows = max(1, self._layout.count())
        spacing = self._layout.spacing()
        height = rows * self._row_height() + max(0, rows - 1) * spacing
        return QSize(super().minimumSizeHint().width(), height)

    def sizeHint(self) -> QSize:
        return self.minimumSizeHint()

    def _current_values(self) -> list[str]:
        values: list[str] = []
        for index in range(self._layout.count()):
            host = self._layout.itemAt(index).widget()
            if host is None:
                continue
            edit = host.findChild(QLineEdit)
            values.append(edit.text() if edit is not None else "")
        return values or [""]

    def _clear_rows(self) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _render(self, *, focus_last: bool = False) -> None:
        self._clear_rows()
        for index, value in enumerate(self._values):
            host = QWidget()
            host.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            host.setFixedHeight(self._row_height())
            row = QHBoxLayout(host)
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(8)
            edit = _dialog_line_edit(value, placeholder=self._placeholder)
            row.addWidget(edit, 1)

            if len(self._values) > 1:
                btn_remove = QPushButton("−")
                style_inline_picker_button(btn_remove)
                btn_remove.setFixedSize(self._row_height(), self._row_height())
                btn_remove.setToolTip("Remove value")
                btn_remove.clicked.connect(lambda _checked=False, row_index=index: self._remove_at(row_index))
                row.addWidget(btn_remove)

            if index == len(self._values) - 1:
                btn_add = QPushButton("+")
                style_inline_picker_button(btn_add)
                btn_add.setFixedSize(self._row_height(), self._row_height())
                btn_add.setToolTip("Add value")
                btn_add.clicked.connect(self._add_row)
                row.addWidget(btn_add)

            self._layout.addWidget(host)

        if focus_last and self._layout.count():
            host = self._layout.itemAt(self._layout.count() - 1).widget()
            if host is not None:
                edit = host.findChild(QLineEdit)
                if edit is not None:
                    edit.setFocus()

        self._notify_layout_changed()

    def _add_row(self) -> None:
        self._values = self._current_values()
        self._values.append("")
        self._render(focus_last=True)

    def _remove_at(self, index: int) -> None:
        self._values = self._current_values()
        if len(self._values) <= 1:
            self._values = [""]
        else:
            self._values.pop(index)
        self._render()

    def text(self) -> str:
        rows: list[str] = []
        seen: set[str] = set()
        for value in self._current_values():
            item = value.strip()
            if not item:
                continue
            key = item.casefold()
            if key in seen:
                continue
            seen.add(key)
            rows.append(item)
        return "\n".join(rows)


def _prepare_dialog_scroll_content(content: QWidget) -> None:
    content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)


class _DialogScrollSync(QObject):
    """Keep scroll content sized to its contents; width tracks the viewport."""

    def __init__(self, dlg: QDialog, scroll: QScrollArea, content: QWidget) -> None:
        super().__init__(dlg)
        self._scroll = scroll
        self._content = content
        dlg.installEventFilter(self)
        content.installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:
        if not _dialog_scroll_targets_alive(self._scroll, self._content):
            return False
        if event.type() in {QEvent.Type.Resize, QEvent.Type.LayoutRequest}:
            if obj is self.parent() or obj is self._content:
                self._schedule_sync()
        return False

    def _schedule_sync(self) -> None:
        QTimer.singleShot(0, self.sync)

    def sync(self) -> None:
        if not _dialog_scroll_targets_alive(self._scroll, self._content):
            return
        try:
            viewport = self._scroll.viewport()
        except RuntimeError:
            return
        if viewport is None or not isValid(viewport):
            return
        self._content.adjustSize()
        width = max(viewport.width(), self._content.sizeHint().width())
        height = max(self._content.sizeHint().height(), self._content.minimumSizeHint().height())
        if width > 0 and height > 0:
            self._content.setMinimumSize(width, height)
            self._content.resize(width, height)


def _dialog_scroll_targets_alive(scroll: QScrollArea | None, content: QWidget | None) -> bool:
    return isValid(scroll) and isValid(content)


def _install_dialog_scroll(
    scroll: QScrollArea,
    content: QWidget,
    dlg: QDialog,
    *,
    bottom_margin: int = 32,
) -> _DialogScrollSync:
    scroll.setWidgetResizable(False)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    _prepare_dialog_scroll_content(content)
    layout = content.layout()
    if isinstance(layout, QVBoxLayout):
        left, top, right, _bottom = layout.getContentsMargins()
        layout.setContentsMargins(left, top, right, bottom_margin)
    scroll.setWidget(content)
    return _DialogScrollSync(dlg, scroll, content)


def project_details_dialog(
    parent,
    *,
    title: str,
    project=None,
    parent_folder: str = "",
    width: int = PROJECT_DIALOG_WIDTH,
):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    intro = QLabel("Project workspace, case subject and order metadata.")
    intro.setWordWrap(True)
    intro.setTextFormat(Qt.PlainText)
    intro.setObjectName("DialogDetailsLabel")
    layout.addWidget(intro)

    scroll = QScrollArea()
    scroll.setFrameShape(QScrollArea.NoFrame)

    content = QWidget()
    content_layout = QVBoxLayout(content)
    content_layout.setContentsMargins(0, 0, 4, 0)
    content_layout.setSpacing(14)

    fields: dict[str, QLineEdit | QPlainTextEdit | _DialogMultiValueEditor] = {}
    scroll_sync_ref: list[_DialogScrollSync | None] = [None]

    def _refresh_dialog_scroll() -> None:
        sync = scroll_sync_ref[0]
        if sync is not None:
            sync.sync()

    project_panel, project_layout = _dialog_panel("Project")
    edit_name = _dialog_line_edit(getattr(project, "name", "") or "")
    project_layout.addWidget(_dialog_field_group("Project name", edit_name))

    edit_desc = QPlainTextEdit()
    edit_desc.setObjectName("DialogField")
    edit_desc.setPlainText(getattr(project, "description", "") or "")
    edit_desc.setFixedHeight(96)
    edit_desc.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    ensure_widget_point_font(edit_desc)
    project_layout.addWidget(_dialog_field_group("Description", edit_desc))

    workspace_row = QHBoxLayout()
    workspace_row.setSpacing(8)
    workspace_row.setContentsMargins(0, 0, 0, 0)
    edit_parent = _dialog_line_edit(parent_folder or "", placeholder="Required parent folder for ViaNyquist workspace")
    btn_browse = make_dialog_button("Browse...")
    btn_browse.setFixedHeight(DIALOG_FIELD_HEIGHT)
    workspace_row.addWidget(edit_parent, 1)
    workspace_row.addWidget(btn_browse, 0, Qt.AlignVCenter)
    workspace_host = QWidget()
    workspace_host.setFixedHeight(DIALOG_FIELD_HEIGHT)
    workspace_host.setLayout(workspace_row)
    project_layout.addWidget(_dialog_field_group("Workspace parent", workspace_host))
    content_layout.addWidget(project_panel)

    subject_panel, subject_layout = _dialog_panel("Case subject / identifiers")
    identifier_specs = [
        ("first_name", "First name", "subject_first_name"),
        ("last_name", "Last name", "subject_last_name"),
        ("oib", "OIB", "subject_oib"),
    ]
    grid = QGridLayout()
    grid.setHorizontalSpacing(14)
    grid.setVerticalSpacing(12)
    for index, (key, label, attr) in enumerate(identifier_specs):
        edit = _dialog_line_edit(getattr(project, attr or key, "") or "")
        fields[key] = edit
        row, col = divmod(index, 2)
        grid.addWidget(_dialog_field_group(label, edit), row, col)
    subject_layout.addLayout(grid)

    multi_identifier_specs = [
        ("msisdn", "Mobile / MSISDN", "subject_msisdn", "MSISDN"),
        ("imsi", "IMSI", "subject_imsi", "IMSI"),
        ("imei", "IMEI", "subject_imei", "IMEI"),
    ]
    for key, label, attr, kind in multi_identifier_specs:
        initial = identifier_values_for_editor(getattr(project, attr or key, "") or "", kind=kind)
        editor = _DialogMultiValueEditor(
            initial_values=initial,
            placeholder=f"Enter {kind}",
            on_layout_changed=_refresh_dialog_scroll,
        )
        fields[key] = editor
        subject_layout.addWidget(_dialog_field_group(label, editor))

    extra = _dialog_multiline_edit(
        getattr(project, "subject_extra_identifiers", "") or "",
        placeholder="Other identifiers or notes, one per line.",
        height=72,
    )
    fields["extra_identifiers"] = extra
    subject_layout.addWidget(_dialog_field_group("Other identifiers", extra))
    content_layout.addWidget(subject_panel)

    metadata_panel, metadata_layout = _dialog_panel("Case order metadata")

    from core.case_metadata import (
        LAWFUL_INTERCEPTION_DATES_LABEL,
        LAWFUL_INTERCEPTION_PERIOD_PICKER_TITLE,
        active_klasa_value,
        active_urbroj_value,
        format_order_datetime,
        load_case_metadata,
        merged_order_validity_bounds,
        order_validity_period_rows,
    )

    metadata: dict[str, Any] = {}
    if project is not None and getattr(project, "id", None):
        metadata = load_case_metadata(int(project.id))

    klasa_values = [str(row.get("value") or "") for row in metadata.get("klasa_entries") or [] if str(row.get("value") or "")]
    urbroj_values = [str(row.get("value") or "") for row in metadata.get("urbroj_entries") or [] if str(row.get("value") or "")]
    merged_bt, merged_et = merged_order_validity_bounds(metadata)
    validity_rows = order_validity_period_rows(metadata)

    def add_metadata_field(
        key: str,
        label: str,
        values: list[str],
        initial: str,
        *,
        placeholder: str,
    ) -> None:
        row = QHBoxLayout()
        row.setSpacing(8)
        edit = QLineEdit()
        edit.setObjectName("DialogField")
        edit.setText(initial)
        edit.setPlaceholderText(placeholder)
        edit.setMinimumHeight(DIALOG_FIELD_HEIGHT)
        edit.setFixedHeight(DIALOG_FIELD_HEIGHT)
        fields[key] = edit
        btn_pick = QPushButton(f"… ({len(values)})" if values else "…")
        _style_inline_dialog_button(btn_pick)
        btn_pick.setEnabled(bool(values))

        def show_picker(_checked: bool = False) -> None:
            pick_rows_dialog(
                dlg,
                label.strip(":"),
                [("value", "Value")],
                [{"value": value} for value in values],
                on_pick=lambda picked, field=edit: field.setText(str(picked.get("value") or "")),
                hint="Double-click a value to place it in the field.",
            )

        btn_pick.clicked.connect(show_picker)
        row.addWidget(edit, 1)
        row.addWidget(btn_pick)
        metadata_layout.addWidget(_dialog_field_group(label.rstrip(":"), _wrap_layout(row)))

    add_metadata_field(
        "klasa",
        "Klasa:",
        klasa_values,
        active_klasa_value(metadata),
        placeholder="Enter Klasa or pick from saved values",
    )
    add_metadata_field(
        "urbroj",
        "Urbroj:",
        urbroj_values,
        active_urbroj_value(metadata),
        placeholder="Enter Urbroj or pick from saved values",
    )

    edit_valid_from = QLineEdit()
    edit_valid_from.setObjectName("DialogField")
    edit_valid_from.setPlaceholderText("Valid from")
    edit_valid_from.setFixedHeight(DIALOG_FIELD_HEIGHT)
    edit_valid_from.setText(format_order_datetime(merged_bt, missing=""))
    fields["order_validity_bt"] = edit_valid_from

    edit_valid_to = QLineEdit()
    edit_valid_to.setObjectName("DialogField")
    edit_valid_to.setPlaceholderText("Valid to")
    edit_valid_to.setFixedHeight(DIALOG_FIELD_HEIGHT)
    edit_valid_to.setText(format_order_datetime(merged_et, missing=""))
    fields["order_validity_et"] = edit_valid_to

    validity_row = QHBoxLayout()
    validity_row.setSpacing(8)
    validity_row.addWidget(edit_valid_from, 1)
    arrow = QLabel("→")
    arrow.setObjectName("Muted")
    validity_row.addWidget(arrow)
    validity_row.addWidget(edit_valid_to, 1)
    btn_periods = QPushButton(f"… ({len(validity_rows)})" if validity_rows else "…")
    _style_inline_dialog_button(btn_periods)
    btn_periods.setEnabled(bool(validity_rows))

    def show_validity_periods(_checked: bool = False) -> None:
        def apply_period(picked: dict[str, Any]) -> None:
            edit_valid_from.setText(str(picked.get("from") or ""))
            edit_valid_to.setText(str(picked.get("to") or ""))

        pick_rows_dialog(
            dlg,
            LAWFUL_INTERCEPTION_PERIOD_PICKER_TITLE,
            [
                ("label", "Period"),
                ("from", "From"),
                ("to", "To"),
                ("source", "Source"),
            ],
            validity_rows,
            on_pick=apply_period,
            hint="Merged range is shown in the fields. Double-click one period to load it into the fields.",
        )

    btn_periods.clicked.connect(show_validity_periods)
    validity_row.addWidget(btn_periods)
    metadata_layout.addWidget(_dialog_field_group(LAWFUL_INTERCEPTION_DATES_LABEL, _wrap_layout(validity_row)))
    content_layout.addWidget(metadata_panel)

    scroll_sync = _install_dialog_scroll(scroll, content, dlg)
    scroll_sync_ref[0] = scroll_sync
    scroll_sync.sync()
    scroll.setMinimumHeight(480)
    layout.addWidget(scroll, 1)

    def browse_parent() -> None:
        selected = QFileDialog.getExistingDirectory(
            dlg,
            "Select parent folder for project workspace",
            edit_parent.text().strip(),
        )
        if selected:
            edit_parent.setText(selected)

    btn_browse.clicked.connect(browse_parent)

    buttons = QDialogButtonBox()
    buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    buttons.addButton("Cancel", QDialogButtonBox.RejectRole)
    _style_dialog_buttons(buttons)

    def accept_project_details() -> None:
        if not edit_parent.text().strip():
            QMessageBox.warning(
                dlg,
                "Workspace required",
                "Select a Workspace parent folder before saving the project.",
            )
            return
        oib = fields["oib"].text().strip()
        if oib and not is_valid_oib(oib):
            QMessageBox.warning(
                dlg,
                "Invalid OIB",
                "OIB must contain 11 digits and pass the Croatian control number check.",
            )
            return
        dlg.accept()

    buttons.accepted.connect(accept_project_details)
    buttons.rejected.connect(dlg.reject)
    _add_dialog_buttons(layout, buttons)

    screen = dlg.screen().availableGeometry() if dlg.screen() else None
    dialog_width = min(width, screen.width() - 64) if screen else width
    dialog_height = min(PROJECT_DIALOG_HEIGHT, screen.height() - 48) if screen else PROJECT_DIALOG_HEIGHT
    dlg.resize(dialog_width, dialog_height)
    scroll_sync.sync()
    ensure_dialog_fonts(dlg)

    if dlg.exec() != QDialog.Accepted:
        return None, False

    subject = {}
    for key, widget in fields.items():
        if isinstance(widget, _DialogMultiValueEditor):
            subject[key] = widget.text()
        elif isinstance(widget, QPlainTextEdit):
            subject[key] = widget.toPlainText().strip()
        else:
            subject[key] = widget.text().strip()

    return {
        "name": edit_name.text().strip(),
        "description": edit_desc.toPlainText().strip(),
        "parent_folder": edit_parent.text().strip(),
        **subject,
    }, True


def finding_details_dialog(
    parent,
    *,
    title: str,
    finding: dict[str, Any],
    width: int = DIALOG_FORM_WIDTH,
    for_edit: bool = True,
):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    if for_edit:
        intro_text = "Edit the finding summary, analyst note, status and tags in one place."
    else:
        intro_text = "Add a title, analyst note and tags for the new finding."
    intro = QLabel(intro_text)
    intro.setWordWrap(True)
    intro.setTextFormat(Qt.PlainText)
    intro.setObjectName("DialogDetailsLabel")
    layout.addWidget(intro)

    summary_panel, summary_layout = _dialog_panel("Finding")
    edit_title = _dialog_line_edit(str(finding.get("title") or ""))
    summary_layout.addWidget(_dialog_field_group("Title", edit_title))

    edit_status = None
    if for_edit:
        edit_status = QComboBox()
        edit_status.addItems(["New", "Investigating", "Confirmed", "False Positive"])
        current_status = str(finding.get("status") or "New")
        status_index = max(0, edit_status.findText(current_status))
        edit_status.setCurrentIndex(status_index)
        edit_status.setFixedHeight(DIALOG_FIELD_HEIGHT)
        summary_layout.addWidget(_dialog_field_group("Status", edit_status))
    layout.addWidget(summary_panel)

    details_panel, details_layout = _dialog_panel("Details")
    edit_tags = _dialog_line_edit(str(finding.get("tags") or ""), placeholder="Comma-separated tags")
    details_layout.addWidget(_dialog_field_group("Tags", edit_tags))
    edit_note = _dialog_multiline_edit(
        str(finding.get("note") or ""),
        placeholder="Analyst note",
        height=160,
    )
    details_layout.addWidget(_dialog_field_group("Note", edit_note))
    layout.addWidget(details_panel, 1)

    buttons = QDialogButtonBox()
    buttons.addButton("Save" if for_edit else "Create", QDialogButtonBox.AcceptRole)
    buttons.addButton("Cancel", QDialogButtonBox.RejectRole)
    _style_dialog_buttons(buttons)
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    _add_dialog_buttons(layout, buttons)

    screen = dlg.screen().availableGeometry() if dlg.screen() else None
    dialog_width = min(width, screen.width() - 64) if screen else width
    dialog_height = min(FINDING_DIALOG_HEIGHT, screen.height() - 48) if screen else FINDING_DIALOG_HEIGHT
    dlg.resize(dialog_width, dialog_height)
    ensure_dialog_fonts(dlg)

    if dlg.exec() != QDialog.Accepted:
        return None, False

    return {
        "title": edit_title.text().strip(),
        "status": edit_status.currentText().strip() if edit_status is not None else "New",
        "tags": edit_tags.text().strip(),
        "note": edit_note.toPlainText().strip(),
    }, True


def new_finding_dialog(
    parent,
    *,
    defaults: dict[str, Any],
    width: int = DIALOG_FORM_WIDTH,
):
    return finding_details_dialog(
        parent,
        title="New finding",
        finding=defaults,
        width=width,
        for_edit=False,
    )


def _wrap_layout(inner: QHBoxLayout) -> QWidget:
    host = QWidget()
    host.setLayout(inner)
    return host


def confirm_dialog(
    parent,
    title: str,
    message: str,
    details: str = "",
    ok_text: str = "OK",
    cancel_text: str = "Cancel",
    width: int = DIALOG_DEFAULT_WIDTH,
    destructive: bool = False,
) -> bool:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    lbl_message = QLabel(message)
    lbl_message.setWordWrap(True)
    lbl_message.setObjectName("DialogMessageLabel")
    layout.addWidget(lbl_message)

    if details:
        lbl_details = QLabel(details)
        lbl_details.setWordWrap(True)
        lbl_details.setTextFormat(Qt.PlainText)
        lbl_details.setObjectName("DialogDetailsLabel")
        layout.addWidget(lbl_details)

    buttons = QDialogButtonBox()
    buttons.addButton(ok_text, QDialogButtonBox.AcceptRole)
    buttons.addButton(cancel_text, QDialogButtonBox.RejectRole)
    _style_dialog_buttons(buttons, destructive_ok=destructive)

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    _add_dialog_buttons(layout, buttons)

    _fit_compact_dialog(dlg, width)
    return dlg.exec() == QDialog.Accepted
