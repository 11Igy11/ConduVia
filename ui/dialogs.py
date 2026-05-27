from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QPushButton,
    QLabel,
    QComboBox,
    QPlainTextEdit,
    QFileDialog,
    QMessageBox,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from core.project_identity import is_valid_oib

# Extra bottom margin keeps dialog action buttons clear of the window edge.
DIALOG_MARGINS = (20, 18, 20, 28)
DIALOG_BUTTON_MIN_HEIGHT = 42


def _apply_dialog_layout(layout: QVBoxLayout) -> None:
    layout.setContentsMargins(*DIALOG_MARGINS)
    layout.setSpacing(14)


def _style_dialog_button(button: QPushButton, *, destructive: bool = False) -> None:
    button.setMinimumHeight(DIALOG_BUTTON_MIN_HEIGHT)
    button.setMinimumWidth(110)
    if destructive:
        button.setObjectName("DangerButton")


def _style_dialog_buttons(buttons: QDialogButtonBox, *, destructive_ok: bool = False) -> None:
    for button in buttons.buttons():
        is_ok = buttons.buttonRole(button) in {
            QDialogButtonBox.AcceptRole,
            QDialogButtonBox.YesRole,
        }
        _style_dialog_button(button, destructive=destructive_ok and is_ok)


def _add_dialog_buttons(layout: QVBoxLayout, buttons: QDialogButtonBox) -> None:
    layout.addSpacing(6)
    layout.addWidget(buttons)


def message_dialog(
    parent,
    title: str,
    message: str,
    details: str = "",
    width: int = 420,
) -> None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setFixedWidth(width)

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

    dlg.exec()


def choice_dialog(
    parent,
    title: str,
    message: str,
    choices: list[str],
    width: int = 360,
) -> str | None:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setFixedWidth(width)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    lbl = QLabel(message)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.PlainText)
    lbl.setObjectName("DialogMessageLabel")
    layout.addWidget(lbl)

    result = {"value": None}

    btn_row = QHBoxLayout()
    btn_row.setSpacing(10)

    for choice in choices:
        btn = QPushButton(choice)
        _style_dialog_button(btn)

        def _make_handler(c=choice):
            def handler():
                result["value"] = c
                dlg.accept()
            return handler

        btn.clicked.connect(_make_handler())
        btn_row.addWidget(btn)

    cancel_btn = QPushButton("Cancel")
    _style_dialog_button(cancel_btn)
    cancel_btn.clicked.connect(dlg.reject)
    btn_row.addWidget(cancel_btn)

    layout.addSpacing(6)
    layout.addLayout(btn_row)

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
    dlg.setFixedWidth(width)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    lbl = QLabel(label)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.PlainText)
    layout.addWidget(lbl)

    edit = QLineEdit()
    edit.setText(text)
    edit.selectAll()
    edit.setMinimumHeight(40)
    layout.addWidget(edit)

    buttons = QDialogButtonBox()
    buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    buttons.addButton("Cancel", QDialogButtonBox.RejectRole)
    _style_dialog_buttons(buttons)

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    _add_dialog_buttons(layout, buttons)

    ok = dlg.exec() == QDialog.Accepted
    return edit.text(), ok


def multiline_input_dialog(
    parent,
    title: str,
    label: str,
    text: str = "",
    width: int = 480,
    height: int = 260,
):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.resize(width, height)
    dlg.setMinimumWidth(width)
    dlg.setMinimumHeight(height)

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    lbl = QLabel(label)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.PlainText)
    layout.addWidget(lbl)

    edit = QPlainTextEdit()
    edit.setPlainText(text)
    layout.addWidget(edit, 1)

    buttons = QDialogButtonBox()
    buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    buttons.addButton("Cancel", QDialogButtonBox.RejectRole)
    _style_dialog_buttons(buttons)

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    _add_dialog_buttons(layout, buttons)

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


def project_details_dialog(
    parent,
    *,
    title: str,
    project=None,
    parent_folder: str = "",
    width: int = 680,
    height: int = 640,
):
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    available = parent.screen().availableGeometry() if parent and parent.screen() else None
    if available:
        height = min(height, max(460, available.height() - 120))
        width = min(width, max(560, available.width() - 120))
    dlg.resize(width, height)
    dlg.setMinimumWidth(width)
    dlg.setMinimumHeight(min(height, 520))

    layout = QVBoxLayout(dlg)
    _apply_dialog_layout(layout)

    intro = QLabel("Project details and known subject/device identifiers.")
    intro.setWordWrap(True)
    intro.setTextFormat(Qt.PlainText)
    layout.addWidget(intro)

    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QScrollArea.NoFrame)
    scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    scroll.setSizeAdjustPolicy(QAbstractScrollArea.SizeAdjustPolicy.AdjustIgnored)
    scroll.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
    scroll.setMinimumHeight(260)

    form_host = QWidget()
    form_host.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
    form = QFormLayout(form_host)
    form.setLabelAlignment(Qt.AlignRight)
    form.setFormAlignment(Qt.AlignTop)
    form.setHorizontalSpacing(12)
    form.setVerticalSpacing(10)
    form.setContentsMargins(0, 0, 4, 8)

    edit_name = QLineEdit()
    edit_name.setText(getattr(project, "name", "") or "")
    edit_name.setMinimumHeight(40)
    form.addRow("Project name:", edit_name)

    edit_desc = QPlainTextEdit()
    edit_desc.setPlainText(getattr(project, "description", "") or "")
    edit_desc.setMinimumHeight(76)
    form.addRow("Description:", edit_desc)

    workspace_row = QHBoxLayout()
    edit_parent = QLineEdit()
    edit_parent.setText(parent_folder or "")
    edit_parent.setPlaceholderText("Required parent folder for ViaNyquist workspace")
    edit_parent.setMinimumHeight(40)
    btn_browse = QPushButton("Browse...")
    btn_browse.setMinimumWidth(110)
    btn_browse.setMinimumHeight(DIALOG_BUTTON_MIN_HEIGHT)
    workspace_row.addWidget(edit_parent, 1)
    workspace_row.addWidget(btn_browse)
    form.addRow("Workspace parent:", workspace_row)

    section = QLabel("Case subject / identifiers")
    section.setObjectName("DialogSectionLabel")
    form.addRow("", section)

    fields: dict[str, QLineEdit | QPlainTextEdit] = {}

    def add_line(key: str, label: str, attr: str = "", placeholder: str = "") -> None:
        edit = QLineEdit()
        edit.setText(getattr(project, attr or key, "") or "")
        edit.setPlaceholderText(placeholder)
        edit.setMinimumHeight(40)
        fields[key] = edit
        form.addRow(label, edit)

    add_line("first_name", "First name:", "subject_first_name")
    add_line("last_name", "Last name:", "subject_last_name")
    add_line("oib", "OIB:", "subject_oib")
    add_line("msisdn", "Mobile / MSISDN:", "subject_msisdn")
    add_line("imsi", "IMSI:", "subject_imsi")
    add_line("imei", "IMEI:", "subject_imei")
    add_line("ip", "Known IP:", "subject_ip")

    extra = QPlainTextEdit()
    extra.setPlainText(getattr(project, "subject_extra_identifiers", "") or "")
    extra.setPlaceholderText("Other identifiers or notes, one per line.")
    extra.setMinimumHeight(82)
    fields["extra_identifiers"] = extra
    form.addRow("Other:", extra)

    scroll.setWidget(form_host)
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

    if dlg.exec() != QDialog.Accepted:
        return None, False

    subject = {}
    for key, widget in fields.items():
        if isinstance(widget, QPlainTextEdit):
            subject[key] = widget.toPlainText().strip()
        else:
            subject[key] = widget.text().strip()

    return {
        "name": edit_name.text().strip(),
        "description": edit_desc.toPlainText().strip(),
        "parent_folder": edit_parent.text().strip(),
        **subject,
    }, True


def confirm_dialog(
    parent,
    title: str,
    message: str,
    details: str = "",
    ok_text: str = "OK",
    cancel_text: str = "Cancel",
    width: int = 420,
    destructive: bool = False,
) -> bool:
    dlg = QDialog(parent)
    dlg.setWindowTitle(title)
    dlg.setModal(True)
    dlg.setFixedWidth(width)

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

    return dlg.exec() == QDialog.Accepted
