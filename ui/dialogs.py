from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QVBoxLayout,
    QFormLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QLineEdit,
    QComboBox,
    QPlainTextEdit,
    QFileDialog,
    QScrollArea,
    QWidget,
)


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
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(14)

    lbl_message = QLabel(message)
    lbl_message.setWordWrap(True)
    lbl_message.setTextFormat(Qt.PlainText)
    lbl_message.setStyleSheet("font-size: 15px; font-weight: 600; color: #f3f4f6;")
    layout.addWidget(lbl_message)

    if details:
        lbl_details = QLabel(details)
        lbl_details.setWordWrap(True)
        lbl_details.setTextFormat(Qt.PlainText)
        lbl_details.setStyleSheet("font-size: 13px; color: #d1d5db;")
        layout.addWidget(lbl_details)

    buttons = QDialogButtonBox()
    btn_ok = buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    btn_ok.setFixedHeight(36)
    btn_ok.setMinimumWidth(110)

    buttons.accepted.connect(dlg.accept)
    layout.addWidget(buttons)

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
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(14)

    lbl = QLabel(message)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.PlainText)
    lbl.setStyleSheet("font-size: 15px; font-weight: 600; color: #f3f4f6;")
    layout.addWidget(lbl)

    result = {"value": None}

    btn_row = QHBoxLayout()
    btn_row.setSpacing(10)

    for choice in choices:
        btn = QPushButton(choice)
        btn.setFixedHeight(36)
        btn.setMinimumWidth(110)

        def _make_handler(c=choice):
            def handler():
                result["value"] = c
                dlg.accept()
            return handler

        btn.clicked.connect(_make_handler())
        btn_row.addWidget(btn)

    cancel_btn = QPushButton("Cancel")
    cancel_btn.setFixedHeight(36)
    cancel_btn.setMinimumWidth(110)
    cancel_btn.clicked.connect(dlg.reject)
    btn_row.addWidget(cancel_btn)

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
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(12)

    lbl = QLabel(label)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.PlainText)
    layout.addWidget(lbl)

    edit = QLineEdit()
    edit.setText(text)
    edit.selectAll()
    edit.setMinimumHeight(38)
    layout.addWidget(edit)

    buttons = QDialogButtonBox()
    btn_ok = buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    btn_cancel = buttons.addButton("Cancel", QDialogButtonBox.RejectRole)

    btn_ok.setFixedHeight(36)
    btn_cancel.setFixedHeight(36)
    btn_ok.setMinimumWidth(110)
    btn_cancel.setMinimumWidth(110)

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    layout.addWidget(buttons)

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

    layout = QVBoxLayout(dlg)
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(12)

    lbl = QLabel(label)
    lbl.setWordWrap(True)
    lbl.setTextFormat(Qt.PlainText)
    layout.addWidget(lbl)

    edit = QPlainTextEdit()
    edit.setPlainText(text)
    layout.addWidget(edit, 1)

    buttons = QDialogButtonBox()
    btn_ok = buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    btn_cancel = buttons.addButton("Cancel", QDialogButtonBox.RejectRole)

    btn_ok.setFixedHeight(36)
    btn_cancel.setFixedHeight(36)
    btn_ok.setMinimumWidth(110)
    btn_cancel.setMinimumWidth(110)

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    layout.addWidget(buttons)

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
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(12)

    lbl = QLabel(label)
    lbl.setWordWrap(True)
    layout.addWidget(lbl)

    combo = QComboBox()
    combo.addItems(items)
    combo.setCurrentIndex(max(0, min(current_index, len(items) - 1)))
    combo.setMinimumHeight(38)
    layout.addWidget(combo)

    buttons = QDialogButtonBox()
    btn_ok = buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    btn_cancel = buttons.addButton("Cancel", QDialogButtonBox.RejectRole)

    btn_ok.setFixedHeight(36)
    btn_cancel.setFixedHeight(36)
    btn_ok.setMinimumWidth(110)
    btn_cancel.setMinimumWidth(110)

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    layout.addWidget(buttons)

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

    layout = QVBoxLayout(dlg)
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(14)

    intro = QLabel("Project details and known subject/device identifiers.")
    intro.setWordWrap(True)
    intro.setTextFormat(Qt.PlainText)
    layout.addWidget(intro)

    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QScrollArea.NoFrame)

    form_host = QWidget()
    form = QFormLayout(form_host)
    form.setLabelAlignment(Qt.AlignRight)
    form.setFormAlignment(Qt.AlignTop)
    form.setHorizontalSpacing(12)
    form.setVerticalSpacing(10)

    edit_name = QLineEdit()
    edit_name.setText(getattr(project, "name", "") or "")
    edit_name.setMinimumHeight(36)
    form.addRow("Project name:", edit_name)

    edit_desc = QPlainTextEdit()
    edit_desc.setPlainText(getattr(project, "description", "") or "")
    edit_desc.setMinimumHeight(76)
    form.addRow("Description:", edit_desc)

    workspace_row = QHBoxLayout()
    edit_parent = QLineEdit()
    edit_parent.setText(parent_folder or "")
    edit_parent.setPlaceholderText("Optional parent folder for ViaNyquist workspace")
    edit_parent.setMinimumHeight(36)
    btn_browse = QPushButton("Browse...")
    btn_browse.setMinimumWidth(110)
    btn_browse.setFixedHeight(36)
    workspace_row.addWidget(edit_parent, 1)
    workspace_row.addWidget(btn_browse)
    form.addRow("Workspace parent:", workspace_row)

    section = QLabel("Case subject / identifiers")
    section.setStyleSheet("font-size: 15px; font-weight: 700; color: #f3f4f6;")
    form.addRow("", section)

    fields: dict[str, QLineEdit | QPlainTextEdit] = {}

    def add_line(key: str, label: str, attr: str = "", placeholder: str = "") -> None:
        edit = QLineEdit()
        edit.setText(getattr(project, attr or key, "") or "")
        edit.setPlaceholderText(placeholder)
        edit.setMinimumHeight(36)
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
    btn_ok = buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    btn_cancel = buttons.addButton("Cancel", QDialogButtonBox.RejectRole)
    btn_ok.setFixedHeight(36)
    btn_cancel.setFixedHeight(36)
    btn_ok.setMinimumWidth(110)
    btn_cancel.setMinimumWidth(110)
    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    layout.addWidget(buttons)

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
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(14)

    lbl_message = QLabel(message)
    lbl_message.setWordWrap(True)
    lbl_message.setStyleSheet("font-size: 15px; font-weight: 600; color: #f3f4f6;")
    layout.addWidget(lbl_message)

    if details:
        lbl_details = QLabel(details)
        lbl_details.setWordWrap(True)
        lbl_details.setTextFormat(Qt.PlainText)
        lbl_details.setStyleSheet("font-size: 13px; color: #d1d5db;")
        layout.addWidget(lbl_details)

    buttons = QDialogButtonBox()
    btn_ok = buttons.addButton(ok_text, QDialogButtonBox.AcceptRole)
    btn_cancel = buttons.addButton(cancel_text, QDialogButtonBox.RejectRole)

    btn_ok.setFixedHeight(36)
    btn_cancel.setFixedHeight(36)
    btn_ok.setMinimumWidth(110)
    btn_cancel.setMinimumWidth(110)

    if destructive:
        btn_ok.setObjectName("DangerButton")

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)

    layout.addWidget(buttons)

    return dlg.exec() == QDialog.Accepted


def ai_settings_dialog(
    parent,
    *,
    base_url: str,
    model: str,
    timeout_seconds: int,
    width: int = 480,
):
    dlg = QDialog(parent)
    dlg.setWindowTitle("AI Settings")
    dlg.setModal(True)
    dlg.setFixedWidth(width)

    layout = QVBoxLayout(dlg)
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(12)

    lbl = QLabel("Configure local AI provider.")
    lbl.setWordWrap(True)
    layout.addWidget(lbl)

    edit_url = QLineEdit()
    edit_url.setText(base_url or "")
    edit_url.setMinimumHeight(38)
    edit_url.setPlaceholderText("http://localhost:11434")
    layout.addWidget(QLabel("Base URL:"))
    layout.addWidget(edit_url)

    edit_model = QLineEdit()
    edit_model.setText(model or "")
    edit_model.setMinimumHeight(38)
    edit_model.setPlaceholderText("llama3")
    layout.addWidget(QLabel("Model:"))
    layout.addWidget(edit_model)

    edit_timeout = QLineEdit()
    edit_timeout.setText(str(timeout_seconds or 600))
    edit_timeout.setMinimumHeight(38)
    edit_timeout.setPlaceholderText("600")
    layout.addWidget(QLabel("Timeout seconds:"))
    layout.addWidget(edit_timeout)

    buttons = QDialogButtonBox()
    btn_ok = buttons.addButton("OK", QDialogButtonBox.AcceptRole)
    btn_cancel = buttons.addButton("Cancel", QDialogButtonBox.RejectRole)

    btn_ok.setFixedHeight(36)
    btn_cancel.setFixedHeight(36)
    btn_ok.setMinimumWidth(110)
    btn_cancel.setMinimumWidth(110)

    buttons.accepted.connect(dlg.accept)
    buttons.rejected.connect(dlg.reject)
    layout.addWidget(buttons)

    ok = dlg.exec() == QDialog.Accepted
    if not ok:
        return None, False

    try:
        timeout = int((edit_timeout.text() or "").strip())
    except Exception:
        timeout = 600

    return {
        "base_url": (edit_url.text() or "").strip() or "http://localhost:11434",
        "model": (edit_model.text() or "").strip() or "llama3",
        "timeout_seconds": max(1, timeout),
    }, True
