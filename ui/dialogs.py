from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QLineEdit,
    QComboBox,
    QPlainTextEdit,
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