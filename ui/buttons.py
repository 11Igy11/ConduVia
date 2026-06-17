"""Shared action button factory for compact toolbar controls."""

from __future__ import annotations

from PySide6.QtWidgets import QPushButton, QSizePolicy

from ui.ui_metrics import ACTION_BUTTON_HEIGHT, DIALOG_BUTTON_HEIGHT, DIALOG_BUTTON_MIN_WIDTH


def button_min_width_for_text(button: QPushButton, *, padding: int = 28) -> int:
    metrics = button.fontMetrics()
    return int(metrics.horizontalAdvance(button.text()) + padding)


def ensure_button_fits_text(
    button: QPushButton,
    *,
    padding: int = 28,
    min_width: int = DIALOG_BUTTON_MIN_WIDTH,
) -> QPushButton:
    button.setMinimumWidth(max(min_width, button_min_width_for_text(button, padding=padding)))
    return button


def style_action_button(
    button: QPushButton,
    *,
    object_name: str = "CompactButton",
) -> QPushButton:
    button.setObjectName(object_name)
    button.setFixedHeight(ACTION_BUTTON_HEIGHT)
    button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    ensure_button_fits_text(button, padding=24, min_width=72)
    return button


def make_action_button(
    text: str,
    *,
    object_name: str = "CompactButton",
    tooltip: str = "",
    enabled: bool = True,
) -> QPushButton:
    button = QPushButton(text)
    style_action_button(button, object_name=object_name)
    if tooltip:
        button.setToolTip(tooltip)
    button.setEnabled(enabled)
    return button


def style_dialog_button(
    button: QPushButton,
    *,
    object_name: str = "DialogButton",
    destructive: bool = False,
) -> QPushButton:
    button.setObjectName("DangerButton" if destructive else object_name)
    button.setFixedHeight(DIALOG_BUTTON_HEIGHT)
    button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    ensure_button_fits_text(button, padding=32, min_width=DIALOG_BUTTON_MIN_WIDTH)
    return button


def style_inline_picker_button(button: QPushButton) -> QPushButton:
    button.setObjectName("DialogInlineButton")
    button.setFixedSize(DIALOG_BUTTON_HEIGHT, DIALOG_BUTTON_HEIGHT)
    button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    return button


def make_dialog_button(
    text: str,
    *,
    object_name: str = "DialogButton",
    tooltip: str = "",
    destructive: bool = False,
    enabled: bool = True,
) -> QPushButton:
    button = QPushButton(text)
    style_dialog_button(button, object_name=object_name, destructive=destructive)
    if tooltip:
        button.setToolTip(tooltip)
    button.setEnabled(enabled)
    return button
