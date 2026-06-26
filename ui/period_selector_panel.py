"""Shared period selector widgets for JSON and PCAP dataset headers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from PySide6.QtWidgets import QComboBox, QHBoxLayout, QLabel, QPushButton, QWidget

from core.period_selector import PERIOD_MODE_OPTIONS, pick_range_button_visible
from ui.buttons import make_action_button
from ui.dataset_header_layout import (
    DATASET_PERIOD_ROW_SPACING,
    DATASET_PERIOD_ROW_TOP_MARGIN,
    PERIOD_COMBO_DAY_MIN_WIDTH,
    PERIOD_COMBO_MODE_MIN_WIDTH,
    PERIOD_CONTROL_HEIGHT,
)


def make_period_label(parent: QWidget) -> QLabel:
    label = QLabel("Period:", parent)
    label.setObjectName("HeaderStatLabel")
    label.setVisible(False)
    return label


def make_period_day_combo(parent: QWidget) -> QComboBox:
    combo = QComboBox(parent)
    combo.setMinimumWidth(PERIOD_COMBO_DAY_MIN_WIDTH)
    combo.setObjectName("CompactControl")
    combo.setFixedHeight(PERIOD_CONTROL_HEIGHT)
    combo.setVisible(False)
    return combo


def make_period_mode_combo(parent: QWidget) -> QComboBox:
    combo = QComboBox(parent)
    combo.setMinimumWidth(PERIOD_COMBO_MODE_MIN_WIDTH)
    combo.setObjectName("CompactControl")
    combo.setFixedHeight(PERIOD_CONTROL_HEIGHT)
    for label, value in PERIOD_MODE_OPTIONS:
        combo.addItem(label, value)
    combo.setVisible(False)
    return combo


def make_pick_range_button(parent: QWidget) -> QPushButton:
    button = make_action_button("Pick range…")
    button.setParent(parent)
    button.hide()
    return button


def build_period_selector_row(
    parent: QWidget,
    *,
    period_label: QLabel,
    day_combo: QComboBox,
    mode_combo: QComboBox,
    pick_range_button: QPushButton,
    middle_widgets: Iterable[QWidget] = (),
    trailing_widgets: Iterable[QWidget] = (),
) -> QWidget:
    row = QWidget(parent)
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, DATASET_PERIOD_ROW_TOP_MARGIN, 0, 0)
    layout.setSpacing(DATASET_PERIOD_ROW_SPACING)
    layout.addWidget(period_label)
    layout.addWidget(day_combo)
    for widget in middle_widgets:
        layout.addWidget(widget)
    layout.addWidget(mode_combo)
    layout.addWidget(pick_range_button)
    for widget in trailing_widgets:
        layout.addWidget(widget)
    layout.addStretch(1)
    row.setVisible(False)
    return row


def sync_pick_range_button(
    button: QPushButton | None,
    *,
    granularity: str,
    has_periods: bool,
) -> None:
    if button is None:
        return
    button.setVisible(pick_range_button_visible(granularity=granularity, has_periods=has_periods))


def sync_period_selector_panel(
    *,
    has_periods: bool,
    granularity: str,
    period_label: QLabel | None = None,
    day_combo: QComboBox | None = None,
    mode_combo: QComboBox | None = None,
    pick_range_button: QPushButton | None = None,
    period_row: QWidget | None = None,
    trailing_widgets: Mapping[QWidget, bool] | None = None,
) -> None:
    for widget in (period_label, day_combo, mode_combo, period_row):
        if widget is not None:
            widget.setVisible(has_periods)
    sync_pick_range_button(
        pick_range_button,
        granularity=granularity,
        has_periods=has_periods,
    )
    for widget, visible in (trailing_widgets or {}).items():
        widget.setVisible(visible)
