from __future__ import annotations

from collections.abc import Iterable, Callable

from PySide6.QtWidgets import QPushButton, QStackedWidget

from ui.font_utils import repolish_widget


def set_active_nav_button(buttons: Iterable[QPushButton], active: QPushButton) -> None:
    for button in buttons:
        is_active = button is active
        if bool(button.property("active")) == is_active:
            continue
        button.setProperty("active", is_active)
        repolish_widget(button)


def switch_page(
    *,
    pages: QStackedWidget,
    index: int,
    active_button: QPushButton,
    nav_buttons: Iterable[QPushButton],
    before_switch: Callable[[int], None] | None = None,
) -> None:
    if before_switch is not None:
        before_switch(index)
    pages.setCurrentIndex(index)
    set_active_nav_button(nav_buttons, active_button)
