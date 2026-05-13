from __future__ import annotations

from collections.abc import Iterable, Callable

from PySide6.QtWidgets import QPushButton, QStackedWidget


def set_active_nav_button(buttons: Iterable[QPushButton], active: QPushButton) -> None:
    for button in buttons:
        button.setProperty("active", button is active)
        button.style().unpolish(button)
        button.style().polish(button)
        button.update()


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
