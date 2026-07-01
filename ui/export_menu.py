from __future__ import annotations

from collections.abc import Callable, Iterable

from PySide6.QtWidgets import QMenu, QPushButton

from ui.buttons import make_action_button

TABLE_EXPORT_FORMATS: tuple[tuple[str, str], ...] = (
    ("csv", "Export CSV"),
    ("xlsx", "Export Excel"),
    ("html", "Export HTML"),
)


def make_export_table_button(
    text: str = "Export table",
    *,
    enabled: bool = True,
    tooltip: str = "",
) -> QPushButton:
    button = make_action_button(text, enabled=enabled, tooltip=tooltip)
    return button


def popup_export_menu(
    button: QPushButton,
    actions: dict[str, Callable[[], None]],
    *,
    formats: Iterable[tuple[str, str]] = TABLE_EXPORT_FORMATS,
) -> None:
    menu = QMenu(button)
    for fmt, label in formats:
        handler = actions.get(fmt)
        if handler is None:
            continue
        menu.addAction(label, lambda checked=False, fn=handler: fn())
    if not menu.actions():
        return
    menu.exec(button.mapToGlobal(button.rect().bottomLeft()))


def popup_labeled_menu(
    button: QPushButton,
    items: Iterable[tuple[str, Callable[[], None]]],
) -> None:
    menu = QMenu(button)
    for label, handler in items:
        menu.addAction(label, lambda checked=False, fn=handler: fn())
    if not menu.actions():
        return
    menu.exec(button.mapToGlobal(button.rect().bottomLeft()))


def connect_table_export_dropdown(
    button: QPushButton,
    export_fn: Callable[[str], None],
) -> None:
    def _open_menu() -> None:
        popup_export_menu(
            button,
            {fmt: (lambda chosen=fmt: export_fn(chosen)) for fmt, _ in TABLE_EXPORT_FORMATS},
        )

    button.clicked.connect(_open_menu)
