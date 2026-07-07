"""Tab widgets that ignore mouse-wheel so page scroll is not hijacked by the tab bar."""

from __future__ import annotations

from PySide6.QtWidgets import QTabBar, QTabWidget


class NonScrollableTabBar(QTabBar):
    def wheelEvent(self, event) -> None:  # noqa: N802
        event.ignore()


def make_tab_widget(parent=None) -> QTabWidget:
    tabs = QTabWidget(parent)
    tabs.setTabBar(NonScrollableTabBar())
    return tabs


def disable_tab_bar_wheel(tab_widget: QTabWidget) -> None:
    if isinstance(tab_widget.tabBar(), NonScrollableTabBar):
        return
    tab_widget.setTabBar(NonScrollableTabBar())
