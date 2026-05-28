from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt

if TYPE_CHECKING:
    from ui.app import App


def handle_app_key_press(app: App, event) -> bool:
    key = event.key()
    mods = event.modifiers()

    if mods & Qt.ControlModifier and key == Qt.Key_F:
        app.search.setFocus()
        app.search.selectAll()
        event.accept()
        return True

    if mods & Qt.ControlModifier and key == Qt.Key_L:
        app.dataset_controller.load_dataset_dialog()
        event.accept()
        return True

    if key == Qt.Key_Escape:
        app.explore_ui_controller.leave_conversation(clear_search=True)
        event.accept()
        return True

    if app.tabs.currentIndex() == 2:
        if key == Qt.Key_J:
            app.findings_controller.jump_to_selected()
            event.accept()
            return True
        if key == Qt.Key_E:
            app.findings_controller.edit_selected()
            event.accept()
            return True
        if key == Qt.Key_Delete:
            app.findings_controller.delete_selected()
            event.accept()
            return True

    return False
