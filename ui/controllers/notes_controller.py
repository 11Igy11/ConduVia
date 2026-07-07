from __future__ import annotations

from typing import TYPE_CHECKING, Any

from core.db import get_project_notes, list_activity, set_project_notes
from ui.ai_output import make_ai_note_block
from ui.notes_actions import (
    export_notes_html_action,
    export_notes_pdf as export_notes_pdf_action,
    export_notes_word as export_notes_word_action,
    insert_notes_chart as insert_notes_chart_action,
    load_project_notes,
    save_project_notes,
)

if TYPE_CHECKING:
    from ui.app import App


class NotesController:
    def __init__(self, app: App):
        self.app = app

    def load_notes(self, project_id: int | None) -> str:
        if project_id is None:
            return ""
        return get_project_notes(project_id) or ""

    def save_notes(self, project_id: int | None, text: str) -> None:
        if project_id is None:
            return
        set_project_notes(project_id, text or "")

    def load_activity(self, project_id: int | None, limit: int = 200, *, order: str = "asc"):
        if project_id is None:
            return []
        return list_activity(project_id, limit=limit, order=order)

    def refresh_ui(self, *, refresh_profile: bool = True) -> None:
        app = self.app
        app.txt_notes.blockSignals(True)

        if app.current_project_id is None:
            load_project_notes(
                project_id=None,
                notes_controller=self,
                notes_page=app.notes_page,
            )
            app.project_activity_rows = []
            if hasattr(app, "projects_ui_controller"):
                app.projects_ui_controller._refresh_project_launcher_cards()
            app.txt_notes.blockSignals(False)
            return

        load_project_notes(
            project_id=app.current_project_id,
            notes_controller=self,
            notes_page=app.notes_page,
        )
        app.txt_notes.blockSignals(False)

        if refresh_profile:
            self.refresh_activity_ui()
        else:
            self.refresh_activity_ui_for_project(app.current_project_id)

    def insert_chart(self) -> None:
        app = self.app
        if app.current_project_id is None:
            app._message_dialog("Notes chart", "Open an active project first.", width=420)
            return

        app.refresh_activity_profile_ui()
        profile = (
            getattr(app.activity_profile_page, "profile", None)
            if hasattr(app, "activity_profile_page")
            else None
        )
        pcap_summary = getattr(getattr(app, "pcap_page", None), "summary", None)

        def choose_chart(choices: list[str]) -> tuple[str, bool]:
            return app._item_choice_dialog(
                "Insert chart",
                "Choose a chart to insert into Notes:",
                choices,
                width=460,
            )

        result = insert_notes_chart_action(
            parent=app,
            project_id=app.current_project_id,
            notes_page=app.notes_page,
            profile=profile,
            pcap_summary=pcap_summary,
            choose_chart=choose_chart,
        )
        if result.cancelled:
            return
        if result.no_data:
            app._message_dialog("Notes chart", result.error, result.details, width=520)
            return
        if not result.inserted:
            app._message_dialog("Notes chart", result.error, result.details, width=520)
            return

        app._notes_dirty = True
        self.flush()

    def open_export_menu(self) -> None:
        from ui.export_menu import popup_labeled_menu

        popup_labeled_menu(
            self.app.notes_page.btn_export,
            [
                ("Export Word", self.export_word),
                ("Export HTML", self.export_html),
                ("Export PDF", self.export_pdf),
            ],
        )

    def export_word(self) -> None:
        app = self.app
        result = export_notes_word_action(
            app,
            project_id=app.current_project_id,
            project_name=app.current_project_name,
            notes_page=app.notes_page,
        )
        if result.cancelled:
            return
        if not result.exported:
            if app.current_project_id is None:
                app._message_dialog("Notes export", result.error, width=420)
                return
            app._message_dialog("Notes export", "Failed to export notes.", result.error, width=520)
            return

        app._message_dialog("Notes export", "Notes exported to Word document.", result.file_path, width=560)

    def export_html(self) -> None:
        result = export_notes_html_action(
            self.app,
            project_id=self.app.current_project_id,
            project_name=self.app.current_project_name,
            notes_page=self.app.notes_page,
        )
        self._handle_export_result(result, "HTML")

    def export_pdf(self) -> None:
        result = export_notes_pdf_action(
            self.app,
            project_id=self.app.current_project_id,
            project_name=self.app.current_project_name,
            notes_page=self.app.notes_page,
        )
        self._handle_export_result(result, "PDF")

    def _handle_export_result(self, result, label: str) -> None:
        app = self.app
        if result.cancelled:
            return
        if not result.exported:
            if app.current_project_id is None:
                app._message_dialog("Notes export", result.error, width=420)
                return
            app._message_dialog("Notes export", f"Failed to export notes to {label}.", result.error, width=520)
            return

        app._message_dialog("Notes export", f"Notes exported to {label}.", result.file_path, width=560)

    def refresh_activity_ui_for_project(self, project_id: int | None) -> None:
        app = self.app
        app.project_activity_rows = []

        if project_id is None:
            if hasattr(app, "projects_ui_controller"):
                app.projects_ui_controller._refresh_project_launcher_cards()
            return

        rows = self.load_activity(project_id, order="asc")
        for row in rows:
            ts = row["created_at"]
            et = row["event_type"]
            msg = row["message"] or ""
            if hasattr(app, "projects_ui_controller"):
                label = app.projects_ui_controller.activity_label(str(et), str(msg))
            else:
                label = str(et).replace("_", " ").title()
            app.project_activity_rows.append({
                "created_at": str(ts or ""),
                "event": label,
                "detail": str(msg or ""),
            })
        if hasattr(app, "projects_ui_controller"):
            app.projects_ui_controller._refresh_project_launcher_cards()

    def refresh_activity_ui(self) -> None:
        app = self.app
        self.refresh_activity_ui_for_project(app.current_project_id)
        app.refresh_activity_profile_ui()

    def on_changed(self) -> None:
        app = self.app
        if app.current_project_id is None:
            return
        app._notes_dirty = True
        app._notes_timer.start(800)

    def flush(self) -> None:
        app = self.app
        if not app._notes_dirty or app.current_project_id is None:
            return

        try:
            saved = save_project_notes(
                project_id=app.current_project_id,
                notes_controller=self,
                notes_page=app.notes_page,
            )
        except Exception:
            return

        if saved:
            app._notes_dirty = False

    def append_ai_text(self, text: str) -> bool:
        app = self.app
        if app.current_project_id is None:
            app._message_dialog("Notes", "Open an active project first.", width=420)
            return False

        block = make_ai_note_block(text)
        if not block:
            return False

        app.notes_page.append_block(block)
        app._notes_dirty = True
        self.flush()
        app.go_to_notes()
        return True
