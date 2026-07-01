from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QMenu

from core.db import add_finding, delete_finding, get_finding, list_findings, update_finding
from core.pcap_finding import (
    communication_finding_note,
    default_communication_finding_title,
    default_period_finding_title,
    flow_from_communication_row,
    flow_from_pcap_summary,
    period_finding_note,
)
from ui.app_helpers import normalize_tags, status_emoji
from ui.dialogs import finding_details_dialog
from ui.explore_widgets import AITextWorker
from ui.findings_format import format_finding_detail, update_finding_status

if TYPE_CHECKING:
    from ui.app import App


class FindingsController:
    def __init__(self, app: App):
        self.app = app
        self.rows: list[Any] = []
        self.view_rows: list[Any] = []

    def selected_finding_id(self) -> int | None:
        return self.app.findings_page.selected_finding_id()

    def set_actions_enabled(self, enabled: bool) -> None:
        self.app.findings_page.set_actions_enabled(enabled)

    def get_selected_row(self, finding_id: int | None):
        if finding_id is None:
            return None, None

        row = get_finding(finding_id)
        if row is None:
            return finding_id, None

        return finding_id, row

    def load_rows(self, project_id: int):
        if project_id is None:
            self.rows = []
            return []

        self.rows = list(list_findings(project_id, limit=500))
        return self.rows

    def get_filtered_rows(self, status_sel, search, tagq, findings_page):
        search = (search or "").strip().lower()
        tagq = (tagq or "").strip().lower()
        status_sel = (status_sel or "All").strip()

        rows = [
            r for r in self.rows
            if findings_page.matches_filters(r, status_sel, search, tagq)
        ]

        return findings_page.sort_rows(rows, findings_page.cmb_find_sort.currentText())

    def prepare_render_rows(self, rows, status_emoji_fn):
        render_rows = []
        for r in rows:
            rr = dict(r)
            rr["status_emoji"] = status_emoji_fn(r["status"])
            render_rows.append(rr)
        return render_rows

    def refresh_ui(self) -> None:
        app = self.app
        self.rows = []
        self.view_rows = []

        if app.current_project_id is None:
            app.findings_page.clear_list()
            app.findings_page.add_list_item("(no active project)", None)
            app.findings_page.clear_detail()
            return

        self.load_rows(app.current_project_id)
        self.apply_filter()

    def apply_filter(self) -> None:
        app = self.app
        keep_id = self.selected_finding_id()
        status_sel = (app.cmb_find_status.currentText() or "All").strip()

        rows = self.get_filtered_rows(
            status_sel,
            app.txt_find_search.text(),
            app.txt_find_tag.text(),
            app.findings_page,
        )

        render_rows = self.prepare_render_rows(rows, status_emoji)
        self.view_rows = rows
        app.findings_page.render_list(render_rows, app.current_project_id, keep_id)

    def clear_filters(self) -> None:
        app = self.app
        app.cmb_find_status.setCurrentText("All")
        app.cmb_find_sort.setCurrentText("Newest")
        app.txt_find_search.setText("")
        app.txt_find_tag.setText("")
        self.apply_filter()

    def on_selected(self) -> None:
        app = self.app
        fid, row = self.get_selected_row(self.selected_finding_id())

        if fid is None:
            app.findings_page.clear_detail()
            return

        if row is None:
            app.findings_page.show_detail("Finding not found.")
            self.set_actions_enabled(False)
            return

        self.set_actions_enabled(True)
        app.findings_page.show_detail(format_finding_detail(row, status_emoji))

    def mark_as_finding(self) -> None:
        app = self.app
        if app.current_project_id is None:
            app._message_dialog("Findings", "Select an active project first (Projects -> Open).", width=460)
            return
        if not app._current_flow:
            app._message_dialog("Findings", "Select a flow first.", width=400)
            return

        default_title = (
            f"{app.current_value('src_ip')} -> {app.current_value('dst_ip')} "
            f"({app.current_value('application_name')})"
        )
        title, ok = app._text_input_dialog("New finding", "Title:", text=default_title, width=480)
        if not ok:
            return
        title = (title or "").strip()
        if not title:
            return

        note, ok2 = app._multiline_input_dialog("New finding", "Note (optional):", width=480, height=260)
        if not ok2:
            note = ""

        tags, ok3 = app._text_input_dialog("New finding", "Tags (comma-separated, optional):", width=440)
        if not ok3:
            tags = ""
        tags = normalize_tags(tags)

        try:
            add_finding(app.current_project_id, app._current_flow, title=title, note=note, tags=tags)
        except Exception as e:
            app._message_dialog("Findings", "Failed to create finding.", str(e), width=460)
            return

        self.refresh_ui()
        app.notes_controller.refresh_activity_ui()
        app.tabs.setCurrentIndex(2)

    def mark_pcap_as_finding(self) -> None:
        app = self.app
        pcap_page = getattr(app, "pcap_page", None)
        if pcap_page is None:
            return

        if app.current_project_id is None:
            app._message_dialog("Findings", "Select an active project first (Projects -> Open).", width=460)
            return

        summary = getattr(pcap_page, "summary", None)
        if summary is None:
            app._message_dialog("Findings", "Open a PCAP file first.", width=400)
            return

        selected_row = getattr(pcap_page, "_selected_communication_row", None)
        if selected_row:
            flow = flow_from_communication_row(selected_row)
            default_title = default_communication_finding_title(selected_row)
            default_note = communication_finding_note(selected_row)
        else:
            period_label = ""
            if hasattr(pcap_page, "_active_period_title"):
                period_label = str(pcap_page._active_period_title() or "").strip()
            flow = flow_from_pcap_summary(summary)
            default_title = default_period_finding_title(summary, period_label=period_label)
            file_label = str(summary.file_name or summary.file_path or "").strip()
            default_note = period_finding_note(
                summary,
                period_label=period_label,
                file_label=file_label,
            )

        title, ok = app._text_input_dialog("New finding", "Title:", text=default_title, width=480)
        if not ok:
            return
        title = (title or "").strip()
        if not title:
            return

        note, ok2 = app._multiline_input_dialog(
            "New finding",
            "Note (optional):",
            text=default_note,
            width=480,
            height=260,
        )
        if not ok2:
            note = ""

        tags, ok3 = app._text_input_dialog("New finding", "Tags (comma-separated, optional):", width=440)
        if not ok3:
            tags = ""
        tags = normalize_tags(tags)

        try:
            add_finding(app.current_project_id, flow, title=title, note=note, tags=tags)
        except Exception as e:
            app._message_dialog("Findings", "Failed to create finding.", str(e), width=460)
            return

        self.refresh_ui()
        app.notes_controller.refresh_activity_ui()
        app.tabs.setCurrentIndex(2)

    def explain_selected(self) -> None:
        app = self.app
        fid, row = self.get_selected_row(self.selected_finding_id())
        if fid is None or row is None:
            app._message_dialog("AI Assistant", "Select a finding first.", width=400)
            return

        if app.ai_task_controller.is_busy():
            app._message_dialog("AI Assistant", "Another AI task is already running.", width=430)
            return

        app.txt_ai_summary.setPlainText("Generating AI finding explanation...")
        app.tabs.setCurrentIndex(0)
        app.btn_finding_ai.setEnabled(False)

        worker = AITextWorker(
            app.ai_service.explain_finding,
            dict(row),
        )
        app.ai_task_controller.start("finding", worker)

    def jump_to_selected(self) -> None:
        app = self.app
        fid, row = self.get_selected_row(self.selected_finding_id())
        if fid is None or row is None:
            return

        src = row["src_ip"]
        dst = row["dst_ip"]

        app.go_to_explore_flows()
        app.search.setText("")
        app.explore_ui_controller.leave_conversation(clear_search=False)
        app.explore_ui_controller.enter_conversation(src, dst)
        QTimer.singleShot(0, lambda: app.explore_ui_controller.select_flow_pair(src, dst))

    def edit_selected(self) -> None:
        app = self.app
        fid, row = self.get_selected_row(self.selected_finding_id())
        if fid is None or row is None:
            return

        values, ok = finding_details_dialog(
            app,
            title="Edit finding",
            finding=dict(row),
        )
        if not ok or not values:
            return
        title = str(values.get("title") or "").strip()
        if not title:
            return
        note = str(values.get("note") or "")
        status = str(values.get("status") or "New")
        tags = normalize_tags(str(values.get("tags") or ""))

        try:
            update_finding(fid, title=title, note=note, status=status, tags=tags)
        except Exception as e:
            app._message_dialog("Findings", "Failed to update finding.", str(e), width=460)
            return

        self.refresh_ui()
        app.notes_controller.refresh_activity_ui()
        app.findings_page.select_finding_by_id(fid)

    def delete_selected(self) -> None:
        app = self.app
        fid, row = self.get_selected_row(self.selected_finding_id())
        if fid is None or row is None:
            return

        title = row["title"] or "(no title)"
        src = f"{row['src_ip']}:{row['src_port'] or ''}"
        dst = f"{row['dst_ip']}:{row['dst_port'] or ''}"

        confirmed = app._confirm_dialog(
            title="Delete finding",
            message="Delete selected finding?",
            details=f"{title}\n{src} -> {dst}",
            ok_text="Delete",
            cancel_text="Cancel",
            width=430,
            destructive=True,
        )
        if not confirmed:
            return

        try:
            delete_finding(fid)
        except Exception as e:
            app._message_dialog("Findings", "Failed to delete finding.", str(e), width=460)
            return

        self.refresh_ui()
        app.notes_controller.refresh_activity_ui()

    def on_context_menu(self, pos) -> None:
        app = self.app
        fid = self.selected_finding_id()
        menu = QMenu(app)

        act_jump = menu.addAction("Jump to Flow (J)")
        act_edit = menu.addAction("Edit (E)")
        act_delete = menu.addAction("Delete (Del)")
        menu.addSeparator()
        act_new = menu.addAction("Set status: 🆕 New")
        act_inv = menu.addAction("Set status: 🟡 Investigating")
        act_conf = menu.addAction("Set status: ✅ Confirmed")
        act_fp = menu.addAction("Set status: ⚪ False Positive")

        if fid is None:
            for action in (act_jump, act_edit, act_delete, act_new, act_inv, act_conf, act_fp):
                action.setEnabled(False)

        chosen = menu.exec(app.findings_list.mapToGlobal(pos))
        if not chosen or fid is None:
            return

        if chosen == act_jump:
            self.jump_to_selected()
            return
        if chosen == act_edit:
            self.edit_selected()
            return
        if chosen == act_delete:
            self.delete_selected()
            return

        if chosen in (act_new, act_inv, act_conf, act_fp):
            status_map = {
                act_new: "New",
                act_inv: "Investigating",
                act_conf: "Confirmed",
                act_fp: "False Positive",
            }
            new_status = status_map[chosen]

            try:
                updated = update_finding_status(fid, new_status, app.current_project_id)
            except Exception as e:
                app._message_dialog("Findings", "Failed to update finding status.", str(e), width=460)
                return
            if not updated:
                return

            self.refresh_ui()
            app.notes_controller.refresh_activity_ui()
