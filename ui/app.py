import sys
import webbrowser
from core.ai.assistant_service import AIAssistantService, AISettings
from ui.registry_page import RegistryPage
from ui.listing_page import ListingPage
from ui.pcap_page import PcapPage
from ui.activity_profile_page import ActivityProfilePage
from ui.settings_page import SettingsPage
from pathlib import Path
from typing import Any
from ui.controllers.flow_controller import FlowController
from ui.controllers.findings_controller import FindingsController
from ui.controllers.search_controller import SearchController
from ui.controllers.projects_ui_controller import ProjectsUIController
from ui.controllers.ai_task_controller import AiTaskController
from ui.controllers.dataset_controller import DatasetController
from ui.controllers.explore_ui_controller import ExploreUIController
from ui.controllers.osint_ui_controller import OsintUIController
from ui.explore_widgets import AITextWorker
from ui.ai_output import AIOutputState, build_ai_output_state, render_ai_output_hub
from ui.notes_page import NotesPage
from ui.navigation import set_active_nav_button, switch_page
from ui.controllers.notes_controller import NotesController
from ui.dialogs import (
    message_dialog,
    choice_dialog,
    text_input_dialog,
    multiline_input_dialog,
    item_choice_dialog,
    confirm_dialog,
)
from PySide6.QtCore import Qt, QTimer, QThread
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtWidgets import (
    QApplication, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget,
    QTextEdit, QTabWidget, QLineEdit,
    QFrame
)
from core.db import (
    init_db,
    get_project,
    get_app_settings,
)
from ui.app_helpers import normalize_ui_theme
from ui.theme import apply_app_stylesheet, polish_combo_popups
from ui.app_sidebar import build_sidebar, wire_navigation
from ui.projects_page import build_projects_page
from ui.explore_page import build_explore_workspace
from ui.dataset_header_layout import DATASET_PAGE_SPACING
from ui.osint_page import build_osint_page
from ui.ai_hub_page import build_ai_hub_page
from ui.app_wiring import wire_app_ui
from ui.app_shortcuts import handle_app_key_press

# ---------- Main App ----------
class App(QWidget):
    def go_to_explore_flows(self):
        self.go_to_json_tab(0)
        self.tabs.setCurrentIndex(1)

    def go_to_notes(self):
        self.go_page(self.IDX_NOTES, self._nav_notes)

    def go_to_ai(self):
        self.go_page(self.IDX_AI, self._nav_ai)

    def go_to_json_tab(self, tab_index: int = 0):
        self.go_page(self.IDX_JSON, self._nav_json)
        if hasattr(self, "json_tabs"):
            self.json_tabs.setCurrentIndex(max(0, tab_index))
        controller = getattr(self, "dataset_controller", None)
        if controller is not None and getattr(controller, "_json_day_groups_raw", None):
            controller._sync_json_period_selector_panel()
            if not getattr(controller, "_json_day_groups", None):
                controller._rebuild_json_period_combo()

    def go_to_findings(self, *, pcap_filter: bool = False, from_pcap: bool = False) -> None:
        if from_pcap:
            self._remember_pcap_return_context()
        self.go_to_json_tab(0)
        if hasattr(self, "tabs"):
            self.tabs.setCurrentIndex(getattr(self, "IDX_FINDINGS_TAB", 2))
        if pcap_filter and hasattr(self, "txt_find_search"):
            self.txt_find_search.setText("PCAP")
        if hasattr(self, "findings_controller"):
            self.findings_controller.apply_filter()
            self.findings_controller.sync_pcap_back_button()

    def go_back_to_pcap(self) -> None:
        ctx = getattr(self, "_pcap_return_context", None)
        self._pcap_return_context = None
        self.go_page(self.IDX_PCAP, self._nav_pcap)
        pcap_page = getattr(self, "pcap_page", None)
        if pcap_page is not None and ctx and hasattr(pcap_page, "summary_tabs"):
            tab = int(ctx.get("summary_tab", 0))
            if 0 <= tab < pcap_page.summary_tabs.count():
                pcap_page.summary_tabs.setCurrentIndex(tab)
        if pcap_page is not None and hasattr(pcap_page, "refresh_current_view"):
            pcap_page.refresh_current_view()
        if hasattr(self, "findings_controller"):
            self.findings_controller.sync_pcap_back_button()
            self.findings_controller.refresh_pcap_findings_link()

    def _remember_pcap_return_context(self) -> None:
        pcap_page = getattr(self, "pcap_page", None)
        if pcap_page is None:
            self._pcap_return_context = None
            return
        summary_tab = 0
        if hasattr(pcap_page, "summary_tabs"):
            summary_tab = pcap_page.summary_tabs.currentIndex()
        self._pcap_return_context = {"summary_tab": summary_tab}

    def _build_sidebar(self) -> QFrame:
        return build_sidebar(self)

    def _wire_navigation(self) -> None:
        wire_navigation(self)

    def _wire_ui(self) -> None:
        wire_app_ui(self)

    def _open_from_registry_search(self, q: str):
        self.go_to_explore_flows()
        self.explore_ui_controller.leave_conversation(clear_search=False)
        self.search.setText(q or "")
        self.search.setFocus()
        self.explore_ui_controller.update_showing()
        
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ViaNyquist")
        self.setMinimumSize(1100, 700)
        self.resize(1200, 800)

        init_db()
        self.project_dir = Path(__file__).resolve().parent.parent
        self._init_state()

        self._shutdown_started = False
        self._profile_refresh_depth = 0
        self._profile_refresh_pending = False
        self._profile_refresh_pending_count = 0
        self.ai_service = AIAssistantService(
            AISettings.from_mapping(get_app_settings())
        )
        self.ai_task_controller = AiTaskController(self)
        self.notes_controller = NotesController(self)
        self.flow_controller = FlowController()
        self.findings_controller = FindingsController(self)
        self.search_controller = SearchController(self)
        self.projects_ui_controller = ProjectsUIController(self)
        self.dataset_controller = DatasetController(self)
        self.explore_ui_controller = ExploreUIController(self)
        self.osint_ui_controller = OsintUIController(self)

        self._notes_timer.timeout.connect(self.notes_controller.flush)
        self._search_timer.timeout.connect(self.search_controller.apply_search_filter)        

        self._build_ui()
        self._wire_ui()

        # init
        self.projects_ui_controller.refresh_projects()
        self.explore_ui_controller.update_detail(None)
        self.explore_ui_controller.update_mode_label()
        self.findings_controller.refresh_ui()
        self.notes_controller.refresh_ui()
        polish_combo_popups(self, get_app_settings().get("ui.theme", "dark"))
        
    def _message_dialog(
        self,
        title: str,
        message: str,
        details: str = "",
        width: int = 380,
    ) -> None:
        return message_dialog(
            self,
            title,
            message,
            details=details,
            width=width,
        )

    def _choice_dialog(
        self,
        title: str,
        message: str,
        choices: list[str],
        width: int = 480,
    ):
        return choice_dialog(
            self,
            title,
            message,
            choices,
            width=width,
        )

    def _text_input_dialog(
        self,
        title: str,
        label: str,
        text: str = "",
        width: int = 420,
    ):
        return text_input_dialog(
            self,
            title,
            label,
            text=text,
            width=width,
        )

    def _multiline_input_dialog(
        self,
        title: str,
        label: str,
        text: str = "",
        width: int = 480,
        height: int = 260,
    ):
        return multiline_input_dialog(
            self,
            title,
            label,
            text=text,
            width=width,
            height=height,
        )

    def _item_choice_dialog(
        self,
        title: str,
        label: str,
        items: list[str],
        current_index: int = 0,
        width: int = 420,
    ):
        return item_choice_dialog(
            self,
            title,
            label,
            items,
            current_index=current_index,
            width=width,
        )
    def open_user_manual(self):
        docs_dir = self.project_dir / "docs"
        candidates = (
            docs_dir / "USER_GUIDE_EN.html",
            docs_dir / "USER_GUIDE.html",
            docs_dir / "USER_GUIDE_EN.md",
        )
        for manual_path in candidates:
            if manual_path.exists():
                webbrowser.open(manual_path.resolve().as_uri())
                return

        self._message_dialog(
            "Help",
            "User manual not found.",
            "Expected one of:\n"
            "- docs/USER_GUIDE_EN.html\n"
            "- docs/USER_GUIDE.html\n"
            "- docs/USER_GUIDE_EN.md",
            width=460,
        )

    def _confirm_dialog(
        self,
        title: str,
        message: str,
        details: str = "",
        ok_text: str = "OK",
        cancel_text: str = "Cancel",
        width: int = 420,
        destructive: bool = False,
    ) -> bool:
        return confirm_dialog(
            self,
            title,
            message,
            details=details,
            ok_text=ok_text,
            cancel_text=cancel_text,
            width=width,
            destructive=destructive,
        )

    def _init_state(self) -> None:
        # State
        self.current_project_id: int | None = None
        self.current_project_name: str = ""
        self.current_folder: Path | None = None        
        
        self._current_flow: dict[str, Any] | None = None
        self._conversation_on = False
        self._flows_expanded = False

        # Paging
        self.PAGE_SIZE = 2000

        # Notes autosave
        self._notes_dirty = False
        self._notes_timer = QTimer(self)
        self._notes_timer.setSingleShot(True)

        # Explore search debounce
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)

        # AI background worker
        self._ai_thread: QThread | None = None
        self._ai_worker: AITextWorker | None = None
        self._ai_mode: str | None = None
        self._ai_output_state = AIOutputState()
        self._pcap_return_context: dict[str, int] | None = None

    def _build_osint_page(self) -> QWidget:
        return build_osint_page(self)

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 8, 8, 4)
        outer.setSpacing(4)

        root = QHBoxLayout()

        # Sidebar
        sidebar = self._build_sidebar()

        # Pages + indexes
        self.pages = QStackedWidget()
        self.IDX_PROJECTS = 0
        self.IDX_PROFILE = 1
        self.IDX_NOTES = 2
        self.IDX_AI = 3
        self.IDX_JSON = 4
        # Explore, Registry, and Listing share one stacked page (IDX_JSON).
        self.IDX_EXPLORE = self.IDX_JSON
        self.IDX_REGISTRY = self.IDX_JSON
        self.IDX_LISTING = self.IDX_JSON
        self.IDX_PCAP = 5
        self.IDX_OSINT = 6
        self.IDX_SETTINGS = 7

        projects_page = build_projects_page(self)

        explore_container, header_card = build_explore_workspace(self)

        # Notes page
        self.notes_page = NotesPage(self)
        self.txt_notes = self.notes_page.editor
        self.notes_page.btn_insert_chart.clicked.connect(self.notes_controller.insert_chart)
        self.notes_page.btn_export_word.clicked.connect(self.notes_controller.export_word)
        self.notes_page.btn_export_html.clicked.connect(self.notes_controller.export_html)
        self.notes_page.btn_export_pdf.clicked.connect(self.notes_controller.export_pdf)

        ai_page = build_ai_hub_page(self)

        # Pages
        self.pages.addWidget(projects_page)

        self.activity_profile_page = ActivityProfilePage(self)
        self.pages.addWidget(self.activity_profile_page)

        self.pages.addWidget(self.notes_page)
        self.pages.addWidget(ai_page)

        json_page = QWidget()
        json_layout = QVBoxLayout(json_page)
        json_layout.setContentsMargins(0, 0, 0, 0)
        json_layout.setSpacing(DATASET_PAGE_SPACING)
        self.json_tabs = QTabWidget()
        self.json_tabs.setDocumentMode(True)
        self.json_tabs.addTab(explore_container, "Explore")

        self.registry_page = RegistryPage(self)
        self.json_tabs.addTab(self.registry_page, "Registry")

        self.listing_page = ListingPage(self)
        self.json_tabs.addTab(self.listing_page, "Listing")

        json_layout.addWidget(header_card)
        json_layout.addWidget(self.json_tabs, 1)
        self.pages.addWidget(json_page)

        self.pcap_page = PcapPage(self)
        self.pages.addWidget(self.pcap_page)

        self.osint_page = self._build_osint_page()
        self.pages.addWidget(self.osint_page)

        self.settings_page = SettingsPage(self)
        self.pages.addWidget(self.settings_page)

        self.pages.setCurrentIndex(self.IDX_PROJECTS)
        set_active_nav_button(self._nav_buttons, self._nav_projects)

        root.addWidget(sidebar)
        root.addWidget(self.pages, 1)
        outer.addLayout(root, 1)

        # footer
        footer = QHBoxLayout()
        footer.addStretch()
        self.lbl_signature = QLabel("by _Igy_")
        self.lbl_signature.setObjectName("Signature")
        footer.addWidget(self.lbl_signature)
        outer.addLayout(footer)
          
    def _set_active_nav(self, active: QPushButton):
        set_active_nav_button(self._nav_buttons, active)

    def go_page(self, idx: int, active_btn: QPushButton):
        switch_page(
            pages=self.pages,
            index=idx,
            active_button=active_btn,
            nav_buttons=self._nav_buttons,
            before_switch=self._before_page_switch,
        )

    def _before_page_switch(self, idx: int) -> None:
        if idx == self.IDX_PROFILE:
            self.refresh_activity_profile_ui()
        if idx == self.IDX_OSINT and hasattr(self, "osint_ui_controller"):
            self.osint_ui_controller.refresh()
        if idx == self.IDX_SETTINGS and hasattr(self, "settings_page"):
            self.settings_page.refresh()

    def refresh_activity_profile_ui(self):
        if not hasattr(self, "activity_profile_page"):
            return
        if self._profile_refresh_depth:
            if self._profile_refresh_pending_count < 3:
                self._profile_refresh_pending = True
            return
        self._profile_refresh_depth += 1
        try:
            quick = False
            if hasattr(self, "dataset_controller"):
                quick = self.dataset_controller.should_defer_profile_heavy_work()
            self.activity_profile_page.refresh(
                self.current_project_id,
                self.current_project_name,
                quick=quick,
            )
        finally:
            self._profile_refresh_depth -= 1
            if self._profile_refresh_pending and not self._profile_refresh_depth:
                self._profile_refresh_pending = False
                self._profile_refresh_pending_count += 1
                if self._profile_refresh_pending_count <= 3:
                    QTimer.singleShot(0, self.refresh_activity_profile_ui)
                else:
                    self._profile_refresh_pending_count = 0

    def refresh_all_views(self):
        self.notes_controller.flush()
        if hasattr(self, "pcap_page"):
            self.pcap_page.refresh_current_view()

        active_project_id = self.current_project_id
        self.projects_ui_controller.refresh_projects()

        project = get_project(active_project_id) if active_project_id is not None else None
        if active_project_id is not None and not project:
            self.projects_ui_controller._clear_active_project()
            active_project_id = None
            project = None

        if active_project_id is None:
            self.dataset_controller.reset_dataset_views()
            self.findings_controller.refresh_ui()
            self.notes_controller.refresh_ui()
            self.refresh_activity_profile_ui()
            if hasattr(self, "osint_ui_controller"):
                self.osint_ui_controller.refresh()
            if hasattr(self, "settings_page"):
                self.settings_page.refresh()
            self._message_dialog(
                "Refresh All",
                "Application views refreshed.",
                "No active project — dataset views were cleared.",
                width=460,
            )
            return

        self.projects_ui_controller.set_active_project(active_project_id)
        for i in range(self.projects_list.count()):
            item = self.projects_list.item(i)
            if int(item.data(Qt.UserRole)) == active_project_id:
                self.projects_list.setCurrentItem(item)
                break
        self.projects_ui_controller.refresh_recent_datasets(active_project_id)
        self.projects_ui_controller.refresh_case_dashboard()

        self.findings_controller.refresh_ui()
        self.notes_controller.refresh_ui()
        self.refresh_activity_profile_ui()
        if hasattr(self, "osint_ui_controller"):
            self.osint_ui_controller.refresh()

        if hasattr(self, "settings_page"):
            self.settings_page.refresh()

        self._message_dialog(
            "Refresh All",
            "Application views refreshed.",
            "Refreshed projects, project dashboard, recent datasets, notes, findings, activity profile, PCAP view and settings.",
            width=460,
        )

    def open_leaks_viewer(
        self,
        *,
        search_text: str = "",
        record_ids: list[int] | None = None,
    ) -> None:
        from ui.leaks_viewer import LeaksViewerDialog

        viewer = getattr(self, "_leaks_viewer", None)
        if viewer is None:
            viewer = LeaksViewerDialog(self)
            self._leaks_viewer = viewer
        else:
            viewer.refresh_datasets()
        query = str(search_text or "").strip()
        pinned_ids = [int(value) for value in (record_ids or []) if int(value) > 0]
        viewer._pinned_record_ids = []
        if pinned_ids:
            viewer.set_pinned_record_ids(pinned_ids)
        elif query:
            viewer.edit_search.setText(query)
            if viewer.list_datasets.count() > 0:
                viewer.list_datasets.setCurrentRow(0)
                viewer._update_dataset_label()
                viewer._update_visible_columns()
            viewer._run_search(reset=True)
        viewer.show()
        viewer.raise_()
        viewer.activateWindow()
        if not pinned_ids and not query:
            viewer._run_search(reset=True)

    def apply_theme(self, theme: str | None) -> None:
        qapp = QApplication.instance()
        if qapp is not None:
            normalized = normalize_ui_theme(theme)
            apply_app_stylesheet(qapp, normalized)
            polish_combo_popups(self, normalized)

    def _open_from_registry(self, src: str, dst: str):
        self.go_to_explore_flows()
        self.search.setText("")
        self.explore_ui_controller.enter_conversation(src, dst)

    def keyPressEvent(self, event):
        if not handle_app_key_press(self, event):
            super().keyPressEvent(event)

    def publish_ai_output(self, source: str, title: str, text: str) -> None:
        self._ai_output_state = build_ai_output_state(source, title, text)
        render_ai_output_hub(
            state=self._ai_output_state,
            project_name=self.current_project_name,
            title_label=getattr(self, "lbl_ai_hub_title", None),
            context_label=getattr(self, "lbl_ai_hub_context", None),
            text_edit=getattr(self, "txt_ai_hub", None),
            add_notes_button=getattr(self, "btn_ai_hub_add_notes", None),
        )
        project_id = self.current_project_id
        if project_id is not None and (text or "").strip():
            try:
                from core.db import save_ai_output

                save_ai_output(
                    int(project_id),
                    source=source,
                    title=title,
                    body_text=text,
                )
            except Exception:
                pass
        self.go_to_ai()

    def show_ai_output_history(self) -> None:
        from ui.ai_output import open_ai_history_dialog

        open_ai_history_dialog(self)

    def load_ai_output_record(self, output_id: int) -> None:
        from core.db import get_ai_output

        record = get_ai_output(int(output_id))
        if record is None:
            self._message_dialog("AI history", "That saved AI output is no longer available.", width=440)
            return
        if self.current_project_id is not None and int(record.get("project_id") or 0) != int(self.current_project_id):
            self._message_dialog("AI history", "That AI output belongs to a different project.", width=440)
            return
        self._ai_output_state = build_ai_output_state(
            str(record.get("source") or ""),
            str(record.get("title") or ""),
            str(record.get("body_text") or ""),
        )
        render_ai_output_hub(
            state=self._ai_output_state,
            project_name=self.current_project_name,
            title_label=getattr(self, "lbl_ai_hub_title", None),
            context_label=getattr(self, "lbl_ai_hub_context", None),
            text_edit=getattr(self, "txt_ai_hub", None),
            add_notes_button=getattr(self, "btn_ai_hub_add_notes", None),
        )
        self.go_to_ai()

    def add_ai_hub_to_notes(self):
        text = (self._ai_output_state.text or "").strip()
        if not text:
            self._message_dialog("Notes", "There is no AI-generated text to add.", width=440)
            return
        self.add_ai_text_to_notes(text)

    def add_ai_text_to_notes(self, text: str) -> bool:
        return self.notes_controller.append_ai_text(text)

    def add_ai_summary_to_notes(self):
        text = (self.txt_ai_summary.toPlainText() or "").strip()
        if not text:
            self._message_dialog("Notes", "There is no AI-generated text to add.", width=440)
            return

        self.add_ai_text_to_notes(text)

    def copy_text(self, text: str):
        if text:
            QGuiApplication.clipboard().setText(text)

    def current_value(self, key: str) -> str:
        if not self._current_flow:
            return ""
        v = self._current_flow.get(key, "")
        return "" if v is None else str(v)

    def shutdown_background_tasks(self, wait_ms: int = 5000) -> None:
        if self._shutdown_started:
            return
        self._shutdown_started = True
        self.ai_task_controller.shutdown(wait_ms=wait_ms)
        self.dataset_controller.shutdown_background_tasks(wait_ms=wait_ms)
        if hasattr(self, "pcap_page"):
            self.pcap_page.shutdown_background_tasks(wait_ms=wait_ms)
        if hasattr(self, "activity_profile_page"):
            self.activity_profile_page.shutdown_background_tasks(wait_ms=wait_ms)
        if hasattr(self, "osint_ui_controller"):
            self.osint_ui_controller.shutdown(wait_ms=wait_ms)

    def closeEvent(self, event):
        self.shutdown_background_tasks()
        super().closeEvent(event)
    
def main():
    from ui.crash_logging import install_crash_logging

    install_crash_logging()

    app = QApplication(sys.argv)

    init_db()
    apply_app_stylesheet(app, get_app_settings().get("ui.theme", "dark"))

    base_dir = Path(__file__).resolve().parent          
    project_dir = base_dir.parent                       
    icon_path = project_dir / "assets" / "ViaNyquist.ico"

    icon = QIcon(str(icon_path))

    app.setWindowIcon(icon)   # global (taskbar + dialogs)
    w = App()
    w.setWindowIcon(icon)     # explicit on main window
    w.showMaximized()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
