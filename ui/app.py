import sys
import webbrowser
from core.ai.assistant_service import AIAssistantService, AISettings
import ipaddress
from ui.registry_page import RegistryPage
from ui.listing_page import ListingPage
from ui.pcap_page import DictTableModel, PcapPage
from ui.activity_profile_page import ActivityProfilePage
from ui.settings_page import SettingsPage
import html
from pathlib import Path
from typing import Any, Callable
from ui.controllers.flow_controller import FlowController
from ui.controllers.findings_controller import FindingsController
from ui.controllers.search_controller import SearchController
from ui.controllers.projects_ui_controller import ProjectsUIController
from ui.controllers.dataset_controller import DatasetController
from ui.controllers.explore_ui_controller import ExploreUIController
from core.analysis_limits import (
    EMBEDDED_SUMMARY_TOP_N,
    SUMMARY_CARD_HEIGHT,
    SUMMARY_CARD_PADDING,
    SUMMARY_CARD_WIDTH,
    SUMMARY_CARDS_WRAP_HEIGHT,
    SUMMARY_CARDS_WRAP_WIDTH,
    SUMMARY_VALUE_COL_WIDTH,
)

from ui.explore_models import FlowTableModel, NumericSortProxy
from ui.explore_widgets import AITextWorker, CopyableTableView, FlowTableView
from ui.ai_output import AIOutputState, build_ai_output_state, make_ai_note_block, render_ai_output_hub
from ui.findings_format import format_finding_detail, update_finding_status
from ui.findings_page import FindingsPage
from ui.notes_actions import (
    export_notes_html_action,
    export_notes_pdf as export_notes_pdf_action,
    export_notes_word as export_notes_word_action,
    insert_notes_chart as insert_notes_chart_action,
    load_project_notes,
    save_project_notes,
)
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
from PySide6.QtGui import QGuiApplication, QIcon, QFont, QPixmap
from PySide6.QtWidgets import (
    QApplication, QWidget, QHBoxLayout, QVBoxLayout, QGridLayout,
    QPushButton, QLabel, QStackedWidget,
    QTextEdit, QTabWidget, QLineEdit,
    QSplitter, QGroupBox,
    QListWidget,
    QAbstractItemView, QComboBox, QDialog, QFrame, QSizePolicy, QScrollArea, QHeaderView,
    QTableView, QMenu
)
from core.db import (
    init_db, add_finding,
    update_finding, delete_finding,
    get_project,
    get_app_settings,
)
# ---------- helpers ----------
def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def status_emoji(status: str) -> str:
    s = (status or "").strip() or "New"
    return {"New": "🆕", "Investigating": "🟡", "Confirmed": "✅", "False Positive": "⚪"}.get(s, "🆕")

def normalize_tags(tags: str) -> str:
    # keep it simple: comma-separated, trim, remove empties, keep order, avoid duplicates
    raw = (tags or "").strip()
    if not raw:
        return ""
    parts = []
    seen = set()
    for p in raw.replace(";", ",").split(","):
        t = p.strip()
        if not t:
            continue
        if t.lower() in seen:
            continue
        seen.add(t.lower())
        parts.append(t)
    return ", ".join(parts)

def normalize_ui_theme(value: str | None) -> str:
    theme = (value or "dark").strip().lower()
    return theme if theme in {"dark", "light"} else "dark"

LIGHT_THEME_OVERRIDES = """
QWidget {
    background: #f4f7fb;
    color: #111827;
}

QLabel {
    background: transparent;
    color: #111827;
}

QFrame#Card,
QFrame#ProfileHero,
QFrame#ProfilePanel,
QFrame#ExploreHeaderCard,
QFrame#ListingHeaderCard,
QFrame#CaseDashboardCompact,
QFrame#PanelCard,
QFrame#FlowDetailsCard,
QFrame#FlowToolbarCard,
QFrame#NotesEditorPanel,
QFrame#NotesEditorContent,
QFrame#NotesListPanel,
QFrame#NotesPreviewPanel,
QFrame#PcapInvestigatorCard,
QGroupBox {
    background: #ffffff;
    border-color: #cbd5e1;
}

QFrame#Card QLabel,
QFrame#ProfileHero QLabel,
QFrame#ProfilePanel QLabel,
QFrame#ExploreHeaderCard QLabel,
QFrame#ListingHeaderCard QLabel,
QFrame#CaseDashboardCompact QLabel,
QFrame#PanelCard QLabel,
QFrame#PcapInvestigatorCard QLabel,
QFrame#FlowToolbarCard QLabel,
QFrame#NotesEditorPanel QLabel,
QFrame#NotesEditorContent QLabel,
QFrame#NotesListPanel QLabel,
QFrame#NotesPreviewPanel QLabel,
QGroupBox QLabel {
    background: transparent;
    color: #111827;
}

QLabel#H1,
QLabel#SectionTitle,
QLabel#ProfileTitle,
QLabel#ProfilePanelTitle,
QLabel#CaseDashboardTitle,
QLabel#HeaderProjectLabel,
QLabel#DialogMessageLabel,
QLabel#DialogSectionLabel {
    background: transparent;
    color: #0f172a;
}

QLabel#Muted,
QLabel#ProfileSubtitle,
QLabel#HeaderPathLabel,
QLabel#HeaderStatLabel,
QLabel#PcapKeyPoints,
QLabel#PcapLimitations,
QLabel#FlowFieldLabel,
QLabel#MutedLabel,
QLabel#DialogDetailsLabel {
    background: transparent;
    color: #475569;
}

QLabel#PcapPlainSummary {
    background: transparent;
    color: #111827;
}

QLabel#PcapLoadingStatus {
    background: transparent;
    color: #16a34a;
}

QLabel#ProfileMetric,
QLabel#CaseMetricCompact {
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    color: #0f172a;
}

QFrame#ProfileCountRow {
    background: #f8fafc;
    border-color: #cbd5e1;
}

QLabel#ProfileCountBadge {
    background: #3b82f6;
    color: #ffffff;
}

QLabel#RegistryStrongTitle {
    background: transparent;
    color: #0f172a;
}

QLabel#RegistryMetricValue {
    background: transparent;
    color: #0f172a;
}

QLabel#RegistryDeviationLabel {
    background: transparent;
    color: #334155;
}

QLabel#RegistryBodyText,
QLabel#RegistrySmallTitle {
    background: transparent;
    color: #475569;
}

QProgressBar#RegistryDeviationBar {
    background: #e2e8f0;
    border: 1px solid #cbd5e1;
    color: #0f172a;
}

QProgressBar#RegistryDeviationBar::chunk {
    background: #3b82f6;
}

QLineEdit,
QTextEdit,
QPlainTextEdit,
QComboBox,
QListWidget,
QTableView {
    background: #ffffff;
    color: #111827;
    border-color: #cbd5e1;
}

QTextEdit#SummaryTextBox,
QPlainTextEdit#SummaryTextBox {
    background: transparent;
    color: #334155;
    border: none;
}

QLineEdit:focus,
QTextEdit:focus,
QPlainTextEdit:focus,
QComboBox:focus {
    border-color: #2563eb;
}

QComboBox QAbstractItemView {
    background: #ffffff;
    color: #111827;
    selection-background-color: #3b82f6;
    selection-color: #ffffff;
}

QTabWidget::pane {
    background: #ffffff;
    border-color: #cbd5e1;
}

QTabBar::tab {
    background: #e2e8f0;
    border-color: #cbd5e1;
    color: #334155;
}

QTabBar::tab:hover {
    background: #dbeafe;
    color: #0f172a;
}

QTabBar::tab:selected {
    background: #ffffff;
    color: #0f172a;
}

QHeaderView::section {
    background: #e2e8f0;
    color: #111827;
    border-color: #cbd5e1;
}

QTableView {
    alternate-background-color: #f1f5f9;
    gridline-color: #cbd5e1;
    selection-background-color: #3b82f6;
    selection-color: #ffffff;
}

QTableView QTableCornerButton::section {
    background: #e2e8f0;
    border: 1px solid #cbd5e1;
}

QPushButton {
    background: #ffffff;
    color: #111827;
    border-color: #cbd5e1;
}

QPushButton:hover {
    background: #e2e8f0;
}

QPushButton#NavButton {
    background: transparent;
    color: #111827;
    border: none;
}

QFrame#SidebarFrame {
    background: transparent;
    border-right: 1px solid #cbd5e1;
}

QPushButton#NavButton:hover {
    background: #e2e8f0;
    border: 1px solid #cbd5e1;
}

QPushButton#NavButton[active="true"] {
    background: #3b82f6;
    color: #ffffff;
}

QPushButton#Primary {
    background: #3b82f6;
    border-color: #3b82f6;
    color: #ffffff;
}

QProgressBar {
    background: #e2e8f0;
    border-color: #cbd5e1;
}

QProgressBar::chunk {
    background: #3b82f6;
}

QScrollArea,
QScrollArea QWidget {
    background: transparent;
}

QSplitter::handle {
    background: #cbd5e1;
}

QSplitter::handle:hover {
    background: #94a3b8;
}

QScrollBar:vertical,
QScrollBar:horizontal {
    background: #f1f5f9;
    border: 1px solid #cbd5e1;
    margin: 0;
}

QScrollBar::handle:vertical,
QScrollBar::handle:horizontal {
    background: #cbd5e1;
    border-radius: 4px;
    min-height: 24px;
    min-width: 24px;
}

QScrollBar::handle:vertical:hover,
QScrollBar::handle:horizontal:hover {
    background: #94a3b8;
}

QScrollBar::add-line,
QScrollBar::sub-line,
QScrollBar::add-page,
QScrollBar::sub-page {
    background: transparent;
    border: none;
}

QFrame#FlowToolbarCard,
QGroupBox#SummaryCard,
QGroupBox#FlowDetailsCard,
QFrame#NotesEditorPanel,
QFrame#ListingHeaderCard {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    color: #111827;
}

QGroupBox::title,
QGroupBox#SummaryCard::title,
QGroupBox#FlowDetailsCard::title {
    background: #ffffff;
    color: #0f172a;
}

QFrame#PcapInvestigatorCard {
    border: 1px solid #60a5fa;
}

QLabel#FlowFieldValue {
    background: #f8fafc;
    border: 1px solid #cbd5e1;
    color: #111827;
}

QLabel#Signature {
    color: #64748b;
}

QPushButton:disabled {
    background: #f1f5f9;
    border-color: #d7dee9;
    color: #94a3b8;
}

QPushButton#NotesToolButton,
QPushButton#NotesColorButton {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    color: #111827;
}

QPushButton#NotesColorButton {
    color: #ef4444;
}

QPushButton#NotesToolButton:hover,
QPushButton#NotesColorButton:hover {
    background: #e2e8f0;
}

QPushButton#NotesToolButton:checked {
    background: #3b82f6;
    border-color: #2563eb;
    color: #ffffff;
}

QLabel#NotesPanelLabel {
    color: #475569;
}

QSpinBox {
    background: #ffffff;
    color: #111827;
    border: 1px solid #cbd5e1;
    border-radius: 10px;
    padding: 6px 8px;
    selection-background-color: #3b82f6;
    selection-color: #ffffff;
}

QSpinBox:focus {
    border-color: #2563eb;
}

QCheckBox {
    color: #111827;
}

QCheckBox::indicator {
    border: 1px solid #94a3b8;
    background: #ffffff;
}

QCheckBox::indicator:hover {
    border-color: #2563eb;
    background: #eff6ff;
}

QCheckBox::indicator:checked {
    border-color: #2563eb;
    background: #3b82f6;
}

QTableView::item {
    color: #111827;
}

QTableView::item:selected {
    background: #3b82f6;
    color: #ffffff;
}

QListWidget::item {
    color: #111827;
}

QListWidget::item:hover {
    background: #e2e8f0;
}

QListWidget::item:selected {
    background: #3b82f6;
    color: #ffffff;
}

QMenu,
QDialog,
QMessageBox,
QInputDialog,
QFileDialog {
    background: #f8fafc;
    color: #111827;
}

QMenu::item:selected {
    background: #3b82f6;
    color: #ffffff;
}

QDialog QLabel,
QMessageBox QLabel,
QInputDialog QLabel {
    background: transparent;
    color: #111827;
}

QDialog QLineEdit,
QDialog QPlainTextEdit,
QDialog QComboBox {
    background: #ffffff;
    border-color: #cbd5e1;
    color: #111827;
}
"""

def app_stylesheet(theme: str | None = "dark") -> str:
    qss_path = Path(__file__).resolve().parent / "style.qss"
    if not qss_path.exists():
        return ""
    qss = qss_path.read_text(encoding="utf-8")
    if normalize_ui_theme(theme) == "light":
        qss += "\n\n/* light theme overrides */\n" + LIGHT_THEME_OVERRIDES
    return qss

def apply_app_stylesheet(qapp: QApplication, theme: str | None = "dark") -> None:
    normalized_theme = normalize_ui_theme(theme)
    qapp.setProperty("ui_theme", normalized_theme)
    qapp.setStyleSheet(app_stylesheet(normalized_theme))

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

    def _build_sidebar(self) -> QFrame:
        sidebar_frame = QFrame()
        sidebar_frame.setObjectName("SidebarFrame")
        sidebar_frame.setFixedWidth(220)
        sidebar = QVBoxLayout(sidebar_frame)
        sidebar.setContentsMargins(0, 0, 12, 0)
        sidebar.setSpacing(8)

        self.btn_nav_projects = QPushButton("Projects")
        self.btn_nav_json = QPushButton("JSON")
        self.btn_nav_pcap = QPushButton("PCAP")
        self.btn_nav_osint = QPushButton("OSINT")
        self.btn_nav_ai = QPushButton("AI output")
        self.btn_nav_notes = QPushButton("Notes")
        self.btn_nav_profile = QPushButton("Profile")
        self.btn_global_refresh = QPushButton("Refresh")
        self.btn_nav_settings = QPushButton("Settings")
        self.btn_nav_help = QPushButton("Help")

        for b in (
            self.btn_nav_projects,
            self.btn_nav_json,
            self.btn_nav_pcap,
            self.btn_nav_osint,
            self.btn_nav_ai,
            self.btn_nav_notes,
            self.btn_nav_profile,
            self.btn_global_refresh,
            self.btn_nav_settings,
            self.btn_nav_help,
        ):
            b.setObjectName("NavButton")
            b.setFixedHeight(40)
        self.btn_global_refresh.setToolTip("Refresh projects, notes, findings, profile, PCAP view and settings.")

        # activ button reference (for highlight)
        self._nav_projects = self.btn_nav_projects
        self._nav_profile = self.btn_nav_profile
        self._nav_notes = self.btn_nav_notes
        self._nav_ai = self.btn_nav_ai
        self._nav_json = self.btn_nav_json
        self._nav_explore = self.btn_nav_json
        self._nav_registry = self.btn_nav_json
        self._nav_listing = self.btn_nav_json
        self._nav_pcap = self.btn_nav_pcap
        self._nav_osint = self.btn_nav_osint
        self._nav_settings = self.btn_nav_settings
        self._nav_buttons = (
            self._nav_projects,
            self._nav_json,
            self._nav_pcap,
            self._nav_osint,
            self._nav_ai,
            self._nav_notes,
            self._nav_profile,
            self._nav_settings,
        )

        sidebar.addWidget(self.btn_nav_projects)
        sidebar.addWidget(self.btn_nav_json)
        sidebar.addWidget(self.btn_nav_pcap)
        sidebar.addWidget(self.btn_nav_osint)
        sidebar.addWidget(self.btn_nav_ai)
        sidebar.addWidget(self.btn_nav_notes)
        sidebar.addWidget(self.btn_nav_profile)
        sidebar.addStretch()
        sidebar.addWidget(self.btn_global_refresh)
        sidebar.addWidget(self.btn_nav_settings)
        sidebar.addWidget(self.btn_nav_help)

        return sidebar_frame

    def _wire_navigation(self) -> None:
        self.btn_nav_projects.clicked.connect(lambda: self.go_page(self.IDX_PROJECTS, self._nav_projects))
        self.btn_nav_profile.clicked.connect(lambda: self.go_page(self.IDX_PROFILE, self._nav_profile))
        self.btn_nav_notes.clicked.connect(self.go_to_notes)
        self.btn_nav_ai.clicked.connect(self.go_to_ai)
        self.btn_nav_json.clicked.connect(lambda: self.go_to_json_tab(0))
        self.btn_global_refresh.clicked.connect(self.refresh_all_views)
        self.btn_nav_pcap.clicked.connect(lambda: self.go_page(self.IDX_PCAP, self._nav_pcap))
        self.btn_nav_osint.clicked.connect(lambda: self.go_page(self.IDX_OSINT, self._nav_osint))
        self.btn_nav_settings.clicked.connect(lambda: self.go_page(self.IDX_SETTINGS, self._nav_settings))
        self.btn_nav_help.clicked.connect(self.open_user_manual)

    def _wire_ui(self) -> None:
        # 1) sidebar navigation
        self._wire_navigation()

        # 3) Explore - search filter (debounced)
        self.search.textChanged.connect(self.search_controller.schedule_search_filter)

        # 4) Explore - table selection -> details
        self.table.selectionModel().selectionChanged.connect(self.explore_ui_controller.on_row_selected)

        # 5) Explore - scrolling auto paging
        self.table.verticalScrollBar().valueChanged.connect(self.explore_ui_controller.on_table_scrolled)

        # 6) Paging controls
        self.btn_load_more.clicked.connect(self.explore_ui_controller.load_next_page)
        self.cmb_page_size.currentTextChanged.connect(self.explore_ui_controller.on_page_size_changed)
        self.cmb_json_day.currentIndexChanged.connect(self.dataset_controller.on_json_day_changed)

        # 7) Explore actions
        self.btn_load.clicked.connect(self.dataset_controller.load_dataset_dialog)
        self.btn_ai_summary.clicked.connect(self.explore_ui_controller.generate_ai_summary)
        self.btn_add_ai_to_notes.clicked.connect(self.add_ai_summary_to_notes)
        self.btn_toggle_conv.clicked.connect(self.explore_ui_controller.toggle_conversation)
        self.btn_expand_flows.clicked.connect(self.explore_ui_controller.toggle_flows_expanded)
        self.btn_mark_finding.clicked.connect(self.mark_as_finding)

        # 8) AI explain flow
        self.btn_ai_explain.clicked.connect(self.explore_ui_controller.explain_selected_flow)
        
        # 9) Filter buttons
        self.btn_filter_src.clicked.connect(
            lambda: self.explore_ui_controller.apply_filter_ip(self.current_value("src_ip"))
        )
        self.btn_filter_dst.clicked.connect(
            lambda: self.explore_ui_controller.apply_filter_ip(self.current_value("dst_ip"))
        )
        self.btn_filter_sni.clicked.connect(
            lambda: self.explore_ui_controller.apply_filter_ip(self.current_value("requested_server_name"))
        )

        # 10) Projects page
        self.btn_new_project.clicked.connect(self.projects_ui_controller.create_project_dialog)
        self.btn_refresh_projects.clicked.connect(self.projects_ui_controller.refresh_projects)
        self.btn_open_project.clicked.connect(self.projects_ui_controller.open_selected_project)
        self.btn_edit_project.clicked.connect(self.projects_ui_controller.edit_selected_project)
        self.btn_delete_project.clicked.connect(self.projects_ui_controller.delete_selected_project)
        self.projects_list.itemSelectionChanged.connect(self.projects_ui_controller.on_project_selected_preview)
        self.btn_open_new_dataset.clicked.connect(self.projects_ui_controller.open_new_dataset)

        # 10b) Double click shortcuts
        self.projects_list.itemDoubleClicked.connect(lambda _: self.projects_ui_controller.open_selected_project())

        # 11) Findings page
        fp = self.findings_page

        fp.selectionChanged.connect(self.on_finding_selected)
        fp.jumpRequested.connect(self.jump_to_selected_finding)
        fp.editRequested.connect(self.edit_selected_finding)
        fp.deleteRequested.connect(self.delete_selected_finding)
        fp.aiRequested.connect(self.explain_selected_finding)
        fp.doubleClickedFinding.connect(self.jump_to_selected_finding)

        fp.btn_find_clear.clicked.connect(self.clear_findings_filters)
        fp.cmb_find_status.currentTextChanged.connect(self.apply_findings_filter)
        fp.cmb_find_sort.currentTextChanged.connect(self.apply_findings_filter)
        fp.txt_find_search.textChanged.connect(self.apply_findings_filter)
        fp.txt_find_tag.textChanged.connect(self.apply_findings_filter)
        fp.contextMenuRequestedFromList.connect(self.on_findings_context_menu)

        # 12) Notes autosave
        self.txt_notes.textChanged.connect(self.on_notes_changed)
        # 13) Registry -> Explore routing
        self.registry_page.openExploreWithConversation.connect(self._open_from_registry)
        self.registry_page.openExploreWithSearch.connect(self._open_from_registry_search)

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

        self.ai_service = AIAssistantService(
            AISettings.from_mapping(get_app_settings())
        )
        self.notes_controller = NotesController()
        self.flow_controller = FlowController()
        self.findings_controller = FindingsController()
        self.search_controller = SearchController(self)
        self.projects_ui_controller = ProjectsUIController(self)
        self.dataset_controller = DatasetController(self)
        self.explore_ui_controller = ExploreUIController(self)

        self._search_timer.timeout.connect(self.search_controller.apply_search_filter)        

        self._build_ui()
        self._wire_ui()

        # init
        self.projects_ui_controller.refresh_projects()
        self.explore_ui_controller.update_detail(None)
        self.explore_ui_controller.update_mode_label()
        self.refresh_findings_ui()
        self.refresh_notes_ui()
        
    def _message_dialog(
        self,
        title: str,
        message: str,
        details: str = "",
        width: int = 420,
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
        width: int = 360,
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
        manual_path = self.project_dir / "docs" / "ViaNyquist.pdf"

        if not manual_path.exists():
            self._message_dialog(
                "Help",
                "User manual not found.",
                str(manual_path),
                width=460,
            )
            return

        webbrowser.open(manual_path.resolve().as_uri())

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
        self._notes_timer.timeout.connect(self._flush_notes)

        # Explore search debounce
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        
        # Findings in-memory cache (for filter/sort)        
        self._findings_view_rows: list[Any] = []

        # AI background worker
        self._ai_thread: QThread | None = None
        self._ai_worker: AITextWorker | None = None
        self._ai_mode: str | None = None
        self._ai_output_state = AIOutputState()

    def _build_osint_page(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(14)

        header = QFrame()
        header.setObjectName("ProfileHero")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(18, 16, 18, 16)
        header_layout.setSpacing(8)

        title = QLabel("OSINT")
        title.setObjectName("ProfileTitle")
        subtitle = QLabel("Under construction. This module will later collect open-source profile signals for the active case.")
        subtitle.setObjectName("ProfileSubtitle")
        subtitle.setWordWrap(True)

        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        root.addWidget(header)

        panel = QFrame()
        panel.setObjectName("ProfilePanel")
        panel_layout = QVBoxLayout(panel)
        panel_layout.setContentsMargins(18, 16, 18, 16)
        panel_layout.setSpacing(10)

        panel_title = QLabel("Planned module")
        panel_title.setObjectName("ProfilePanelTitle")
        body = QLabel(
            "OSINT will be a separate workspace for social network, messaging-app and public-source indicators. "
            "For beta, this page is only a navigation placeholder so the final module has a reserved place in the application."
        )
        body.setObjectName("Muted")
        body.setWordWrap(True)
        body.setTextInteractionFlags(Qt.TextSelectableByMouse)

        panel_layout.addWidget(panel_title)
        panel_layout.addWidget(body)
        root.addWidget(panel)
        root.addStretch()
        return page

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
        self.IDX_EXPLORE = self.IDX_JSON
        self.IDX_REGISTRY = self.IDX_JSON
        self.IDX_LISTING = self.IDX_JSON
        self.IDX_PCAP = 5
        self.IDX_OSINT = 6
        self.IDX_SETTINGS = 7

        # -------- Projects page --------
        projects_page = QWidget()
        projects_layout = QVBoxLayout(projects_page)
        projects_layout.setContentsMargins(12, 10, 12, 24)
        projects_layout.setSpacing(12)

        self.lbl_active_project = QLabel("Active project: (none)")

        btn_row = QHBoxLayout()

        self.btn_new_project = QPushButton("New project")
        self.btn_open_project = QPushButton("Open project")
        self.btn_open_new_dataset = QPushButton("Open dataset")
        self.btn_edit_project = QPushButton("Edit project")
        self.btn_refresh_projects = QPushButton("Refresh")
        self.btn_delete_project = QPushButton("Delete selected")

        btn_row.addWidget(self.btn_new_project)
        btn_row.addWidget(self.btn_open_project)
        btn_row.addWidget(self.btn_open_new_dataset)
        btn_row.addWidget(self.btn_edit_project)
        btn_row.addWidget(self.btn_refresh_projects)
        btn_row.addWidget(self.btn_delete_project)

        self.projects_list = QListWidget()
        self.projects_info = QTextEdit()
        self.projects_info.setReadOnly(True)
        self.projects_info.setPlaceholderText("Select a project to see details.")

        self.project_recent_json_rows: list[dict[str, Any]] = []
        self.project_recent_pcap_rows: list[dict[str, Any]] = []
        self.project_activity_rows: list[dict[str, Any]] = []

        self.btn_expand_json_datasets = QPushButton("Open JSON list")
        self.btn_expand_pcap_datasets = QPushButton("Open PCAP list")
        self.btn_expand_project_activity = QPushButton("Open activity log")
        for button in (self.btn_open_new_dataset, self.btn_expand_json_datasets, self.btn_expand_pcap_datasets, self.btn_expand_project_activity):
            button.setMinimumHeight(42)

        self.btn_expand_json_datasets.clicked.connect(
            lambda: self._open_project_rows_dialog(
                "Recent JSON datasets",
                [
                    ("status", "Status"),
                    ("name", "Name"),
                    ("kind", "Kind"),
                    ("path", "Path"),
                ],
                self.project_recent_json_rows,
                on_double_click=self._open_json_dataset_row,
            )
        )
        self.btn_expand_pcap_datasets.clicked.connect(
            lambda: self._open_project_rows_dialog(
                "Recent PCAP days",
                [
                    ("name", "Name"),
                    ("file_count", "Files"),
                    ("packets", "Packets"),
                    ("volume", "Volume"),
                    ("device_ip", "Device IP"),
                    ("period", "Period"),
                ],
                self.project_recent_pcap_rows,
                on_double_click=self._open_pcap_dataset_row,
            )
        )
        self.btn_expand_project_activity.clicked.connect(
            lambda: self._open_project_rows_dialog(
                "Recent activity",
                [
                    ("event", "Event"),
                    ("created_at", "Time"),
                    ("detail", "Detail"),
                ],
                self.project_activity_rows,
            )
        )

        projects_layout.addWidget(self.lbl_active_project)

        self.case_dashboard = QFrame()
        self.case_dashboard.setObjectName("CaseDashboardCompact")
        self.case_dashboard.setMaximumHeight(128)
        dashboard_layout = QVBoxLayout(self.case_dashboard)
        dashboard_layout.setContentsMargins(12, 10, 12, 10)
        dashboard_layout.setSpacing(8)

        self.lbl_case_dashboard_title = QLabel("Case Dashboard")
        self.lbl_case_dashboard_title.setObjectName("CaseDashboardTitle")
        self.lbl_case_dashboard_subject = QLabel("Select a project to see case context.")
        self.lbl_case_dashboard_subject.setWordWrap(True)
        self.lbl_case_dashboard_subject.setObjectName("Muted")

        dashboard_header = QHBoxLayout()
        dashboard_header.setSpacing(14)

        self.lbl_case_dashboard_logo = QLabel()
        self.lbl_case_dashboard_logo.setObjectName("CaseDashboardLogo")
        self.lbl_case_dashboard_logo.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.lbl_case_dashboard_logo.setFixedSize(58, 44)
        logo_path = Path(__file__).resolve().parent.parent / "assets" / "ViaNyquist.png"
        logo_pixmap = QPixmap(str(logo_path))
        if not logo_pixmap.isNull():
            self.lbl_case_dashboard_logo.setPixmap(
                logo_pixmap.scaled(
                    self.lbl_case_dashboard_logo.size(),
                    Qt.KeepAspectRatio,
                    Qt.SmoothTransformation,
                )
            )
        dashboard_header.addWidget(self.lbl_case_dashboard_logo)
        dashboard_header.addWidget(self.lbl_case_dashboard_title)
        dashboard_header.addWidget(self.lbl_case_dashboard_subject, 1)
        dashboard_layout.addLayout(dashboard_header)

        self.case_metric_cards = []
        case_metrics = QHBoxLayout()
        case_metrics.setSpacing(8)
        for title in ("JSON Datasets", "PCAP Days", "Findings", "Device IPs"):
            card = QLabel(f"{title}: 0")
            card.setObjectName("CaseMetricCompact")
            card.setAlignment(Qt.AlignCenter)
            card.setMinimumHeight(34)
            card.setWordWrap(True)
            self.case_metric_cards.append(card)
            case_metrics.addWidget(card, 1)

        dashboard_metrics_row = QHBoxLayout()
        dashboard_metrics_row.setSpacing(8)
        dashboard_metrics_row.addLayout(case_metrics, 1)
        dashboard_layout.addLayout(dashboard_metrics_row)

        projects_layout.addWidget(self.case_dashboard)
        projects_layout.addLayout(btn_row)

        middle_row = QHBoxLayout()

        left_col = QVBoxLayout()
        left_col.addWidget(QLabel("Recent Projects:"))
        left_col.addWidget(self.projects_list, 1)

        right_col = QVBoxLayout()
        right_col.addWidget(QLabel("Selected project summary:"))
        right_col.addWidget(self.projects_info, 1)

        middle_row.addLayout(left_col, 2)
        middle_row.addLayout(right_col, 3)

        projects_layout.addLayout(middle_row, 1)

        self.lbl_recent_json_count = QLabel("0 JSON datasets")
        self.lbl_recent_json_count.setObjectName("ProfileMetric")
        self.lbl_recent_json_detail = QLabel("No JSON datasets saved for this project.")
        self.lbl_recent_json_detail.setObjectName("Muted")
        self.lbl_recent_json_detail.setWordWrap(True)

        self.lbl_recent_pcap_count = QLabel("0 PCAP days")
        self.lbl_recent_pcap_count.setObjectName("ProfileMetric")
        self.lbl_recent_pcap_detail = QLabel("No PCAP days saved for this project.")
        self.lbl_recent_pcap_detail.setObjectName("Muted")
        self.lbl_recent_pcap_detail.setWordWrap(True)

        self.lbl_recent_activity_count = QLabel("0 events")
        self.lbl_recent_activity_count.setObjectName("ProfileMetric")
        self.lbl_recent_activity_detail = QLabel("No project activity yet.")
        self.lbl_recent_activity_detail.setObjectName("Muted")
        self.lbl_recent_activity_detail.setWordWrap(True)

        bottom_grid = QGridLayout()
        bottom_grid.setSpacing(14)
        bottom_grid.addWidget(
            self._project_launcher_card(
                "Recent JSON datasets",
                "Unique JSON files or folders saved to the active project.",
                self.lbl_recent_json_count,
                self.lbl_recent_json_detail,
                [self.btn_expand_json_datasets],
            ),
            0,
            0,
        )
        bottom_grid.addWidget(
            self._project_launcher_card(
                "Recent PCAP days",
                "Unique PCAP capture days saved to the active project.",
                self.lbl_recent_pcap_count,
                self.lbl_recent_pcap_detail,
                [self.btn_expand_pcap_datasets],
            ),
            0,
            1,
        )
        bottom_grid.addWidget(
            self._project_launcher_card(
                "Recent activity",
                "Central project activity log for datasets, PCAP sources, findings and notes.",
                self.lbl_recent_activity_count,
                self.lbl_recent_activity_detail,
                [self.btn_expand_project_activity],
            ),
            0,
            2,
        )
        bottom_grid.setColumnStretch(0, 1)
        bottom_grid.setColumnStretch(1, 1)
        bottom_grid.setColumnStretch(2, 1)

        projects_layout.addLayout(bottom_grid, 1)

        # -------- Explore page --------
        explore_container = QWidget()
        explore_layout = QVBoxLayout(explore_container)

        self.lbl_project_banner = QLabel("Project: (none)")
        self.lbl_project_banner.setObjectName("HeaderProjectLabel")

        self.btn_load = QPushButton("Load dataset")

        self.lbl_path = QLabel("No dataset loaded")
        self.lbl_path.setObjectName("HeaderPathLabel")
        self.lbl_path.setWordWrap(True)

        self.lbl_stats = QLabel("")
        self.lbl_stats.setObjectName("HeaderStatLabel")
        self.lbl_stats.setWordWrap(False)

        self.lbl_loaded = QLabel("")
        self.lbl_loaded.setObjectName("HeaderStatLabel")

        self.lbl_showing = QLabel("")
        self.lbl_showing.setObjectName("HeaderStatLabel")

        self.lbl_json_day = QLabel("Period:")
        self.lbl_json_day.setObjectName("HeaderStatLabel")
        self.lbl_json_day.setVisible(False)

        self.cmb_json_day = QComboBox()
        self.cmb_json_day.setMinimumWidth(230)
        self.cmb_json_day.setVisible(False)

        self.lbl_json_meta = QLabel("")
        self.lbl_json_meta.setObjectName("HeaderStatLabel")
        self.lbl_json_meta.setWordWrap(False)
        self.lbl_json_meta.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.lbl_mode = QLabel("")
        self.lbl_mode.hide()

        self.lbl_conv_summary = QLabel("")
        self.lbl_conv_summary.hide()

        self.btn_load_more = QPushButton("Load next")
        self.btn_load_more.setEnabled(False)

        self.cmb_page_size = QComboBox()
        self.cmb_page_size.addItems(["1000", "2000", "5000", "10000"])
        self.cmb_page_size.setCurrentText("2000")

        header_card = QFrame()
        header_card.setObjectName("ExploreHeaderCard")

        header_layout = QVBoxLayout(header_card)
        header_layout.setContentsMargins(8, 6, 8, 6)
        header_layout.setSpacing(2)

        # row 1
        header_top = QHBoxLayout()
        header_top.setSpacing(6)

        header_top.addWidget(self.lbl_project_banner)
        header_top.addStretch()
        header_top.addWidget(self.btn_load)
        header_top.addWidget(QLabel("Page size:"))
        header_top.addWidget(self.cmb_page_size)
        header_top.addWidget(self.btn_load_more)
        
        # row 2
        header_mid = QHBoxLayout()
        header_mid.setSpacing(4)
        header_mid.setContentsMargins(0, 0, 0, 0)
        header_mid.addWidget(self.lbl_path, 1)

        # row 3
        header_bottom = QHBoxLayout()
        header_bottom.setSpacing(4)
        header_bottom.setContentsMargins(0, 0, 0, 0)
        header_bottom.addWidget(self.lbl_stats, 1)
        header_bottom.addSpacing(8)
        header_bottom.addWidget(self.lbl_json_day)
        header_bottom.addWidget(self.cmb_json_day)

        header_meta = QHBoxLayout()
        header_meta.setSpacing(4)
        header_meta.setContentsMargins(0, 0, 0, 0)
        header_meta.addWidget(self.lbl_json_meta, 1)

        header_layout.addLayout(header_top)
        header_layout.addLayout(header_mid)
        header_layout.addLayout(header_bottom)
        header_layout.addLayout(header_meta)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search IP / SNI / app...")
        self.search.setMinimumHeight(40)

        self.tabs = QTabWidget()
        self.tabs.setObjectName("ExploreSubTabs")
        self.tabs.setDocumentMode(True)

        self.btn_ai_summary = QPushButton("Generate AI Summary")
        self.btn_add_ai_to_notes = QPushButton("Add AI to Notes")
        self.btn_add_ai_to_notes.setEnabled(True)
        for btn in (self.btn_ai_summary, self.btn_add_ai_to_notes):
            btn.setObjectName("ExploreTabActionButton")
            btn.setFixedHeight(30)
            btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        summary_tab = QWidget()
        summary_layout = QVBoxLayout(summary_tab)
        summary_layout.setContentsMargins(8, 8, 8, 8)
        summary_layout.setSpacing(8)

        self.summary_preview_rows: dict[str, list[tuple[QLabel, QLabel]]] = {}
        self.summary_preview_cards: dict[str, QGroupBox] = {}
        self.summary_expand_buttons: dict[str, QPushButton] = {}

        summary_row_font = QFont("Consolas", 10)
        summary_row_font.setStyleHint(QFont.Monospace)
        summary_row_font.setFixedPitch(True)

        def _build_summary_card(title: str, key: str) -> QGroupBox:
            box = QGroupBox(title)
            box.setObjectName("SummaryCard")
            box.setFixedSize(SUMMARY_CARD_WIDTH, SUMMARY_CARD_HEIGHT)
            layout = QVBoxLayout(box)
            layout.setContentsMargins(8, 8, 8, 8)
            layout.setSpacing(4)

            rows: list[tuple[QLabel, QLabel]] = []
            rows_layout = QVBoxLayout()
            rows_layout.setContentsMargins(0, 0, 0, 0)
            rows_layout.setSpacing(2)
            for _row_index in range(EMBEDDED_SUMMARY_TOP_N):
                row_layout = QHBoxLayout()
                row_layout.setContentsMargins(0, 0, 0, 0)
                row_layout.setSpacing(6)
                lbl_name = QLabel()
                lbl_name.setObjectName("SummaryPreviewName")
                lbl_name.setFont(summary_row_font)
                lbl_name.setWordWrap(False)
                lbl_name.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
                lbl_name.setMinimumWidth(0)
                lbl_name.setTextInteractionFlags(Qt.TextSelectableByMouse)

                lbl_count = QLabel()
                lbl_count.setObjectName("SummaryPreviewCount")
                lbl_count.setFont(summary_row_font)
                lbl_count.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
                lbl_count.setFixedWidth(SUMMARY_VALUE_COL_WIDTH)
                lbl_count.setTextInteractionFlags(Qt.TextSelectableByMouse)

                row_layout.addWidget(lbl_name, 1)
                row_layout.addWidget(lbl_count, 0)
                rows.append((lbl_name, lbl_count))
                rows_layout.addLayout(row_layout)

            self.summary_preview_rows[key] = rows
            self.summary_preview_cards[key] = box
            layout.addLayout(rows_layout)
            layout.addStretch(1)

            expand = QPushButton("Expand table")
            expand.setObjectName("SummaryExpandButton")
            expand.setFixedHeight(30)
            expand.setEnabled(False)
            expand.clicked.connect(lambda _checked=False, kind=key: self.dataset_controller.expand_dataset_summary(kind))
            self.summary_expand_buttons[key] = expand
            expand_row = QHBoxLayout()
            expand_row.addStretch()
            expand_row.addWidget(expand)
            layout.addLayout(expand_row)
            return box

        self.lbl_dataset_summary = QLabel("Dataset summary")
        self.lbl_dataset_summary.setObjectName("SectionTitle")

        cards_grid = QGridLayout()
        cards_grid.setContentsMargins(0, 0, 0, 0)
        cards_grid.setHorizontalSpacing(10)
        cards_grid.setVerticalSpacing(8)
        cards_grid.addWidget(_build_summary_card("Top source IPs", "src"), 0, 0)
        cards_grid.addWidget(_build_summary_card("Top destination IPs", "dst"), 0, 1)
        cards_grid.addWidget(_build_summary_card("Top protocols", "proto"), 1, 0)
        cards_grid.addWidget(_build_summary_card("Top applications", "apps"), 1, 1)

        cards_panel = QWidget()
        cards_panel.setFixedSize(SUMMARY_CARDS_WRAP_WIDTH, SUMMARY_CARDS_WRAP_HEIGHT)
        cards_panel.setLayout(cards_grid)

        dataset_column = QVBoxLayout()
        dataset_column.setContentsMargins(0, 0, 0, 0)
        dataset_column.setSpacing(6)
        dataset_column.addWidget(self.lbl_dataset_summary)
        dataset_column.addWidget(cards_panel)

        self.lbl_ai_summary = QLabel("AI assistant output")
        self.lbl_ai_summary.setObjectName("SectionTitle")

        self.txt_ai_summary = QTextEdit()
        self.txt_ai_summary.setReadOnly(True)
        self.txt_ai_summary.setPlaceholderText("Generate AI summary to populate this panel.")

        ai_output_card = QFrame()
        ai_output_card.setObjectName("Card")
        ai_output_card.setMinimumHeight(SUMMARY_CARDS_WRAP_HEIGHT)
        ai_output_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        ai_output_card_layout = QVBoxLayout(ai_output_card)
        ai_output_card_layout.setContentsMargins(10, 10, 10, 10)
        ai_output_card_layout.setSpacing(0)
        ai_output_card_layout.addWidget(self.txt_ai_summary, 1)

        ai_column = QVBoxLayout()
        ai_column.setContentsMargins(0, 0, 0, 0)
        ai_column.setSpacing(6)
        ai_column.addWidget(self.lbl_ai_summary)
        ai_column.addWidget(ai_output_card, 1)

        dataset_column_widget = QWidget()
        dataset_column_widget.setLayout(dataset_column)
        dataset_column_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        dataset_column_widget.setFixedWidth(SUMMARY_CARDS_WRAP_WIDTH)

        ai_column_widget = QWidget()
        ai_column_widget.setLayout(ai_column)
        ai_column_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        summary_content = QHBoxLayout()
        summary_content.setContentsMargins(0, 0, 0, 0)
        summary_content.setSpacing(12)
        summary_content.setAlignment(Qt.AlignTop)
        summary_content.addWidget(dataset_column_widget, 0)
        summary_content.addWidget(ai_column_widget, 1)

        summary_layout.addLayout(summary_content, 1)

        self.tabs.addTab(summary_tab, "Summary")

        flows_tab = QWidget()
        flows_tab_layout = QVBoxLayout(flows_tab)
        flows_tab_layout.setContentsMargins(8, 8, 8, 8)
        flows_tab_layout.setSpacing(8)

        # ----- FLOW TOOLBAR -----        
        toolbar_wrap = QFrame()
        toolbar_wrap.setObjectName("FlowToolbarCard")
        toolbar_wrap.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        toolbar_wrap.setFixedHeight(68)

        toolbar = QHBoxLayout(toolbar_wrap)
        toolbar.setContentsMargins(10, 10, 10, 10)
        toolbar.setSpacing(10)
        toolbar.setAlignment(Qt.AlignVCenter)

        left_actions = QHBoxLayout()
        left_actions.setSpacing(8)

        right_actions = QHBoxLayout()
        right_actions.setSpacing(8)

        self.btn_filter_src = QPushButton("Filter source")
        self.btn_filter_dst = QPushButton("Filter destination")
        self.btn_filter_sni = QPushButton("Filter SNI")
        self.btn_load.setFixedHeight(34)

        self.btn_toggle_conv = QPushButton("Conversation: OFF")
        self.btn_expand_flows = QPushButton("Expand Flows")
        self.btn_mark_finding = QPushButton("Mark as Finding")
        self.btn_ai_explain = QPushButton("Explain with AI")

        for b in (
            self.btn_filter_src, self.btn_filter_dst,
            self.btn_filter_sni,
            self.btn_toggle_conv, self.btn_expand_flows,
            self.btn_mark_finding, self.btn_ai_explain
        ):
            b.setFixedHeight(34)
            b.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        
        left_actions.addSpacing(6)
        left_actions.addWidget(self.btn_filter_src)
        left_actions.addWidget(self.btn_filter_dst)
        left_actions.addWidget(self.btn_filter_sni)

        right_actions.addWidget(self.btn_toggle_conv)
        right_actions.addWidget(self.btn_expand_flows)
        right_actions.addWidget(self.btn_mark_finding)
        right_actions.addWidget(self.btn_ai_explain)

        toolbar.addLayout(left_actions)
        toolbar.addStretch()
        toolbar.addLayout(right_actions)

        flows_tab_layout.addWidget(self.search)
        flows_tab_layout.addWidget(toolbar_wrap)
        self.splitter = QSplitter(Qt.Horizontal)

        self.table = FlowTableView(self)
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.setWordWrap(False)
        self.table.setShowGrid(False)
        self.table.setCornerButtonEnabled(False)
        self.table.setEditTriggers(QTableView.NoEditTriggers)
        self.table.setFocusPolicy(Qt.StrongFocus)
        
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(34)

        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setMinimumSectionSize(70)
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        header.setSectionResizeMode(QHeaderView.Interactive)

        self.model = FlowTableModel([])
        self.proxy = NumericSortProxy()
        self.proxy.setSourceModel(self.model)
        self.table.setModel(self.proxy)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Interactive)        # Source IP
        header.setSectionResizeMode(1, QHeaderView.Fixed)              # Source Port
        header.setSectionResizeMode(2, QHeaderView.Interactive)        # Destination IP
        header.setSectionResizeMode(3, QHeaderView.Fixed)              # Destination Port
        header.setSectionResizeMode(4, QHeaderView.Fixed)              # Protocol
        header.setSectionResizeMode(5, QHeaderView.Interactive)        # App
        header.setSectionResizeMode(6, QHeaderView.Fixed)              # Bytes
        header.setSectionResizeMode(7, QHeaderView.Fixed)              # Duration
        header.setSectionResizeMode(8, QHeaderView.Stretch)            # SNI
        self.table.setColumnWidth(0, 138)
        self.table.setColumnWidth(1, 92)
        self.table.setColumnWidth(2, 138)
        self.table.setColumnWidth(3, 116)
        self.table.setColumnWidth(4, 86)
        self.table.setColumnWidth(5, 140)
        self.table.setColumnWidth(6, 96)
        self.table.setColumnWidth(7, 104)

        self.splitter.addWidget(self.table)

        self.details_panel = QWidget()
        details_panel = self.details_panel
        details_panel.setMinimumWidth(430)
        details_panel.setMaximumWidth(520)

        details_layout = QVBoxLayout(details_panel)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_layout.setSpacing(10)

        grp = QGroupBox("Flow details")
        grp.setObjectName("FlowDetailsCard")

        details_grid = QGridLayout(grp)
        details_grid.setContentsMargins(14, 14, 14, 14)
        details_grid.setHorizontalSpacing(14)
        details_grid.setVerticalSpacing(12)

        self.d_src = QLabel("-"); self.d_src.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.d_dst = QLabel("-"); self.d_dst.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.d_proto = QLabel("-")
        self.d_app = QLabel("-")
        self.d_bytes = QLabel("-")
        self.d_packets = QLabel("-")
        self.d_duration = QLabel("-")
        self.d_sni = QLabel("-"); self.d_sni.setTextInteractionFlags(Qt.TextSelectableByMouse)

        for w in (self.d_src, self.d_dst, self.d_proto, self.d_app, self.d_bytes, self.d_packets, self.d_duration, self.d_sni):
            w.setWordWrap(True)
            w.setMinimumHeight(36)
            w.setAlignment(Qt.AlignLeft | Qt.AlignTop)
            w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        self.d_src.setTextFormat(Qt.PlainText)
        self.d_dst.setTextFormat(Qt.PlainText)
        self.d_sni.setTextFormat(Qt.PlainText)

        lbl_src = QLabel("Source")
        lbl_dst = QLabel("Destination")
        lbl_proto = QLabel("Protocol")
        lbl_app = QLabel("Application")
        lbl_bytes = QLabel("Bytes")
        lbl_packets = QLabel("Packets")
        lbl_duration = QLabel("Duration (ms)")
        lbl_sni = QLabel("SNI")

        for lbl in (lbl_src, lbl_dst, lbl_proto, lbl_app, lbl_bytes, lbl_packets, lbl_duration, lbl_sni):
            lbl.setObjectName("FlowFieldLabel")

        for val in (self.d_src, self.d_dst, self.d_proto, self.d_app, self.d_bytes, self.d_packets, self.d_duration, self.d_sni):
            val.setObjectName("FlowFieldValue")

        details_grid.addWidget(lbl_src,      0, 0)
        details_grid.addWidget(lbl_dst,      0, 1)
        details_grid.addWidget(self.d_src,   1, 0)
        details_grid.addWidget(self.d_dst,   1, 1)

        details_grid.addWidget(lbl_proto,    2, 0)
        details_grid.addWidget(lbl_app,      2, 1)
        details_grid.addWidget(self.d_proto, 3, 0)
        details_grid.addWidget(self.d_app,   3, 1)

        details_grid.addWidget(lbl_bytes,    4, 0)
        details_grid.addWidget(lbl_packets,  4, 1)
        details_grid.addWidget(self.d_bytes, 5, 0)
        details_grid.addWidget(self.d_packets, 5, 1)

        details_grid.addWidget(lbl_duration,    6, 0)
        details_grid.addWidget(self.d_duration, 7, 0)

        details_grid.addWidget(lbl_sni,         8, 0, 1, 2)
        details_grid.addWidget(self.d_sni,      9, 0, 1, 2)

        details_grid.setColumnStretch(0, 1)
        details_grid.setColumnStretch(1, 1)

        grp.setMinimumHeight(0)
        grp.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(grp)
        details_layout.addWidget(scroll, 1)

        self.splitter.addWidget(details_panel)
        self.splitter.setStretchFactor(0, 5)
        self.splitter.setStretchFactor(1, 2)
        self.splitter.setCollapsible(1, False)

        flows_tab_layout.addWidget(self.splitter)
        self.tabs.addTab(flows_tab, "Flows")

        # Findings tab
        self.findings_page = FindingsPage()

        self.btn_finding_edit = self.findings_page.btn_finding_edit
        self.btn_finding_delete = self.findings_page.btn_finding_delete
        self.btn_finding_jump = self.findings_page.btn_finding_jump
        self.btn_finding_ai = self.findings_page.btn_finding_ai

        self.cmb_find_status = self.findings_page.cmb_find_status
        self.cmb_find_sort = self.findings_page.cmb_find_sort
        self.txt_find_search = self.findings_page.txt_find_search
        self.txt_find_tag = self.findings_page.txt_find_tag
        self.btn_find_clear = self.findings_page.btn_find_clear

        self.findings_list = self.findings_page.findings_list
        self.finding_detail = self.findings_page.finding_detail
        self.findings_split = self.findings_page.findings_split

        self.tabs.addTab(self.findings_page, "Findings")

        explore_ai_actions = QHBoxLayout()
        explore_ai_actions.setContentsMargins(0, 0, 8, 0)
        explore_ai_actions.setSpacing(6)
        explore_ai_actions.addWidget(self.btn_ai_summary)
        explore_ai_actions.addWidget(self.btn_add_ai_to_notes)
        explore_ai_actions_widget = QWidget()
        explore_ai_actions_widget.setObjectName("ExploreTabActions")
        explore_ai_actions_widget.setLayout(explore_ai_actions)
        explore_ai_actions_widget.setFixedHeight(30)
        self.tabs.setCornerWidget(explore_ai_actions_widget, Qt.TopRightCorner)

        # Notes page
        self.notes_page = NotesPage(self)
        self.txt_notes = self.notes_page.editor
        self.notes_page.btn_insert_chart.clicked.connect(self.insert_notes_chart)
        self.notes_page.btn_export_word.clicked.connect(self.export_notes_word)
        self.notes_page.btn_export_html.clicked.connect(self.export_notes_html)
        self.notes_page.btn_export_pdf.clicked.connect(self.export_notes_pdf)

        ai_page = QWidget()
        ai_root = QVBoxLayout(ai_page)
        ai_root.setContentsMargins(10, 10, 10, 10)
        ai_root.setSpacing(10)

        ai_header = QFrame()
        ai_header.setObjectName("ExploreHeaderCard")
        ai_header_layout = QVBoxLayout(ai_header)
        ai_header_layout.setContentsMargins(14, 14, 14, 14)
        ai_header_layout.setSpacing(8)

        ai_title_row = QHBoxLayout()
        self.lbl_ai_hub_title = QLabel("AI Summary")
        self.lbl_ai_hub_title.setObjectName("HeaderProjectLabel")
        self.btn_ai_hub_add_notes = QPushButton("Add to Notes")
        self.btn_ai_hub_add_notes.setEnabled(False)
        ai_title_row.addWidget(self.lbl_ai_hub_title)
        ai_title_row.addStretch()
        ai_title_row.addWidget(self.btn_ai_hub_add_notes)

        self.lbl_ai_hub_context = QLabel("Generate an AI result from JSON, PCAP or Profile to see it here.")
        self.lbl_ai_hub_context.setObjectName("Muted")
        self.lbl_ai_hub_context.setWordWrap(True)

        ai_header_layout.addLayout(ai_title_row)
        ai_header_layout.addWidget(self.lbl_ai_hub_context)
        ai_root.addWidget(ai_header)

        self.txt_ai_hub = QTextEdit()
        self.txt_ai_hub.setReadOnly(True)
        self.txt_ai_hub.setPlaceholderText("The latest AI-generated explanation or summary will appear here.")
        ai_root.addWidget(self.txt_ai_hub, 1)

        self.btn_ai_hub_add_notes.clicked.connect(self.add_ai_hub_to_notes)

        # Explore layout
        explore_layout.addWidget(self.lbl_mode)
        explore_layout.addWidget(self.lbl_conv_summary)
        explore_layout.addWidget(self.tabs, 1)

        # Pages
        self.pages.addWidget(projects_page)

        self.activity_profile_page = ActivityProfilePage(self)
        self.pages.addWidget(self.activity_profile_page)

        self.pages.addWidget(self.notes_page)
        self.pages.addWidget(ai_page)

        json_page = QWidget()
        json_layout = QVBoxLayout(json_page)
        json_layout.setContentsMargins(0, 0, 0, 0)
        json_layout.setSpacing(4)
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
        if idx == self.IDX_SETTINGS and hasattr(self, "settings_page"):
            self.settings_page.refresh()

    def _project_launcher_card(
        self,
        title: str,
        description: str,
        count_label: QLabel,
        detail_label: QLabel,
        buttons: list[QPushButton],
    ) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 28)
        layout.setSpacing(10)

        lbl_title = QLabel(title)
        lbl_title.setObjectName("SectionTitle")
        lbl_title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lbl_description = QLabel(description)
        lbl_description.setObjectName("Muted")
        lbl_description.setWordWrap(False)
        lbl_description.setMaximumHeight(24)
        lbl_description.setTextInteractionFlags(Qt.TextSelectableByMouse)

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_description)
        layout.addWidget(count_label)
        detail_label.setWordWrap(False)
        detail_label.setMaximumHeight(24)
        layout.addWidget(detail_label)
        layout.addStretch(1)

        button_row = QHBoxLayout()
        button_row.setContentsMargins(0, 4, 0, 0)
        button_row.addStretch()
        for button in buttons:
            button_row.addWidget(button)
        layout.addLayout(button_row)
        return card

    def _open_project_rows_dialog(
        self,
        title: str,
        columns: list[tuple[str, str]],
        rows: list[dict[str, Any]],
        on_double_click: Callable[[dict[str, Any], QDialog], None] | None = None,
    ) -> None:
        if not rows:
            self._message_dialog(title, "No rows are loaded.", width=380)
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        screen = QGuiApplication.primaryScreen()
        if screen is not None:
            available = screen.availableGeometry()
            dlg.resize(min(1180, available.width() - 120), min(680, available.height() - 120))
        else:
            dlg.resize(1080, 640)

        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(14, 14, 14, 28)
        layout.setSpacing(10)

        hint = QLabel("Expanded project view. Sort columns or right-click to copy values.")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        table = CopyableTableView(self)
        table.setModel(DictTableModel(columns, rows))
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QTableView.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.setMinimumHeight(480)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        if on_double_click is not None:
            def handle_double_click(index):
                model = table.model()
                if not isinstance(model, DictTableModel) or not index.isValid():
                    return
                row_idx = index.row()
                if 0 <= row_idx < len(model.rows):
                    on_double_click(model.rows[row_idx], dlg)

            table.doubleClicked.connect(handle_double_click)

        for idx, (key, label) in enumerate(columns):
            name = f"{key} {label}".lower()
            width = 140
            if "detail" in name:
                width = 620
            elif "path" in name:
                width = 520
            elif "event" in name:
                width = 320
            elif "period" in name:
                width = 300
            elif "time" in name or "created" in name:
                width = 220
            elif "name" in name:
                width = 260
            table.setColumnWidth(idx, width)

        layout.addWidget(table, 1)

        footer = QHBoxLayout()
        footer.addStretch()
        btn_close = QPushButton("Close")
        btn_close.setMinimumHeight(42)
        btn_close.clicked.connect(dlg.accept)
        footer.addWidget(btn_close)
        layout.addSpacing(6)
        layout.addLayout(footer)
        dlg.exec()

    def _open_json_dataset_row(self, row: dict[str, Any], dialog: QDialog) -> None:
        path_text = str(row.get("path") or "")
        path = Path(path_text)
        if not path_text or not path.exists():
            self._message_dialog("JSON dataset", "Path not found.", path_text or "-", width=460)
            return
        dialog.accept()
        if path.is_file():
            self.dataset_controller.load_dataset_file(str(path))
        elif path.is_dir():
            self.dataset_controller.load_dataset_path(str(path))
        self.go_to_json_tab(0)

    def _open_pcap_dataset_row(self, row: dict[str, Any], dialog: QDialog) -> None:
        row = self._resolve_project_pcap_row(row)
        paths = [str(path) for path in (row.get("paths") or []) if str(path or "").strip()]
        existing_paths = [path for path in paths if Path(path).is_file()]
        if existing_paths:
            dialog.accept()
            self.go_page(self.IDX_PCAP, self._nav_pcap)
            if hasattr(self, "pcap_page"):
                label = str(row.get("name") or "")
                self.pcap_page._load_pcap_files(existing_paths, label=label)
            return

        path_text = str(row.get("path") or "")
        path = Path(path_text)
        if not path_text or not path.is_file():
            if row.get("day") or str(row.get("name") or "").strip():
                self._message_dialog(
                    "PCAP dataset",
                    "Saved PCAP day cannot be opened because the original source files are not available at their saved paths.",
                    str(row.get("name") or row.get("day") or path_text or "-"),
                    width=560,
                )
                return
            self._message_dialog("PCAP dataset", "PCAP file not found.", path_text or "-", width=460)
            return
        dialog.accept()
        self.go_page(self.IDX_PCAP, self._nav_pcap)
        if hasattr(self, "pcap_page"):
            self.pcap_page.load_pcap(str(path))

    def _resolve_project_pcap_row(self, row: dict[str, Any]) -> dict[str, Any]:
        paths = [str(path) for path in (row.get("paths") or []) if str(path or "").strip()]
        if any(Path(path).is_file() for path in paths):
            return row

        project_id = getattr(self, "current_project_id", None)
        controller = getattr(self, "projects_ui_controller", None)
        if project_id is None or controller is None or not hasattr(controller, "_project_pcap_day_rows"):
            return row

        row_day = str(row.get("day") or "").strip()
        row_name = str(row.get("name") or "").strip()
        row_path = str(row.get("path") or "").strip()
        try:
            candidates = controller._project_pcap_day_rows(project_id)
        except Exception:
            return row

        for candidate in candidates:
            candidate_day = str(candidate.get("day") or "").strip()
            candidate_name = str(candidate.get("name") or "").strip()
            labels = {value for value in (row_day, row_name, row_path) if value}
            if (
                (row_day and row_day == candidate_day)
                or (row_name and row_name == candidate_name)
                or (row_path and row_path == candidate_name)
                or (candidate_day and candidate_day in labels)
            ):
                merged = dict(row)
                merged.update({
                    "day": candidate.get("day") or row.get("day"),
                    "name": candidate.get("name") or row.get("name"),
                    "paths": candidate.get("paths") or row.get("paths") or [],
                    "file_count": candidate.get("file_count") or row.get("file_count"),
                })
                candidate_path = str(candidate.get("path") or "")
                row_path_obj = Path(row_path) if row_path else None
                if candidate_path or not (row_path_obj and row_path_obj.is_file()):
                    merged["path"] = candidate_path
                return merged
        return row

    def refresh_activity_profile_ui(self):
        if hasattr(self, "activity_profile_page"):
            self.activity_profile_page.refresh(self.current_project_id, self.current_project_name)

    def refresh_all_views(self):
        if hasattr(self, "_flush_notes"):
            self._flush_notes()

        active_project_id = self.current_project_id
        self.projects_ui_controller.refresh_projects()

        if active_project_id is not None and get_project(active_project_id):
            self.projects_ui_controller.set_active_project(active_project_id)
            for i in range(self.projects_list.count()):
                item = self.projects_list.item(i)
                if int(item.data(Qt.UserRole)) == active_project_id:
                    self.projects_list.setCurrentItem(item)
                    break
            self.projects_ui_controller.refresh_recent_datasets(active_project_id)
            self.projects_ui_controller.refresh_case_dashboard(active_project_id)

        self.refresh_findings_ui()
        self.refresh_notes_ui()
        self.refresh_activity_profile_ui()
        if hasattr(self, "pcap_page"):
            self.pcap_page.refresh_current_view()

        if hasattr(self, "settings_page"):
            self.settings_page.refresh()

        self._message_dialog(
            "Refresh All",
            "Application views refreshed.",
            "Refreshed projects, project dashboard, recent datasets, notes, findings, activity profile, PCAP view and settings.",
            width=460,
        )

    def apply_theme(self, theme: str | None) -> None:
        qapp = QApplication.instance()
        if qapp is not None:
            apply_app_stylesheet(qapp, normalize_ui_theme(theme))

    def _open_from_registry(self, src: str, dst: str):
        self.go_to_explore_flows()
        self.search.setText("")
        self.explore_ui_controller.enter_conversation(src, dst)

        # ---------- Keyboard shortcuts ----------
    def keyPressEvent(self, event):
        key = event.key()
        mods = event.modifiers()

        if mods & Qt.ControlModifier and key == Qt.Key_F:
            # focus global search (flows)
            self.search.setFocus()
            self.search.selectAll()
            event.accept()
            return

        if mods & Qt.ControlModifier and key == Qt.Key_L:
            self.dataset_controller.load_dataset_dialog()
            event.accept()
            return

        if key == Qt.Key_Escape:
            self.explore_ui_controller.leave_conversation(clear_search=True)
            event.accept()
            return

        # Findings tab shortcuts
        if self.tabs.currentIndex() == 2:
            if key == Qt.Key_J:
                self.jump_to_selected_finding()
                event.accept()
                return
            if key == Qt.Key_E:
                self.edit_selected_finding()
                event.accept()
                return
            if key == Qt.Key_Delete:
                self.delete_selected_finding()
                event.accept()
                return

        super().keyPressEvent(event)
          
    def on_ai_task_finished(self, result: str):
        self.txt_ai_summary.setPlainText(result)
        title = {
            "summary": "JSON Dataset Summary",
            "flow": "Flow Explanation",
            "finding": "Finding Explanation",
        }.get(self._ai_mode or "", "AI Summary")
        self.publish_ai_output("JSON", title, result)

        if self._ai_mode == "summary":
            self.btn_ai_summary.setEnabled(True)
            self.btn_ai_summary.setText("Generate AI Summary")
        elif self._ai_mode == "flow":
            self.btn_ai_explain.setEnabled(True)
        elif self._ai_mode == "finding":
            self.btn_finding_ai.setEnabled(True)

    def on_ai_task_error(self, message: str):
        self.txt_ai_summary.setPlainText(f"AI error: {message}")

        if self._ai_mode == "summary":
            self.btn_ai_summary.setEnabled(True)
            self.btn_ai_summary.setText("Generate AI Summary")
        elif self._ai_mode == "flow":
            self.btn_ai_explain.setEnabled(True)
        elif self._ai_mode == "finding":
            self.btn_finding_ai.setEnabled(True)

    def _cleanup_ai_thread(self):
        if self._ai_worker is not None:
            self._ai_worker.deleteLater()
            self._ai_worker = None

        if self._ai_thread is not None:
            self._ai_thread.deleteLater()
            self._ai_thread = None

        self._ai_mode = None    

    # ---------- Findings ----------
    def selected_finding_id(self) -> int | None:
        return self.findings_page.selected_finding_id()

    def set_findings_actions_enabled(self, enabled: bool):
        self.findings_page.set_actions_enabled(enabled)

    def _get_selected_finding_row(self):
        fid = self.selected_finding_id()
        return self.findings_controller.get_selected_row(fid)

    def mark_as_finding(self):
        if self.current_project_id is None:
            self._message_dialog("Findings", "Select an active project first (Projects -> Open).", width=460)
            return
        if not self._current_flow:
            self._message_dialog("Findings", "Select a flow first.", width=400)
            return

        default_title = f"{self.current_value('src_ip')} -> {self.current_value('dst_ip')} ({self.current_value('application_name')})"
        title, ok = self._text_input_dialog("New finding", "Title:", text=default_title, width=480)
        if not ok:
            return
        title = (title or "").strip()
        if not title:
            return

        note, ok2 = self._multiline_input_dialog("New finding", "Note (optional):", width=480, height=260)
        if not ok2:
            note = ""

        tags, ok3 = self._text_input_dialog("New finding", "Tags (comma-separated, optional):", width=440)
        if not ok3:
            tags = ""
        tags = normalize_tags(tags)

        try:
            add_finding(self.current_project_id, self._current_flow, title=title, note=note, tags=tags)
        except Exception as e:
            self._message_dialog("Findings", "Failed to create finding.", str(e), width=460)
            return

        self.refresh_findings_ui()
        self.refresh_activity_ui()
        self.tabs.setCurrentIndex(2)

    def clear_findings_filters(self):
        self.cmb_find_status.setCurrentText("All")
        self.cmb_find_sort.setCurrentText("Newest")
        self.txt_find_search.setText("")
        self.txt_find_tag.setText("")
        self.apply_findings_filter()
    
    def refresh_findings_ui(self):
        self.findings_controller.rows = []
        self._findings_view_rows = []

        if self.current_project_id is None:
            self.findings_page.clear_list()
            self.findings_page.add_list_item("(no active project)", None)
            self.findings_page.clear_detail()
            return

        rows = self.findings_controller.load_rows(self.current_project_id)        

        self.apply_findings_filter()

    def apply_findings_filter(self):
        keep_id = self.selected_finding_id()

        status_sel = (self.cmb_find_status.currentText() or "All").strip()
        search = (self.txt_find_search.text() or "").strip().lower()
        tagq = (self.txt_find_tag.text() or "").strip().lower()

        rows = self.findings_controller.get_filtered_rows(
            status_sel,
            self.txt_find_search.text(),
            self.txt_find_tag.text(),
            self.findings_page
        )                                   

        render_rows = self.findings_controller.prepare_render_rows(
            rows,
            status_emoji
        )

        self._findings_view_rows = rows
        self.findings_page.render_list(render_rows, self.current_project_id, keep_id)

    def on_finding_selected(self):
        fid, row = self._get_selected_finding_row()

        if fid is None:
            self.findings_page.clear_detail()
            return

        if row is None:
            self.findings_page.show_detail("Finding not found.")
            self.set_findings_actions_enabled(False)
            return

        self.set_findings_actions_enabled(True)

        self.findings_page.show_detail(format_finding_detail(row, status_emoji))

    def explain_selected_finding(self):
        fid, row = self._get_selected_finding_row()
        if fid is None or row is None:
            self._message_dialog("AI Assistant", "Select a finding first.", width=400)
            return

        if self._ai_thread is not None:
            self._message_dialog("AI Assistant", "Another AI task is already running.", width=430)
            return

        self._ai_mode = "finding"
        self.txt_ai_summary.setPlainText("Generating AI finding explanation...")
        self.tabs.setCurrentIndex(0)

        self.btn_finding_ai.setEnabled(False)

        self._ai_thread = QThread()
        self._ai_worker = AITextWorker(
            self.ai_service.explain_finding,
            dict(row),
        )

        self._ai_worker.moveToThread(self._ai_thread)
        self._ai_thread.started.connect(self._ai_worker.run)
        self._ai_worker.finished.connect(self.on_ai_task_finished)
        self._ai_worker.error.connect(self.on_ai_task_error)

        self._ai_worker.finished.connect(self._ai_thread.quit)
        self._ai_worker.error.connect(self._ai_thread.quit)

        self._ai_thread.finished.connect(self._cleanup_ai_thread)

        self._ai_thread.start()

    def jump_to_selected_finding(self):
        fid, row = self._get_selected_finding_row()
        if fid is None or row is None:
            return

        src = row["src_ip"]
        dst = row["dst_ip"]

        self.go_to_explore_flows()
        self.search.setText("")
        self.explore_ui_controller.leave_conversation(clear_search=False)
        self.explore_ui_controller.enter_conversation(src, dst)

        QTimer.singleShot(0, lambda: self.explore_ui_controller.select_flow_pair(src, dst))

    def edit_selected_finding(self):
        fid, row = self._get_selected_finding_row()
        if fid is None or row is None:
            return

        title, ok = self._text_input_dialog("Edit finding", "Title:", text=row["title"] or "", width=480)
        if not ok:
            return
        title = (title or "").strip()
        if not title:
            return

        note, ok2 = self._multiline_input_dialog("Edit finding", "Note:", text=row["note"] or "", width=480, height=260)
        if not ok2:
            return

        statuses = ["New", "Investigating", "Confirmed", "False Positive"]
        cur = row["status"] if row["status"] in statuses else "New"
        idx = statuses.index(cur)

        status, ok3 = self._item_choice_dialog(
            "Edit finding",
            "Status:",
            statuses,
            current_index=idx,
            width=420,
        )
        if not ok3:
            return

        tags, ok4 = self._text_input_dialog("Edit finding", "Tags (comma-separated):", text=row["tags"] or "", width=440)
        if not ok4:
            return

        tags = normalize_tags(tags)

        try:
            update_finding(fid, title=title, note=note, status=status, tags=tags)
        except Exception as e:
            self._message_dialog("Findings", "Failed to update finding.", str(e), width=460)
            return

        self.refresh_findings_ui()
        self.refresh_activity_ui()
        self.findings_page.select_finding_by_id(fid)

    def delete_selected_finding(self):
        fid, row = self._get_selected_finding_row()
        if fid is None or row is None:
            return

        title = row["title"] or "(no title)"
        src = f"{row['src_ip']}:{row['src_port'] or ''}"
        dst = f"{row['dst_ip']}:{row['dst_port'] or ''}"

        confirmed = self._confirm_dialog(
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
            self._message_dialog("Findings", "Failed to delete finding.", str(e), width=460)
            return

        self.refresh_findings_ui()
        self.refresh_activity_ui()

    # Context menu (right click) on Findings
    def on_findings_context_menu(self, pos):
        fid = self.selected_finding_id()
        menu = QMenu(self)

        act_jump = menu.addAction("Jump to Flow (J)")
        act_edit = menu.addAction("Edit (E)")
        act_delete = menu.addAction("Delete (Del)")
        menu.addSeparator()
        act_new = menu.addAction("Set status: 🆕 New")
        act_inv = menu.addAction("Set status: 🟡 Investigating")
        act_conf = menu.addAction("Set status: ✅ Confirmed")
        act_fp = menu.addAction("Set status: ⚪ False Positive")

        if fid is None:
            for a in (act_jump, act_edit, act_delete, act_new, act_inv, act_conf, act_fp):
                a.setEnabled(False)

        chosen = menu.exec(self.findings_list.mapToGlobal(pos))
        if not chosen or fid is None:
            return

        if chosen == act_jump:
            self.jump_to_selected_finding()
            return
        if chosen == act_edit:
            self.edit_selected_finding()
            return
        if chosen == act_delete:
            self.delete_selected_finding()
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
                updated = update_finding_status(fid, new_status, self.current_project_id)
            except Exception as e:
                self._message_dialog("Findings", "Failed to update finding status.", str(e), width=460)
                return
            if not updated:
                return

            self.refresh_findings_ui()
            self.refresh_activity_ui()

    def _make_ai_note_block(self, text: str) -> str:
        return make_ai_note_block(text)

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

    def add_ai_hub_to_notes(self):
        text = (self._ai_output_state.text or "").strip()
        if not text:
            self._message_dialog("Notes", "There is no AI-generated text to add.", width=440)
            return
        self.add_ai_text_to_notes(text)

    def add_ai_text_to_notes(self, text: str) -> bool:
        if self.current_project_id is None:
            self._message_dialog("Notes", "Open an active project first.", width=420)
            return False

        block = self._make_ai_note_block(text)
        if not block:
            return False

        self.notes_page.append_block(block)
        self._notes_dirty = True
        self._flush_notes()
        self.go_to_notes()
        return True

    def add_ai_summary_to_notes(self):
        text = (self.txt_ai_summary.toPlainText() or "").strip()
        if not text:
            self._message_dialog("Notes", "There is no AI-generated text to add.", width=440)
            return

        self.add_ai_text_to_notes(text)

    # ---------- Notes ----------
    def refresh_notes_ui(self, *, refresh_profile: bool = True):
        self.txt_notes.blockSignals(True)

        if self.current_project_id is None:
            load_project_notes(
                project_id=None,
                notes_controller=self.notes_controller,
                notes_page=self.notes_page,
            )
            self.project_activity_rows = []
            if hasattr(self, "projects_ui_controller"):
                self.projects_ui_controller._refresh_project_launcher_cards()
            self.txt_notes.blockSignals(False)
            return

        load_project_notes(
            project_id=self.current_project_id,
            notes_controller=self.notes_controller,
            notes_page=self.notes_page,
        )
        self.txt_notes.blockSignals(False)

        if refresh_profile:
            self.refresh_activity_ui()
        else:
            self.refresh_activity_ui_for_project(self.current_project_id)

    def insert_notes_chart(self):
        if self.current_project_id is None:
            self._message_dialog("Notes chart", "Open an active project first.", width=420)
            return

        self.refresh_activity_profile_ui()
        profile = getattr(self.activity_profile_page, "profile", None) if hasattr(self, "activity_profile_page") else None
        pcap_summary = getattr(getattr(self, "pcap_page", None), "summary", None)

        def choose_chart(choices: list[str]) -> tuple[str, bool]:
            return self._item_choice_dialog(
                "Insert chart",
                "Choose a chart to insert into Notes:",
                choices,
                width=460,
            )

        result = insert_notes_chart_action(
            parent=self,
            project_id=self.current_project_id,
            notes_page=self.notes_page,
            profile=profile,
            pcap_summary=pcap_summary,
            choose_chart=choose_chart,
        )
        if result.cancelled:
            return
        if result.no_data:
            self._message_dialog("Notes chart", result.error, result.details, width=520)
            return
        if not result.inserted:
            self._message_dialog("Notes chart", result.error, result.details, width=520)
            return

        self._notes_dirty = True
        self._flush_notes()

    def export_notes_word(self):
        result = export_notes_word_action(
            self,
            project_id=self.current_project_id,
            project_name=self.current_project_name,
            notes_page=self.notes_page,
        )
        if result.cancelled:
            return
        if not result.exported:
            if self.current_project_id is None:
                self._message_dialog("Notes export", result.error, width=420)
                return
            self._message_dialog("Notes export", "Failed to export notes.", result.error, width=520)
            return

        self._message_dialog("Notes export", "Notes exported to Word document.", result.file_path, width=560)

    def export_notes_html(self):
        result = export_notes_html_action(
            self,
            project_id=self.current_project_id,
            project_name=self.current_project_name,
            notes_page=self.notes_page,
        )
        self._handle_notes_export_result(result, "HTML")

    def export_notes_pdf(self):
        result = export_notes_pdf_action(
            self,
            project_id=self.current_project_id,
            project_name=self.current_project_name,
            notes_page=self.notes_page,
        )
        self._handle_notes_export_result(result, "PDF")

    def _handle_notes_export_result(self, result, label: str) -> None:
        if result.cancelled:
            return
        if not result.exported:
            if self.current_project_id is None:
                self._message_dialog("Notes export", result.error, width=420)
                return
            self._message_dialog("Notes export", f"Failed to export notes to {label}.", result.error, width=520)
            return

        self._message_dialog("Notes export", f"Notes exported to {label}.", result.file_path, width=560)

    def refresh_activity_ui_for_project(self, project_id: int | None):
        self.project_activity_rows = []

        if project_id is None:
            if hasattr(self, "projects_ui_controller"):
                self.projects_ui_controller._refresh_project_launcher_cards()
            return

        rows = self.notes_controller.load_activity(project_id)
        if not rows:
            if hasattr(self, "projects_ui_controller"):
                self.projects_ui_controller._refresh_project_launcher_cards()
            return

        for r in rows:
            ts = r["created_at"]
            et = r["event_type"]
            msg = r["message"] or ""
            if hasattr(self, "projects_ui_controller"):
                label = self.projects_ui_controller.activity_label(str(et), str(msg))
            else:
                label = str(et).replace("_", " ").title()
            self.project_activity_rows.append({
                "created_at": str(ts or ""),
                "event": label,
                "detail": str(msg or ""),
            })
        if hasattr(self, "projects_ui_controller"):
            self.projects_ui_controller._refresh_project_launcher_cards()

    def refresh_activity_ui(self):
        self.refresh_activity_ui_for_project(self.current_project_id)
        self.refresh_activity_profile_ui()

    def on_notes_changed(self):
        if self.current_project_id is None:
            return
        self._notes_dirty = True
        self._notes_timer.start(800)

    def _flush_notes(self):
        if not self._notes_dirty or self.current_project_id is None:
            return

        try:
            saved = save_project_notes(
                project_id=self.current_project_id,
                notes_controller=self.notes_controller,
                notes_page=self.notes_page,
            )
        except Exception:
            return

        if saved:
            self._notes_dirty = False

    def clear_dataset_context(self) -> None:
        # reset basic dataset state
        self.current_folder = None
        self._current_flow = None
        self._conversation_on = False
        self._flows_expanded = False

        # reset flow storage / table
        self.flow_controller.set_flows([])
        self.model.set_flows([])

        # reset search / proxy / selection
        self.search.blockSignals(True)
        self.search.setText("")
        self.search.blockSignals(False)

        self.proxy.set_filter_text("")
        self.proxy.clear_conversation()

        if self.table.selectionModel():
            self.table.clearSelection()

        # reset explore details / labels
        self.explore_ui_controller.update_detail(None)
        self.explore_ui_controller.update_mode_label()
        self.explore_ui_controller.update_conversation_summary()
        self.explore_ui_controller.update_loaded_label()
        self.explore_ui_controller.update_load_more_enabled()
        self.explore_ui_controller.update_showing()

        self.lbl_path.setText("No dataset loaded")
        if hasattr(self, "explore_ui_controller"):
            self.explore_ui_controller.set_json_stats_text("", include_counts=False)
        elif hasattr(self, "lbl_stats"):
            self.lbl_stats.setText("")
        if hasattr(self, "lbl_json_meta"):
            self.lbl_json_meta.setText("")
        self.lbl_conv_summary.clear()
        self.lbl_conv_summary.hide()
        self.lbl_mode.clear()
        self.lbl_mode.hide()

        for rows in getattr(self, "summary_preview_rows", {}).values():
            self.dataset_controller.clear_summary_preview_rows(rows)

        # reset AI output
        self.txt_ai_summary.clear()

        # reset flow details panel state
        if hasattr(self, "details_panel"):
            self.details_panel.show()
        if hasattr(self, "btn_expand_flows"):
            self.btn_expand_flows.setText("Expand Flows")

        # reset registry
        if hasattr(self, "registry_page"):
            self.registry_page.set_dataset("", [], [])

        # reset listing
        if hasattr(self, "listing_page"):
            try:
                self.listing_page.set_dataset("", [], [])
            except Exception:
                pass

    # ---------- clipboard ----------
    def copy_text(self, text: str):
        if text:
            QGuiApplication.clipboard().setText(text)

    def current_value(self, key: str) -> str:
        if not self._current_flow:
            return ""
        v = self._current_flow.get(key, "")
        return "" if v is None else str(v)    
    
def main():
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
