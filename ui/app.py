import sys
from core.ai.assistant_service import AIAssistantService
import ipaddress
from ui.registry_page import RegistryPage
import html
from datetime import datetime
from pathlib import Path
from typing import Any
from core.protocols import format_ip_proto
from ui.findings_page import FindingsPage

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QTimer, QObject, QThread, Signal
from PySide6.QtGui import QGuiApplication, QColor, QIcon, QFont, QPixmap
from PySide6.QtWidgets import (
    QApplication, QWidget, QHBoxLayout, QVBoxLayout, QGridLayout,
    QPushButton, QLabel, QStackedWidget, QFileDialog,
    QTextEdit, QTabWidget, QTableView, QLineEdit,
    QSplitter, QFormLayout, QGroupBox,
    QListWidget, QListWidgetItem, QMessageBox, QInputDialog,
    QComboBox, QMenu, QFrame, QSizePolicy, QScrollArea, QHeaderView
)

from core.loader import load_folder
from core.analyzer import top_src_ips, top_dst_ips, top_applications, top_protocols
from core.db import (
    init_db, create_project, list_projects, get_project,
    delete_project, add_dataset_load, list_recent_datasets,
    add_finding, list_findings, get_finding,
    update_finding, delete_finding,
    get_project_notes, set_project_notes,
    list_activity, add_activity
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

def esc(s: Any) -> str:
    return html.escape("" if s is None else str(s))

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

# ---------- Table Model ----------
class FlowTableModel(QAbstractTableModel):
    COLUMNS = [
        ("src_ip", "Source IP"),
        ("src_port", "Source Port"),
        ("dst_ip", "Destination IP"),
        ("dst_port", "Destination Port"),
        ("protocol", "Protocol"),
        ("application_name", "Application"),
        ("bidirectional_bytes", "Bytes"),
        ("bidirectional_duration_ms", "Duration(ms)"),
        ("requested_server_name", "SNI"),
    ]

    def __init__(self, flows: list[dict[str, Any]] | None = None):
        super().__init__()
        self._flows: list[dict[str, Any]] = flows or []
        self._ip_cache: dict[str, bool] = {}
        self._bg_private = QColor("#E8F5E9")  # light green
        self._bg_public = QColor("#FFEBEE")   # light red

    def set_flows(self, flows: list[dict[str, Any]]):
        self.beginResetModel()
        self._flows = flows
        self._ip_cache.clear()
        self.endResetModel()

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._flows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.COLUMNS[section][1]
        return str(section + 1)

    def _cached_is_private(self, ip: str) -> bool:
        if ip in self._ip_cache:
            return self._ip_cache[ip]
        val = is_private_ip(ip)
        self._ip_cache[ip] = val
        return val

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None

        flow = self._flows[index.row()]
        key = self.COLUMNS[index.column()][0]

        if role == Qt.DisplayRole:
            val = flow.get(key, "")
            if key == "protocol":
                return format_ip_proto(val)
            return "" if val is None else str(val)

        if role == Qt.ToolTipRole:
            val = flow.get(key, "")
            if key == "protocol":
                return format_ip_proto(val)
            return "" if val is None else str(val)

        if role == Qt.UserRole:
            val = flow.get(key)
            if isinstance(val, (int, float)):
                return val
            try:
                return int(val)
            except Exception:
                return 0

        if role == Qt.BackgroundRole and key in ("src_ip", "dst_ip"):
            ip = flow.get(key, "")
            if not isinstance(ip, str) or not ip:
                return None
            return self._bg_private if self._cached_is_private(ip) else self._bg_public

        return None

# ---------- Proxy ----------
class NumericSortProxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.filter_text = ""
        self.conv_a: str | None = None
        self.conv_b: str | None = None

    def set_filter_text(self, text: str):
        self.filter_text = (text or "").lower()
        self.invalidate()

    def set_conversation(self, a: str | None, b: str | None):
        self.conv_a = a
        self.conv_b = b
        self.invalidate()

    def clear_conversation(self):
        self.conv_a = None
        self.conv_b = None
        self.invalidate()

    def filterAcceptsRow(self, row: int, parent: QModelIndex) -> bool:
        model = self.sourceModel()

        if self.conv_a and self.conv_b:
            src_ip = model.data(model.index(row, 0, parent), Qt.DisplayRole) or ""
            dst_ip = model.data(model.index(row, 2, parent), Qt.DisplayRole) or ""
            a, b = self.conv_a, self.conv_b
            if not ((src_ip == a and dst_ip == b) or (src_ip == b and dst_ip == a)):
                return False

        if not self.filter_text:
            return True

        for col in range(model.columnCount()):
            val = model.data(model.index(row, col, parent), Qt.DisplayRole)
            if val and self.filter_text in str(val).lower():
                return True
        return False

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:
        l = self.sourceModel().data(left, Qt.UserRole)
        r = self.sourceModel().data(right, Qt.UserRole)
        if isinstance(l, (int, float)) and isinstance(r, (int, float)):
            return l < r
        ls = self.sourceModel().data(left, Qt.DisplayRole) or ""
        rs = self.sourceModel().data(right, Qt.DisplayRole) or ""
        return str(ls) < str(rs)
    
class AITextWorker(QObject):
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.fn(*self.args, **self.kwargs)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

# ---------- Main App ----------
class App(QWidget):
    def build_home_page(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

    # ---------- header (logo + title) ----------
        header = QHBoxLayout()
        header.setSpacing(14)

        logo = QLabel()
        logo.setFixedSize(64, 64)

        icon_path = self.project_dir / "assets" / "ConduVia.ico"
        pm = QPixmap(str(icon_path)) if icon_path.exists() else QPixmap()

        if not pm.isNull():
            logo.setPixmap(pm.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        title = QLabel("ConduVia")
        f = QFont()
        f.setPointSize(30)
        f.setBold(True)
        title.setFont(f)

        subtitle = QLabel("Network flow analysis")
        subtitle.setStyleSheet("color: #666666; font-size: 14px;")

        title_col.addWidget(title)
        title_col.addWidget(subtitle)

        header.addWidget(logo, 0)
        header.addLayout(title_col, 1)
        header.addStretch()

        layout.addLayout(header) 

    # ---------- main card ----------
        card = QFrame()
        card.setFrameShape(QFrame.StyledPanel)
        card.setStyleSheet("""
        QFrame {
            background: #ffffff;
            border: 1px solid #e6e6e6;
            border-radius: 12px;
        }
    """)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 18, 20, 18)
        card_layout.setSpacing(12)

    # Quick start block
        qs_title = QLabel("Quick start")
        qs_title.setStyleSheet("font-size: 14px; font-weight: 600; color: #111827;")

        info = QLabel(
        "1) Create/Open a project\n"
        "2) Load a dataset folder\n"        
    )
        info.setStyleSheet("color: #374151; font-size: 13px;")
        info.setWordWrap(True)

    # Actions
        actions = QHBoxLayout()
        actions.setSpacing(10)

        self.btn_home_projects = QPushButton("Projects")
        self.btn_home_explore = QPushButton("Explore")
        self.btn_home_registry = QPushButton("Registry")

        for b in (self.btn_home_projects, self.btn_home_explore, self.btn_home_registry):
            b.setFixedHeight(36)
                
        # subtle style for others
        for b in (self.btn_home_projects, self.btn_home_explore, self.btn_home_registry):
            b.setStyleSheet("""
            QPushButton {
                background: #ffffff;
                color: #111827;
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                padding: 0 12px;
            }
            QPushButton:hover { background: #f9fafb; }
        """)

        actions.addWidget(self.btn_home_projects)
        actions.addWidget(self.btn_home_explore)
        actions.addWidget(self.btn_home_registry)
        actions.addStretch()

        card_layout.addWidget(qs_title)
        card_layout.addWidget(info)
        card_layout.addSpacing(6)
        card_layout.addLayout(actions)

        layout.addWidget(card)
        layout.addStretch()

        return page
    
    def _ensure_pair_loaded(self, src: str, dst: str):
        """Ensure at least one flow for (src,dst) exists in loaded_flows; expand paging if needed."""
        if not self.flows:
            return
        
        # već učitano? brzo provjeri
        for f in self.loaded_flows:
            if not isinstance(f, dict):
                continue
            s = str(f.get("src_ip") or "")
            d = str(f.get("dst_ip") or "")
            if (s == src and d == dst) or (s == dst and d == src):
                return

        # nađi prvi match u cijelom datasetu
        hit_idx = -1
        for i, f in enumerate(self.flows):
            if not isinstance(f, dict):
                continue
            s = str(f.get("src_ip") or "")
            d = str(f.get("dst_ip") or "")
            if (s == src and d == dst) or (s == dst and d == src):
                hit_idx = i
                break

        if hit_idx < 0:
            return

        # proširi loaded_flows do tog indexa (uz mali buffer)
        end = min(len(self.flows), max(hit_idx + 1, len(self.loaded_flows)) + self.PAGE_SIZE)
        self.loaded_flows = self.flows[:end]
        self.model.set_flows(self.loaded_flows)
        self.update_loaded_label()
        self.update_load_more_enabled()
        self.update_showing()

    def _scroll_to_flow_pair(self, src: str, dst: str):
        for r_idx in range(self.proxy.rowCount()):
            idx0 = self.proxy.index(r_idx, 0)
            src_ip = self.proxy.data(idx0, Qt.DisplayRole)
            dst_ip = self.proxy.data(self.proxy.index(r_idx, 2), Qt.DisplayRole)

            if (src_ip == src and dst_ip == dst) or (src_ip == dst and dst_ip == src):
                self.table.scrollTo(idx0, QTableView.PositionAtCenter)
                return idx0, r_idx

        return None, None

    def _select_flow_pair(self, src: str, dst: str):
        self.table.clearSelection()

        idx0, r_idx = self._scroll_to_flow_pair(src, dst)
        if idx0 is None:
            return False

        self.table.setCurrentIndex(idx0)
        self.table.selectRow(r_idx)
        self.update_showing()
        return True

    def go_to_explore_flows(self):
        self.go_page(self.IDX_EXPLORE, self._nav_explore)
        self.tabs.setCurrentIndex(1)

    def leave_conversation(self, clear_search: bool = False):
        self.proxy.clear_conversation()
        self._conversation_on = False
        self.btn_toggle_conv.setText("Conversation: OFF")
        self.update_mode_label()
        self.update_conversation_summary()

        if clear_search:
            self.search.setText("")

        self.update_showing()

    def enter_conversation(self, src: str, dst: str):
        if not src or not dst:
            return

        self._ensure_pair_loaded(src, dst)
        self.proxy.set_conversation(src, dst)
        self._conversation_on = True
        self.btn_toggle_conv.setText("Conversation: ON")
        self.update_mode_label()
        self.update_showing()
        self.update_conversation_summary()
        self.proxy.invalidate()

    def _build_sidebar(self) -> QVBoxLayout:
        sidebar = QVBoxLayout()

        self.btn_nav_projects = QPushButton("Projects")
        self.btn_nav_explore = QPushButton("Explore")
        self.btn_nav_registry = QPushButton("Registry")

        for b in (self.btn_nav_projects, self.btn_nav_explore, self.btn_nav_registry):
            b.setObjectName("NavButton")
            b.setFixedHeight(40)

                # aktivni button reference (za highlight)
        self._nav_projects = self.btn_nav_projects
        self._nav_explore = self.btn_nav_explore
        self._nav_registry = self.btn_nav_registry

        sidebar.addWidget(self.btn_nav_projects)
        sidebar.addWidget(self.btn_nav_explore)
        sidebar.addWidget(self.btn_nav_registry)
        sidebar.addStretch()

        return sidebar

    def _wire_navigation(self) -> None:
        self.btn_nav_projects.clicked.connect(lambda: self.go_page(self.IDX_PROJECTS, self._nav_projects))
        self.btn_nav_explore.clicked.connect(lambda: self.go_page(self.IDX_EXPLORE, self._nav_explore))
        self.btn_nav_registry.clicked.connect(lambda: self.go_page(self.IDX_REGISTRY, self._nav_registry))

    def _wire_ui(self) -> None:
        # 1) sidebar navigation
        self._wire_navigation()

        # 3) Explore - search filter
        self.search.textChanged.connect(self.proxy.set_filter_text)
        self.search.textChanged.connect(self.update_showing)

        # 4) Explore - table selection -> details
        self.table.selectionModel().selectionChanged.connect(self.on_row_selected)

        # 5) Explore - scrolling auto paging
        self.table.verticalScrollBar().valueChanged.connect(self.on_table_scrolled)

        # 6) Paging controls
        self.btn_load_more.clicked.connect(self.load_next_page)
        self.cmb_page_size.currentTextChanged.connect(self.on_page_size_changed)

        # 7) Explore actions
        self.btn_load.clicked.connect(self.load_dataset_dialog)
        self.btn_ai_summary.clicked.connect(self.generate_ai_summary)
        self.btn_add_ai_to_notes.clicked.connect(self.add_ai_summary_to_notes)
        self.btn_toggle_conv.clicked.connect(self.toggle_conversation)
        self.btn_expand_flows.clicked.connect(self.toggle_flows_expanded)
        self.btn_mark_finding.clicked.connect(self.mark_as_finding)

        # 7A) AI explain flow
        self.btn_ai_explain.clicked.connect(self.explain_selected_flow)

        # 8) Copy buttons
        self.btn_copy_src.clicked.connect(lambda: self.copy_text(self.current_value("src_ip")))
        self.btn_copy_dst.clicked.connect(lambda: self.copy_text(self.current_value("dst_ip")))
        self.btn_copy_sni.clicked.connect(lambda: self.copy_text(self.current_value("requested_server_name")))

        # 9) Filter buttons
        self.btn_filter_src.clicked.connect(lambda: self.apply_filter_ip(self.current_value("src_ip")))
        self.btn_filter_dst.clicked.connect(lambda: self.apply_filter_ip(self.current_value("dst_ip")))

        # 10) Projects page
        self.btn_new_project.clicked.connect(self.create_project_dialog)
        self.btn_refresh_projects.clicked.connect(self.refresh_projects)
        self.btn_open_project.clicked.connect(self.open_selected_project)
        self.btn_delete_project.clicked.connect(self.delete_selected_project)
        self.projects_list.itemSelectionChanged.connect(self.on_project_selected_preview)
        self.btn_open_dataset.clicked.connect(self.open_selected_dataset)

        # 10b) Double click shortcuts
        self.projects_list.itemDoubleClicked.connect(lambda _: self.open_selected_project())
        self.recent_list.itemDoubleClicked.connect(lambda _: self.open_selected_dataset())

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

    def _post_init(self) -> None:
        pass
    
    def update_conversation_summary(self):
        if not self._conversation_on:
            self.lbl_conv_summary.clear()
            self.lbl_conv_summary.hide()
            return

        rows = self.proxy.rowCount()
        if rows == 0:
            self.lbl_conv_summary.clear()
            self.lbl_conv_summary.hide()
            return

        total_bytes = 0
        apps = {}

        for r in range(rows):
            idx_bytes = self.proxy.index(r, 6)
            idx_app = self.proxy.index(r, 5)

            b = self.proxy.data(idx_bytes, Qt.DisplayRole)
            app = self.proxy.data(idx_app, Qt.DisplayRole) or ""

            try:
                total_bytes += int(b)
            except Exception:
                pass

            apps[app] = apps.get(app, 0) + 1

        top_app = max(apps, key=apps.get) if apps else "-"

        self.lbl_conv_summary.setText(
            f"Conversation summary — Flows: {rows} | Bytes: {total_bytes:,} | Top app: {top_app}"
        )
        self.lbl_conv_summary.show()

    def _open_from_registry_search(self, q: str):
        self.go_to_explore_flows()
        self.leave_conversation(clear_search=False)
        self.search.setText(q or "")
        self.search.setFocus()
        self.update_showing()
        
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ConduVia")
        self.setMinimumSize(1100, 700)
        self.resize(1200, 800)

        init_db()
        self.project_dir = Path(__file__).resolve().parent.parent
        self._init_state()

        self.ai_service = AIAssistantService()

        self._build_ui()
        self._wire_ui()
        self._post_init()

        # init
        self.refresh_projects()
        self.update_detail(None)
        self.update_mode_label()
        self.refresh_findings_ui()
        self.refresh_notes_ui()

    def _init_state(self) -> None:
        # State
        self.current_project_id: int | None = None
        self.current_project_name: str = ""
        self.current_folder: Path | None = None

        self.flows: list[dict[str, Any]] = []          # all flows in memory (for now)
        self.loaded_flows: list[dict[str, Any]] = []   # currently shown in table
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

        # Findings in-memory cache (for filter/sort)
        self._findings_rows: list[Any] = []
        self._findings_view_rows: list[Any] = []

        # AI background worker
        self._ai_thread: QThread | None = None
        self._ai_worker: AITextWorker | None = None
        self._ai_mode: str | None = None

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
        self.IDX_EXPLORE = 1
        self.IDX_REGISTRY = 2

        # -------- Projects page --------
        projects_page = QWidget()
        projects_layout = QVBoxLayout(projects_page)

        self.lbl_active_project = QLabel("Active project: (none)")

        btn_row = QHBoxLayout()
        self.btn_new_project = QPushButton("New project")
        self.btn_open_project = QPushButton("Open selected")
        self.btn_refresh_projects = QPushButton("Refresh")
        self.btn_delete_project = QPushButton("Delete selected")
        btn_row.addWidget(self.btn_new_project)
        btn_row.addWidget(self.btn_open_project)
        btn_row.addWidget(self.btn_refresh_projects)
        btn_row.addWidget(self.btn_delete_project)

        self.projects_list = QListWidget()
        self.projects_info = QTextEdit()
        self.projects_info.setReadOnly(True)

        self.lbl_recent = QLabel("Recent datasets:")
        self.recent_list = QListWidget()

        recent_btn_row = QHBoxLayout()
        self.btn_open_dataset = QPushButton("Open dataset")
        recent_btn_row.addWidget(self.btn_open_dataset)
        recent_btn_row.addStretch()

        projects_layout.addWidget(self.lbl_active_project)
        projects_layout.addLayout(btn_row)
        projects_layout.addWidget(QLabel("Projects:"))
        projects_layout.addWidget(self.projects_list, 2)
        projects_layout.addWidget(self.projects_info, 1)
        projects_layout.addWidget(self.lbl_recent)
        projects_layout.addWidget(self.recent_list, 1)
        projects_layout.addLayout(recent_btn_row)

        # -------- Explore page --------
        explore_container = QWidget()
        explore_layout = QVBoxLayout(explore_container)

        self.lbl_project_banner = QLabel("Project: (none)")
        self.btn_load = QPushButton("Load dataset folder")
        self.lbl_path = QLabel("No dataset loaded")
        self.lbl_stats = QLabel("")
        self.lbl_showing = QLabel("")
        self.lbl_mode = QLabel("")
        self.lbl_mode.hide()

        self.lbl_conv_summary = QLabel("")
        self.lbl_conv_summary.hide()

        paging_row = QHBoxLayout()
        self.lbl_loaded = QLabel("")
        self.btn_load_more = QPushButton("Load next")
        self.btn_load_more.setEnabled(False)

        paging_row.addWidget(self.lbl_loaded)
        paging_row.addStretch()
        paging_row.addWidget(QLabel("Page size:"))
        self.cmb_page_size = QComboBox()
        self.cmb_page_size.addItems(["1000", "2000", "5000", "10000"])
        self.cmb_page_size.setCurrentText("2000")
        paging_row.addWidget(self.cmb_page_size)
        paging_row.addWidget(self.btn_load_more)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search IP / SNI / app...")

        self.tabs = QTabWidget()

        summary_tab = QWidget()
        summary_layout = QVBoxLayout(summary_tab)
        summary_layout.setContentsMargins(8, 8, 8, 8)
        summary_layout.setSpacing(10)

        self.btn_ai_summary = QPushButton("Generate AI Summary")
        self.btn_add_ai_to_notes = QPushButton("Add AI to Notes")
        self.btn_add_ai_to_notes.setEnabled(True)

        summary_btn_row = QHBoxLayout()
        summary_btn_row.setSpacing(8)
        summary_btn_row.addWidget(self.btn_ai_summary)
        summary_btn_row.addWidget(self.btn_add_ai_to_notes)
        summary_btn_row.addStretch()

        summary_layout.addLayout(summary_btn_row)

        summary_split = QSplitter(Qt.Horizontal)

        # ----- Left: Dataset summary -----
        dataset_panel = QWidget()
        dataset_layout = QVBoxLayout(dataset_panel)
        dataset_layout.setContentsMargins(0, 0, 0, 0)
        dataset_layout.setSpacing(8)

        self.lbl_dataset_summary = QLabel("Dataset summary")
        self.lbl_dataset_summary.setObjectName("SectionTitle")

        dataset_grid = QGridLayout()
        dataset_grid.setContentsMargins(0, 0, 0, 0)
        dataset_grid.setHorizontalSpacing(10)
        dataset_grid.setVerticalSpacing(10)

        # Top source IPs
        self.box_top_src = QGroupBox("Top source IPs")
        self.box_top_src.setObjectName("SummaryCard")
        box_top_src_layout = QVBoxLayout(self.box_top_src)
        self.txt_top_src = QTextEdit()
        self.txt_top_src.setReadOnly(True)
        self.txt_top_src.setObjectName("SummaryTextBox")
        box_top_src_layout.addWidget(self.txt_top_src)

        # Top destination IPs
        self.box_top_dst = QGroupBox("Top destination IPs")
        self.box_top_dst.setObjectName("SummaryCard")
        box_top_dst_layout = QVBoxLayout(self.box_top_dst)
        self.txt_top_dst = QTextEdit()
        self.txt_top_dst.setReadOnly(True)
        self.txt_top_dst.setObjectName("SummaryTextBox")
        box_top_dst_layout.addWidget(self.txt_top_dst)

        # Top protocols
        self.box_top_proto = QGroupBox("Top protocols")
        self.box_top_proto.setObjectName("SummaryCard")
        box_top_proto_layout = QVBoxLayout(self.box_top_proto)
        self.txt_top_proto = QTextEdit()
        self.txt_top_proto.setReadOnly(True)
        self.txt_top_proto.setObjectName("SummaryTextBox")
        box_top_proto_layout.addWidget(self.txt_top_proto)

        # Top applications
        self.box_top_apps = QGroupBox("Top applications")
        self.box_top_apps.setObjectName("SummaryCard")
        box_top_apps_layout = QVBoxLayout(self.box_top_apps)
        self.txt_top_apps = QTextEdit()
        self.txt_top_apps.setReadOnly(True)
        self.txt_top_apps.setObjectName("SummaryTextBox")
        box_top_apps_layout.addWidget(self.txt_top_apps)

        dataset_grid.addWidget(self.box_top_src, 0, 0)
        dataset_grid.addWidget(self.box_top_dst, 0, 1)
        dataset_grid.addWidget(self.box_top_proto, 1, 0)
        dataset_grid.addWidget(self.box_top_apps, 1, 1)

        dataset_layout.addWidget(self.lbl_dataset_summary)
        dataset_layout.addLayout(dataset_grid, 1)

        # ----- Right: AI assistant output -----
        ai_panel = QWidget()
        ai_layout = QVBoxLayout(ai_panel)
        ai_layout.setContentsMargins(0, 0, 0, 0)
        ai_layout.setSpacing(6)

        self.lbl_ai_summary = QLabel("AI assistant output")
        self.lbl_ai_summary.setObjectName("SectionTitle")

        self.txt_ai_summary = QTextEdit()
        self.txt_ai_summary.setReadOnly(True)
        self.txt_ai_summary.setPlaceholderText("AI summary will appear here...")
        self.txt_ai_summary.setMinimumWidth(520)

        ai_layout.addWidget(self.lbl_ai_summary)
        ai_layout.addWidget(self.txt_ai_summary, 1)

        summary_split.addWidget(dataset_panel)
        summary_split.addWidget(ai_panel)
        summary_split.setStretchFactor(0, 4)
        summary_split.setStretchFactor(1, 5)
        summary_split.setCollapsible(0, False)
        summary_split.setCollapsible(1, False)

        summary_layout.addWidget(summary_split, 1)

        self.tabs.addTab(summary_tab, "Summary")

        flows_tab = QWidget()
        flows_tab_layout = QVBoxLayout(flows_tab)
        flows_tab_layout.setContentsMargins(8, 8, 8, 8)
        flows_tab_layout.setSpacing(8)

        # ----- FLOW TOOLBAR -----        
        toolbar_wrap = QFrame()
        toolbar_wrap.setObjectName("FlowToolbarCard")

        toolbar = QHBoxLayout(toolbar_wrap)
        toolbar.setContentsMargins(10, 10, 10, 10)
        toolbar.setSpacing(10)

        left_actions = QHBoxLayout()
        left_actions.setSpacing(8)

        right_actions = QHBoxLayout()
        right_actions.setSpacing(8)

        self.btn_copy_src = QPushButton("Copy source IP")
        self.btn_copy_dst = QPushButton("Copy destination IP")
        self.btn_copy_sni = QPushButton("Copy SNI")

        self.btn_filter_src = QPushButton("Filter source")
        self.btn_filter_dst = QPushButton("Filter destination")

        self.btn_toggle_conv = QPushButton("Conversation: OFF")
        self.btn_expand_flows = QPushButton("Expand Flows")
        self.btn_mark_finding = QPushButton("Mark as Finding")
        self.btn_ai_explain = QPushButton("Explain with AI")

        for b in (
            self.btn_copy_src, self.btn_copy_dst, self.btn_copy_sni,
            self.btn_filter_src, self.btn_filter_dst,
            self.btn_toggle_conv, self.btn_expand_flows,
            self.btn_mark_finding, self.btn_ai_explain
        ):
            b.setFixedHeight(34)

        left_actions.addWidget(self.btn_copy_src)
        left_actions.addWidget(self.btn_copy_dst)
        left_actions.addWidget(self.btn_copy_sni)
        left_actions.addSpacing(6)
        left_actions.addWidget(self.btn_filter_src)
        left_actions.addWidget(self.btn_filter_dst)

        right_actions.addWidget(self.btn_toggle_conv)
        right_actions.addWidget(self.btn_expand_flows)
        right_actions.addWidget(self.btn_mark_finding)
        right_actions.addWidget(self.btn_ai_explain)

        toolbar.addLayout(left_actions)
        toolbar.addStretch()
        toolbar.addLayout(right_actions)

        flows_tab_layout.addWidget(toolbar_wrap)
        self.splitter = QSplitter(Qt.Horizontal)

        self.table = QTableView()
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
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)   # Source IP
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)   # Source Port
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)   # Destination IP
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)   # Destination Port
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)   # Protocol
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)   # App
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)   # Bytes
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)   # Duration
        header.setSectionResizeMode(8, QHeaderView.Stretch)            # SNI

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

        # Notes tab
        notes_tab = QWidget()
        notes_root = QHBoxLayout(notes_tab)

        left = QVBoxLayout()
        left.addWidget(QLabel("Project notes"))
        self.txt_notes = QTextEdit()
        self.txt_notes.setPlaceholderText("Write case notes here… (autosave)")
        left.addWidget(self.txt_notes, 1)

        right = QVBoxLayout()
        right.addWidget(QLabel("Activity log"))
        self.lst_activity = QListWidget()
        right.addWidget(self.lst_activity, 1)

        notes_root.addLayout(left, 2)
        notes_root.addLayout(right, 1)

        self.tabs.addTab(notes_tab, "Notes")

        # Explore layout
        explore_layout.addWidget(self.lbl_project_banner)
        explore_layout.addWidget(self.btn_load)
        explore_layout.addWidget(self.lbl_path)
        explore_layout.addWidget(self.lbl_stats)
        explore_layout.addLayout(paging_row)
        explore_layout.addWidget(self.lbl_showing)
        explore_layout.addWidget(self.lbl_mode)
        explore_layout.addWidget(self.lbl_conv_summary)
        explore_layout.addWidget(self.search)
        explore_layout.addWidget(self.tabs, 1)

        # Pages
        self.pages.addWidget(projects_page)
        self.pages.addWidget(explore_container)

        self.registry_page = RegistryPage()
        self.pages.addWidget(self.registry_page)

        self.pages.setCurrentIndex(self.IDX_PROJECTS)
        self._set_active_nav(self._nav_projects)

        root.addLayout(sidebar, 1)
        root.addWidget(self.pages, 8)
        outer.addLayout(root, 1)

        # footer
        footer = QHBoxLayout()
        footer.addStretch()
        self.lbl_signature = QLabel("by _Igy_")
        self.lbl_signature.setObjectName("Signature")
        footer.addWidget(self.lbl_signature)
        outer.addLayout(footer)
        
    def _set_active_nav(self, active: QPushButton):
        for b in (self._nav_projects, self._nav_explore, self._nav_registry):
            b.setProperty("active", b is active)
            b.style().unpolish(b)
            b.style().polish(b)
            b.update()

    def go_page(self, idx: int, active_btn: QPushButton):
        self.pages.setCurrentIndex(idx)
        self._set_active_nav(active_btn)

    def _open_from_registry(self, src: str, dst: str):
        self.go_to_explore_flows()
        self.search.setText("")
        self.enter_conversation(src, dst)

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
            self.load_dataset_dialog()
            event.accept()
            return

        if key == Qt.Key_Escape:
            self.leave_conversation(clear_search=True)
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

    # ---------- Paging ----------
    def on_page_size_changed(self, txt: str):
        try:
            self.PAGE_SIZE = max(250, int(txt))
        except Exception:
            self.PAGE_SIZE = 2000
        self.update_loaded_label()
        self.update_load_more_enabled()

    def update_loaded_label(self):
        total = len(self.flows)
        loaded = len(self.loaded_flows)
        if total:
            self.lbl_loaded.setText(f"Loaded: {loaded} / {total}")
        else:
            self.lbl_loaded.setText("")

    def update_load_more_enabled(self):
        self.btn_load_more.setEnabled(bool(self.flows) and len(self.loaded_flows) < len(self.flows))

    def load_next_page(self):
        if not self.flows:
            return
        start = len(self.loaded_flows)
        end = min(len(self.flows), start + self.PAGE_SIZE)
        if start >= end:
            return

        self.loaded_flows = self.flows[:end]
        self.model.set_flows(self.loaded_flows)
        self.update_loaded_label()
        self.update_load_more_enabled()
        self.update_showing()

    def on_table_scrolled(self, value: int):
        if not self.flows:
            return
        if self._conversation_on:
            return
        bar = self.table.verticalScrollBar()
        if bar.maximum() <= 0:
            return
        if value >= int(bar.maximum() * 0.92):
            if len(self.loaded_flows) < len(self.flows):
                self.load_next_page()

    # ---------- Projects ----------
    def refresh_projects(self):
        self.projects_list.clear()
        projects = list_projects()
        for p in projects:
            item = QListWidgetItem(f"{p.name} (id={p.id})")
            item.setData(Qt.UserRole, p.id)
            self.projects_list.addItem(item)

    def create_project_dialog(self):
        name, ok = QInputDialog.getText(self, "New project", "Project name:")
        if not ok:
            return
        name = (name or "").strip()
        if not name:
            return

        desc, ok2 = QInputDialog.getMultiLineText(self, "New project", "Description (optional):")
        if not ok2:
            desc = ""

        base = QFileDialog.getExistingDirectory(self, "Select project base folder (optional)")
        base = base or ""

        try:
            pid = create_project(name=name, description=desc, base_folder=base)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            return

        self.set_active_project(pid)
        self.refresh_projects()
        self.refresh_recent_datasets(pid)
        self.refresh_findings_ui()
        self.refresh_notes_ui()

    def on_project_selected_preview(self):
        item = self.projects_list.currentItem()
        if not item:
            self.projects_info.setText("")
            self.recent_list.clear()
            return

        pid = int(item.data(Qt.UserRole))
        p = get_project(pid)
        if not p:
            return

        info = []
        info.append(f"Name: {p.name}")
        info.append(f"ID: {p.id}")
        info.append(f"Base folder: {p.base_folder or '-'}")
        info.append(f"Created: {p.created_at}")
        info.append(f"Updated: {p.updated_at}")
        info.append("")
        info.append(p.description or "")
        self.projects_info.setText("\n".join(info))

        self.refresh_recent_datasets(pid)

    def open_selected_project(self):
        item = self.projects_list.currentItem()
        if not item:
            return
        pid = int(item.data(Qt.UserRole))
        self.set_active_project(pid)
    
    def delete_selected_project(self):
        item = self.projects_list.currentItem()
        if not item:
            return

        project_id = int(item.data(Qt.UserRole))
        project = get_project(project_id)
        if not project:
            QMessageBox.warning(self, "Delete project", "Project not found.")
            return

        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Delete project")
        msg.setText("Delete selected project?")
        msg.setInformativeText(
            f"{project.name} (id={project.id})\n\n"
            "This will permanently delete:\n"
            "• project\n"
            "• loaded datasets\n"
            "• findings\n"
            "• activity log"
        )

        btn_delete = msg.addButton("Delete", QMessageBox.DestructiveRole)
        msg.addButton(QMessageBox.Cancel)
        msg.setDefaultButton(QMessageBox.Cancel)

        msg.exec()
        if msg.clickedButton() != btn_delete:
            return

        try:
            delete_project(project_id)
        except Exception as e:
            QMessageBox.critical(self, "Delete project failed", str(e))
            return

        if self.current_project_id == project_id:
            # reset state
            self.current_project_id = None
            self.current_project_name = ""
            self.current_folder = None

            # reset banners
            self.lbl_active_project.setText("Active project: (none)")
            self.lbl_project_banner.setText("Project: (none)")

            # reset dataset UI
            self.lbl_path.setText("No dataset loaded")
            self.lbl_stats.setText("")
            self.txt_top_src.setPlainText("No flows loaded.")
            self.txt_top_dst.setPlainText("No flows loaded.")
            self.txt_top_proto.setPlainText("No flows loaded.")
            self.txt_top_apps.setPlainText("No flows loaded.")
            self.txt_ai_summary.clear()

            self.flows = []
            self.loaded_flows = []
            self.model.set_flows([])
            self.leave_conversation(clear_search=True)
            self.update_loaded_label()
            self.update_load_more_enabled()
            self._flows_expanded = False
            if hasattr(self, "details_panel"):
                self.details_panel.show()
            if hasattr(self, "btn_expand_flows"):
                self.btn_expand_flows.setText("Expand Flows")

            # reset registry page dataset
            if hasattr(self, "registry_page"):
                self.registry_page.set_dataset("", [], [])

            # reset findings + notes UI
            self.refresh_findings_ui()
            self.refresh_notes_ui()

        self.refresh_projects()

    def set_active_project(self, project_id: int):
        p = get_project(project_id)
        if not p:
            QMessageBox.warning(self, "Project", "Project not found.")
            return

        self.current_project_id = p.id
        self.current_project_name = p.name

        self.lbl_active_project.setText(f"Active project: {p.name} (id={p.id})")
        self.lbl_project_banner.setText(f"Project: {p.name} (id={p.id})")

        self.refresh_recent_datasets(p.id)
        self.refresh_findings_ui()
        self.refresh_notes_ui()

    def refresh_recent_datasets(self, project_id: int):
        self.recent_list.clear()
        paths = list_recent_datasets(project_id, limit=15)
        if not paths:
            self.recent_list.addItem(QListWidgetItem("(no datasets yet)"))
            return
        for fp in paths:
            item = QListWidgetItem(fp)
            item.setData(Qt.UserRole, fp)
            self.recent_list.addItem(item)

    def open_selected_dataset(self):
        item = self.recent_list.currentItem()
        if not item:
            return
        fp = item.data(Qt.UserRole)
        if not fp or str(fp).startswith("("):
            return
        self.load_dataset_path(str(fp))
        self.go_page(self.IDX_EXPLORE, self._nav_explore)

    # ---------- Explore ----------
    def load_dataset_dialog(self):
        folder = QFileDialog.getExistingDirectory(self, "Select dataset folder")
        if not folder:
            return
        self.load_dataset_path(folder)

    def load_dataset_path(self, folder: str):
        folder = str(folder)
        if not Path(folder).exists():
            QMessageBox.warning(self, "Dataset", f"Folder not found:\n{folder}")
            return

        previous_flows = []

        if self.current_project_id is not None:
            recent = list_recent_datasets(self.current_project_id, limit=2)

            if len(recent) >= 1:
                prev_folder = recent[0]

                # ako je isti folder → ignoriraj
                if str(prev_folder) != str(folder):
                    try:
                        _, previous_flows = load_folder(prev_folder)
                    except Exception:
                        previous_flows = []

        self.current_folder = Path(folder)
        files, flows = load_folder(folder, debug=False)
        self.flows = flows

        from core.compare import compare_flows

        compare_result = None
        if previous_flows:
            compare_result = compare_flows(self.flows, previous_flows)
        from core.compare import summarize_new_flows

        summary_new = None
        if compare_result:
            summary_new = summarize_new_flows(compare_result["new"])
            compare_result["summary_new"] = summary_new

        if hasattr(self, "registry_page"):
            self.registry_page.set_dataset(folder, files, flows, compare_result=compare_result)

        self.lbl_path.setText(f"Dataset: {folder}")
        self.lbl_stats.setText(f"JSON files: {len(files)}\nTotal flow records: {len(flows)}")

        if self.current_project_id is not None:
            add_dataset_load(self.current_project_id, folder)
            self.refresh_recent_datasets(self.current_project_id)
            self.refresh_activity_ui()

        self.render_summary()

        self.loaded_flows = self.flows[: min(len(self.flows), self.PAGE_SIZE)]
        self.model.set_flows(self.loaded_flows)

        self.search.setText("")
        self.leave_conversation(clear_search=False)

        self.update_loaded_label()
        self.update_load_more_enabled()

        self.tabs.setCurrentIndex(1)
        self._flows_expanded = False
        self.details_panel.show()
        self.btn_expand_flows.setText("Expand Flows")
        self.splitter.setSizes([920, 420])
        self.update_detail(None)
        
    def render_summary(self):
        if not self.flows:
            self.txt_top_src.setPlainText("No flows loaded.")
            self.txt_top_dst.setPlainText("No flows loaded.")
            self.txt_top_proto.setPlainText("No flows loaded.")
            self.txt_top_apps.setPlainText("No flows loaded.")
            return

        src_lines = []
        for ip, c in top_src_ips(self.flows, limit=10):
            src_lines.append(f"{ip:<18} {c:>5}")

        dst_lines = []
        for ip, c in top_dst_ips(self.flows, limit=10):
            dst_lines.append(f"{ip:<18} {c:>5}")

        proto_lines = []
        for proto, c in top_protocols(self.flows, limit=10):
            proto_lines.append(f"{format_ip_proto(proto):<18} {c:>5}")

        app_lines = []
        for app, c in top_applications(self.flows, limit=10):
            app_lines.append(f"{app:<28} {c:>5}")

        self.txt_top_src.setPlainText("\n".join(src_lines))
        self.txt_top_dst.setPlainText("\n".join(dst_lines))
        self.txt_top_proto.setPlainText("\n".join(proto_lines))
        self.txt_top_apps.setPlainText("\n".join(app_lines))

    def generate_ai_summary(self):
        if not self.flows:
            QMessageBox.information(self, "AI Assistant", "Load a dataset first.")
            return

        if self._ai_thread is not None:
            QMessageBox.information(self, "AI Assistant", "AI summary is already running.")
            return

        self.btn_ai_summary.setEnabled(False)
        self.txt_ai_summary.setPlainText("Generating AI summary...")
        self.btn_ai_summary.setText("Generating...")
        QApplication.processEvents()

        dataset_path = str(self.current_folder) if self.current_folder else ""

        self._ai_mode = "summary"
        self._ai_thread = QThread()
        self._ai_worker = AITextWorker(
            self.ai_service.generate_dataset_summary,
            list(self.flows),
            self.current_project_name,
            dataset_path,
        )

        self._ai_worker.moveToThread(self._ai_thread)
        self._ai_thread.started.connect(self._ai_worker.run)
        self._ai_worker.finished.connect(self.on_ai_task_finished)
        self._ai_worker.error.connect(self.on_ai_task_error)

        self._ai_worker.finished.connect(self._ai_thread.quit)
        self._ai_worker.error.connect(self._ai_thread.quit)

        self._ai_thread.finished.connect(self._cleanup_ai_thread)

        self._ai_thread.start()

    def explain_selected_flow(self):
        if not self._current_flow:
            QMessageBox.information(self, "AI Assistant", "Select a flow first.")
            return

        if self._ai_thread is not None:
            QMessageBox.information(self, "AI Assistant", "Another AI task is already running.")
            return

        self._ai_mode = "flow"
        self.btn_ai_explain.setEnabled(False)
        self.txt_ai_summary.setPlainText("Generating AI flow explanation...")
        self.tabs.setCurrentIndex(0)

        self._ai_thread = QThread()
        self._ai_worker = AITextWorker(
            self.ai_service.explain_flow,
            dict(self._current_flow),
        )

        self._ai_worker.moveToThread(self._ai_thread)
        self._ai_thread.started.connect(self._ai_worker.run)
        self._ai_worker.finished.connect(self.on_ai_task_finished)
        self._ai_worker.error.connect(self.on_ai_task_error)

        self._ai_worker.finished.connect(self._ai_thread.quit)
        self._ai_worker.error.connect(self._ai_thread.quit)

        self._ai_thread.finished.connect(self._cleanup_ai_thread)

        self._ai_thread.start()

    def on_ai_task_finished(self, result: str):
        self.txt_ai_summary.setPlainText(result)

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

    def update_showing(self):
        total = len(self.model._flows)
        shown = self.proxy.rowCount()
        self.lbl_showing.setText(f"Showing: {shown} / {total} (loaded)" if total else "")

    # ---------- selection -> details ----------
    def on_row_selected(self, *args):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            self.update_detail(None)
            return

        proxy_index = sel[0]
        source_index = self.proxy.mapToSource(proxy_index)
        row = source_index.row()

        if 0 <= row < len(self.loaded_flows):
            self.update_detail(self.loaded_flows[row])
        else:
            self.update_detail(None)

    def update_detail(self, flow: dict[str, Any] | None):
        self._current_flow = flow
        if not flow:
            self.d_src.setText("-")
            self.d_dst.setText("-")
            self.d_proto.setText("-")
            self.d_app.setText("-")
            self.d_bytes.setText("-")
            self.d_packets.setText("-")
            self.d_duration.setText("-")
            self.d_sni.setText("-")
            return

        self.d_src.setText(f"{flow.get('src_ip','')}:{flow.get('src_port','')}")
        self.d_dst.setText(f"{flow.get('dst_ip','')}:{flow.get('dst_port','')}")
        self.d_proto.setText(format_ip_proto(flow.get("protocol", "")))
        self.d_app.setText(str(flow.get("application_name", "")))
        self.d_bytes.setText(str(flow.get("bidirectional_bytes", "")))
        self.d_packets.setText(str(flow.get("bidirectional_packets", "")))
        self.d_duration.setText(str(flow.get("bidirectional_duration_ms", "")))
        self.d_sni.setText(str(flow.get("requested_server_name", "")))

    # ---------- Filter / Conversation ----------
    def apply_filter_ip(self, ip: str):
        if not ip:
            return
        self.search.setText(ip)
        self.search.setFocus()

    def toggle_conversation(self):
        if self._conversation_on:
            self.leave_conversation()
            return

        if not self._current_flow:
            QMessageBox.information(self, "Conversation", "Select a flow first (Flows tab).")
            return

        src = self.current_value("src_ip")
        dst = self.current_value("dst_ip")
        self.enter_conversation(src, dst)

    def toggle_flows_expanded(self):
        self._flows_expanded = not self._flows_expanded

        if self._flows_expanded:
            self.details_panel.hide()
            self.btn_expand_flows.setText("Collapse Flows")
            self.splitter.setSizes([1400, 0])
        else:
            self.details_panel.show()
            self.btn_expand_flows.setText("Expand Flows")
            self.splitter.setSizes([920, 420])

    def update_mode_label(self):
        if self._conversation_on and self.proxy.conv_a and self.proxy.conv_b:
            a = self.proxy.conv_a
            b = self.proxy.conv_b
            self.lbl_mode.setText(f"Mode: Conversation between {a} ⇄ {b}")
            self.lbl_mode.show()
        else:
            self.lbl_mode.clear()
            self.lbl_mode.hide()

    # ---------- Findings ----------
    def selected_finding_id(self) -> int | None:
        return self.findings_page.selected_finding_id()

    def set_findings_actions_enabled(self, enabled: bool):
        self.findings_page.set_actions_enabled(enabled)

    def _get_selected_finding_row(self):
        fid = self.selected_finding_id()
        if fid is None:
            return None, None

        row = get_finding(fid)
        if row is None:
            return fid, None

        return fid, row

    def mark_as_finding(self):
        if self.current_project_id is None:
            QMessageBox.warning(self, "Findings", "Select an active project first (Projects -> Open).")
            return
        if not self._current_flow:
            QMessageBox.warning(self, "Findings", "Select a flow first.")
            return

        default_title = f"{self.current_value('src_ip')} -> {self.current_value('dst_ip')} ({self.current_value('application_name')})"
        title, ok = QInputDialog.getText(self, "New finding", "Title:", text=default_title)
        if not ok:
            return
        title = (title or "").strip()
        if not title:
            return

        note, ok2 = QInputDialog.getMultiLineText(self, "New finding", "Note (optional):")
        if not ok2:
            note = ""

        try:
            add_finding(self.current_project_id, self._current_flow, title=title, note=note)
            add_activity(self.current_project_id, "finding_created", title)
        except Exception as e:
            QMessageBox.critical(self, "Findings", str(e))
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
        self._findings_rows = []
        self._findings_view_rows = []

        if self.current_project_id is None:
            self.findings_page.clear_list()
            self.findings_page.add_list_item("(no active project)", None)
            self.findings_page.clear_detail()
            return

        rows = list_findings(self.current_project_id, limit=500)
        self._findings_rows = list(rows)

        self.apply_findings_filter()

    def apply_findings_filter(self):
        keep_id = self.selected_finding_id()

        status_sel = (self.cmb_find_status.currentText() or "All").strip()
        search = (self.txt_find_search.text() or "").strip().lower()
        tagq = (self.txt_find_tag.text() or "").strip().lower()

        rows = [
            r for r in self._findings_rows
            if self.findings_page.matches_filters(r, status_sel, search, tagq)
        ]

        rows = self.findings_page.sort_rows(rows, self.cmb_find_sort.currentText())

        render_rows = []
        for r in rows:
            rr = dict(r)
            rr["status_emoji"] = status_emoji(r["status"])
            render_rows.append(rr)

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

        lines = []
        lines.append(f"Title: {row['title']}")
        lines.append("")
        lines.append(f"Status: {status_emoji(row['status'])} {row['status']}")
        lines.append(f"Created: {row['created_at']}")
        lines.append(f"Tags: {row['tags'] or '-'}")
        lines.append("")
        lines.append("Flow")
        lines.append(f"Source: {row['src_ip']}:{row['src_port'] or ''}")
        lines.append(f"Destination: {row['dst_ip']}:{row['dst_port'] or ''}")
        lines.append(f"Protocol: {row['protocol']}")
        lines.append(f"Application: {row['application_name'] or '-'}")
        lines.append(f"SNI: {row['requested_server_name'] or '-'}")
        lines.append(f"Bytes: {row['bidirectional_bytes']}")
        lines.append(f"Packets: {row['bidirectional_packets']}")
        lines.append(f"Duration (ms): {row['bidirectional_duration_ms']}")
        lines.append("")
        lines.append("Note")
        lines.append(row["note"] or "-")

        self.findings_page.show_detail("\n".join(lines))

    def explain_selected_finding(self):
        fid, row = self._get_selected_finding_row()
        if fid is None or row is None:
            QMessageBox.information(self, "AI Assistant", "Select a finding first.")
            return

        if self._ai_thread is not None:
            QMessageBox.information(self, "AI Assistant", "Another AI task is already running.")
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
        self.leave_conversation(clear_search=False)
        self.enter_conversation(src, dst)

        QTimer.singleShot(0, lambda: self._select_flow_pair(src, dst))

    def edit_selected_finding(self):
        fid, row = self._get_selected_finding_row()
        if fid is None or row is None:
            return

        title, ok = QInputDialog.getText(self, "Edit finding", "Title:", text=row["title"] or "")
        if not ok:
            return
        title = (title or "").strip()
        if not title:
            return

        note, ok2 = QInputDialog.getMultiLineText(self, "Edit finding", "Note:", text=row["note"] or "")
        if not ok2:
            return

        statuses = ["New", "Investigating", "Confirmed", "False Positive"]
        cur = row["status"] if row["status"] in statuses else "New"
        idx = statuses.index(cur)
        status, ok3 = QInputDialog.getItem(self, "Edit finding", "Status:", statuses, idx, False)
        if not ok3:
            return

        tags, ok4 = QInputDialog.getText(self, "Edit finding", "Tags (comma-separated):", text=row["tags"] or "")
        if not ok4:
            return

        tags = normalize_tags(tags)

        try:
            update_finding(fid, title=title, note=note, status=status, tags=tags)
            if self.current_project_id:
                add_activity(self.current_project_id, "finding_updated", f"#{fid} {title}")
        except Exception as e:
            QMessageBox.critical(self, "Findings", str(e))
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

        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Delete finding")
        msg.setText("Delete selected finding?")
        msg.setInformativeText(f"{title}\n{src} -> {dst}")

        btn_delete = msg.addButton("Delete", QMessageBox.DestructiveRole)
        msg.addButton(QMessageBox.Cancel)
        msg.setDefaultButton(QMessageBox.Cancel)

        msg.exec()
        if msg.clickedButton() != btn_delete:
            return

        try:
            delete_finding(fid)
            if self.current_project_id:
                add_activity(self.current_project_id, "finding_deleted", f"#{fid} {title}")
        except Exception as e:
            QMessageBox.critical(self, "Findings", str(e))
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
            row = get_finding(fid)
            if row is None:
                return

            status_map = {
                act_new: "New",
                act_inv: "Investigating",
                act_conf: "Confirmed",
                act_fp: "False Positive",
            }
            new_status = status_map[chosen]

            try:
                update_finding(
                    fid,
                    title=row["title"] or "",
                    note=row["note"] or "",
                    status=new_status,
                    tags=row["tags"] or "",
                )
                if self.current_project_id:
                    add_activity(self.current_project_id, "finding_status", f"#{fid} -> {new_status}")
            except Exception as e:
                QMessageBox.critical(self, "Findings", str(e))
                return

            self.refresh_findings_ui()
            self.refresh_activity_ui()

    def _make_ai_note_block(self, text: str) -> str:
        ts = datetime.now().strftime("%d.%m.%Y. %H:%M:%S")
        body = (text or "").strip()

        if not body:
            return ""

        return (
            f"[AI note added: {ts}]\n"
            f"{body}\n"
            f"{'-' * 60}\n"
        )

    def add_ai_summary_to_notes(self):
        if self.current_project_id is None:
            QMessageBox.information(self, "Notes", "Open an active project first.")
            return

        text = (self.txt_ai_summary.toPlainText() or "").strip()
        if not text:
            QMessageBox.information(self, "Notes", "There is no AI-generated text to add.")
            return

        block = self._make_ai_note_block(text)
        if not block:
            return

        existing = self.txt_notes.toPlainText() or ""

        if existing.strip():
            if not existing.endswith("\n"):
                existing += "\n"
            new_text = existing + "\n" + block
        else:
            new_text = block

        self.txt_notes.setPlainText(new_text)
        self._notes_dirty = True
        self._flush_notes()

        self.tabs.setCurrentIndex(3)  # Notes tab

    # ---------- Notes ----------
    def refresh_notes_ui(self):
        self.txt_notes.blockSignals(True)
        self.lst_activity.clear()

        if self.current_project_id is None:
            self.txt_notes.setPlainText("")
            self.txt_notes.setPlaceholderText("Select an active project to use Notes.")
            self.txt_notes.setEnabled(False)
            self.lst_activity.addItem(QListWidgetItem("(no active project)"))
            self.txt_notes.blockSignals(False)
            return

        self.txt_notes.setEnabled(True)
        self.txt_notes.setPlaceholderText("Write case notes here… (autosave)")
        self.txt_notes.setPlainText(get_project_notes(self.current_project_id) or "")
        self.txt_notes.blockSignals(False)

        self.refresh_activity_ui()

    def refresh_activity_ui(self):
        self.lst_activity.clear()
        if self.current_project_id is None:
            self.lst_activity.addItem(QListWidgetItem("(no active project)"))
            return

        rows = list_activity(self.current_project_id, limit=200)
        if not rows:
            self.lst_activity.addItem(QListWidgetItem("(no activity yet)"))
            return

        for r in rows:
            ts = r["created_at"]
            et = r["event_type"]
            msg = r["message"] or ""
            self.lst_activity.addItem(QListWidgetItem(f"{ts} | {et} | {msg}"))

    def on_notes_changed(self):
        if self.current_project_id is None:
            return
        self._notes_dirty = True
        self._notes_timer.start(800)

    def _flush_notes(self):
        if not self._notes_dirty or self.current_project_id is None:
            return
        try:
            set_project_notes(self.current_project_id, self.txt_notes.toPlainText())
        except Exception:
            return
        self._notes_dirty = False

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

    # load global stylesheet
    qss_path = Path(__file__).resolve().parent / "style.qss"
    if qss_path.exists():
        app.setStyleSheet(qss_path.read_text(encoding="utf-8"))

    base_dir = Path(__file__).resolve().parent          # ...\Conduvia\ui
    project_dir = base_dir.parent                       # ...\Conduvia
    icon_path = project_dir / "assets" / "ConduVia.ico"

    icon = QIcon(str(icon_path))

    app.setWindowIcon(icon)   # global (taskbar + dialogs)
    w = App()
    w.setWindowIcon(icon)     # explicit on main window
    w.showMaximized()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
