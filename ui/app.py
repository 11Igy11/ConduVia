import sys
import ipaddress
import html
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QTimer
from PySide6.QtGui import QGuiApplication, QColor
from PySide6.QtWidgets import (
    QApplication, QWidget, QHBoxLayout, QVBoxLayout,
    QPushButton, QLabel, QStackedWidget, QFileDialog,
    QTextEdit, QTabWidget, QTableView, QLineEdit,
    QSplitter, QFormLayout, QGroupBox,
    QListWidget, QListWidgetItem, QMessageBox, QInputDialog,
    QComboBox, QMenu
)

from core.loader import load_folder
from core.analyzer import top_src_ips, top_dst_ips, top_applications, top_protocols
from core.db import (
    init_db, create_project, list_projects, get_project,
    add_dataset_load, list_recent_datasets,
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
        ("src_port", "Src Port"),
        ("dst_ip", "Dest IP"),
        ("dst_port", "Dst Port"),
        ("protocol", "Proto"),
        ("application_name", "App"),
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
            return "" if val is None else str(val)

        if role == Qt.ToolTipRole:
            val = flow.get(key, "")
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


# ---------- Main App ----------
class App(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Conduvia")
        self.setMinimumSize(1100, 700)
        self.resize(1200, 800)

        init_db()

        # State
        self.current_project_id: int | None = None
        self.current_project_name: str = ""
        self.current_folder: Path | None = None

        self.flows: list[dict[str, Any]] = []      # all flows in memory (for now)
        self.loaded_flows: list[dict[str, Any]] = []  # currently shown in table
        self._current_flow: dict[str, Any] | None = None
        self._conversation_on = False

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

        root = QHBoxLayout(self)

        # Sidebar
        sidebar = QVBoxLayout()
        btn_projects = QPushButton("Projects")
        btn_explore = QPushButton("Explore")
        btn_projects.setFixedHeight(40)
        btn_explore.setFixedHeight(40)
        sidebar.addWidget(btn_projects)
        sidebar.addWidget(btn_explore)
        sidebar.addStretch()

        # Pages
        self.pages = QStackedWidget()

        # -------- Projects page --------
        projects_page = QWidget()
        projects_layout = QVBoxLayout(projects_page)

        self.lbl_active_project = QLabel("Active project: (none)")

        btn_row = QHBoxLayout()
        self.btn_new_project = QPushButton("New project")
        self.btn_open_project = QPushButton("Open selected")
        self.btn_refresh_projects = QPushButton("Refresh")
        btn_row.addWidget(self.btn_new_project)
        btn_row.addWidget(self.btn_open_project)
        btn_row.addWidget(self.btn_refresh_projects)

        self.projects_list = QListWidget()
        self.projects_list.itemSelectionChanged.connect(self.on_project_selected_preview)
        self.projects_list.itemDoubleClicked.connect(lambda _: self.open_selected_project())

        self.projects_info = QTextEdit()
        self.projects_info.setReadOnly(True)

        self.lbl_recent = QLabel("Recent datasets:")
        self.recent_list = QListWidget()
        self.recent_list.itemDoubleClicked.connect(lambda _: self.open_selected_dataset())

        recent_btn_row = QHBoxLayout()
        self.btn_open_dataset = QPushButton("Open dataset")
        self.btn_open_dataset.clicked.connect(self.open_selected_dataset)
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

        self.btn_new_project.clicked.connect(self.create_project_dialog)
        self.btn_open_project.clicked.connect(self.open_selected_project)
        self.btn_refresh_projects.clicked.connect(self.refresh_projects)

        # -------- Explore page --------
        explore_container = QWidget()
        explore_layout = QVBoxLayout(explore_container)

        self.lbl_project_banner = QLabel("Project: (none)")
        self.btn_load = QPushButton("Load dataset folder")
        self.lbl_path = QLabel("No dataset loaded")
        self.lbl_stats = QLabel("")
        self.lbl_showing = QLabel("")
        self.lbl_mode = QLabel("")

        # Paging controls
        paging_row = QHBoxLayout()
        self.lbl_loaded = QLabel("")
        self.btn_load_more = QPushButton("Load next")
        self.btn_load_more.clicked.connect(self.load_next_page)
        self.btn_load_more.setEnabled(False)
        paging_row.addWidget(self.lbl_loaded)
        paging_row.addStretch()
        paging_row.addWidget(QLabel("Page size:"))
        self.cmb_page_size = QComboBox()
        self.cmb_page_size.addItems(["1000", "2000", "5000", "10000"])
        self.cmb_page_size.setCurrentText("2000")
        self.cmb_page_size.currentTextChanged.connect(self.on_page_size_changed)
        paging_row.addWidget(self.cmb_page_size)
        paging_row.addWidget(self.btn_load_more)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search IP / SNI / app...")

        self.tabs = QTabWidget()

        # Summary tab
        self.txt_summary = QTextEdit()
        self.txt_summary.setReadOnly(True)
        self.tabs.addTab(self.txt_summary, "Summary")

        # Flows tab
        flows_tab = QWidget()
        flows_tab_layout = QVBoxLayout(flows_tab)
        self.splitter = QSplitter(Qt.Horizontal)

        self.table = QTableView()
        self.table.setSortingEnabled(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setSelectionMode(QTableView.SingleSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)

        self.model = FlowTableModel([])
        self.proxy = NumericSortProxy()
        self.proxy.setSourceModel(self.model)
        self.table.setModel(self.proxy)

        self.search.textChanged.connect(self.proxy.set_filter_text)
        self.search.textChanged.connect(lambda _: self.update_showing())
        self.table.selectionModel().selectionChanged.connect(self.on_row_selected)

        # Auto-load on scroll near bottom
        self.table.verticalScrollBar().valueChanged.connect(self.on_table_scrolled)

        self.splitter.addWidget(self.table)

        # Details panel
        details_panel = QWidget()
        details_panel.setMinimumWidth(420)
        details_layout = QVBoxLayout(details_panel)

        grp = QGroupBox("Flow details")
        form = QFormLayout(grp)

        self.d_src = QLabel("-"); self.d_src.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.d_dst = QLabel("-"); self.d_dst.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.d_proto = QLabel("-")
        self.d_app = QLabel("-")
        self.d_bytes = QLabel("-")
        self.d_packets = QLabel("-")
        self.d_duration = QLabel("-")
        self.d_sni = QLabel("-"); self.d_sni.setTextInteractionFlags(Qt.TextSelectableByMouse)

        form.addRow("Source:", self.d_src)
        form.addRow("Destination:", self.d_dst)
        form.addRow("Protocol:", self.d_proto)
        form.addRow("Application:", self.d_app)
        form.addRow("Bytes:", self.d_bytes)
        form.addRow("Packets:", self.d_packets)
        form.addRow("Duration (ms):", self.d_duration)
        form.addRow("SNI:", self.d_sni)

        details_layout.addWidget(grp)

        # Buttons: copy
        btn_row1 = QHBoxLayout()
        self.btn_copy_src = QPushButton("Copy Src IP")
        self.btn_copy_dst = QPushButton("Copy Dst IP")
        self.btn_copy_sni = QPushButton("Copy SNI")
        self.btn_copy_src.clicked.connect(lambda: self.copy_text(self.current_value("src_ip")))
        self.btn_copy_dst.clicked.connect(lambda: self.copy_text(self.current_value("dst_ip")))
        self.btn_copy_sni.clicked.connect(lambda: self.copy_text(self.current_value("requested_server_name")))
        btn_row1.addWidget(self.btn_copy_src)
        btn_row1.addWidget(self.btn_copy_dst)
        btn_row1.addWidget(self.btn_copy_sni)
        details_layout.addLayout(btn_row1)

        # Buttons: filter
        btn_row2 = QHBoxLayout()
        self.btn_filter_src = QPushButton("Filter Src")
        self.btn_filter_dst = QPushButton("Filter Dst")
        self.btn_filter_src.clicked.connect(lambda: self.apply_filter_ip(self.current_value("src_ip")))
        self.btn_filter_dst.clicked.connect(lambda: self.apply_filter_ip(self.current_value("dst_ip")))
        btn_row2.addWidget(self.btn_filter_src)
        btn_row2.addWidget(self.btn_filter_dst)
        details_layout.addLayout(btn_row2)

        # Conversation + Finding
        self.btn_toggle_conv = QPushButton("Conversation: OFF")
        self.btn_toggle_conv.clicked.connect(self.toggle_conversation)

        self.btn_mark_finding = QPushButton("Mark as Finding")
        self.btn_mark_finding.clicked.connect(self.mark_as_finding)

        details_layout.addWidget(self.btn_toggle_conv)
        details_layout.addWidget(self.btn_mark_finding)
        details_layout.addStretch()

        self.splitter.addWidget(details_panel)
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 2)
        self.splitter.setCollapsible(1, False)

        flows_tab_layout.addWidget(self.splitter)
        self.tabs.addTab(flows_tab, "Flows")

        # Findings tab
        findings_tab = QWidget()
        findings_root = QVBoxLayout(findings_tab)

        actions = QHBoxLayout()
        self.btn_finding_edit = QPushButton("Edit")
        self.btn_finding_delete = QPushButton("Delete")
        self.btn_finding_jump = QPushButton("Jump to Flow")
        actions.addWidget(self.btn_finding_edit)
        actions.addWidget(self.btn_finding_delete)
        actions.addWidget(self.btn_finding_jump)
        actions.addStretch()
        findings_root.addLayout(actions)

        # Findings filter row (THIS is what was missing)
        frow = QHBoxLayout()
        frow.addWidget(QLabel("Status:"))
        self.cmb_find_status = QComboBox()
        self.cmb_find_status.addItems(["All", "New", "Investigating", "Confirmed", "False Positive"])
        frow.addWidget(self.cmb_find_status)

        frow.addSpacing(12)
        frow.addWidget(QLabel("Search:"))
        self.txt_find_search = QLineEdit()
        self.txt_find_search.setPlaceholderText("title / ip / app / sni / note...")
        frow.addWidget(self.txt_find_search, 2)

        frow.addSpacing(12)
        frow.addWidget(QLabel("Tag contains:"))
        self.txt_find_tag = QLineEdit()
        self.txt_find_tag.setPlaceholderText("e.g. c2, dns, exfil ...")
        frow.addWidget(self.txt_find_tag, 1)

        frow.addSpacing(12)
        frow.addWidget(QLabel("Sort:"))
        self.cmb_find_sort = QComboBox()
        self.cmb_find_sort.addItems(["Newest", "Oldest", "Status", "Title"])
        frow.addWidget(self.cmb_find_sort)

        self.btn_find_clear = QPushButton("Clear")
        frow.addWidget(self.btn_find_clear)

        findings_root.addLayout(frow)

        self.findings_split = QSplitter(Qt.Horizontal)

        self.findings_list = QListWidget()
        self.findings_list.itemSelectionChanged.connect(self.on_finding_selected)
        self.findings_list.itemDoubleClicked.connect(lambda _: self.jump_to_selected_finding())

        # Right click menu on Findings (restored)
        self.findings_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.findings_list.customContextMenuRequested.connect(self.on_findings_context_menu)

        self.finding_detail = QTextEdit()
        self.finding_detail.setReadOnly(True)
        self.finding_detail.setPlaceholderText("Select a finding to see details...")

        self.findings_split.addWidget(self.findings_list)
        self.findings_split.addWidget(self.finding_detail)
        self.findings_split.setSizes([420, 700])

        findings_root.addWidget(self.findings_split)
        self.tabs.addTab(findings_tab, "Findings")

        self.btn_finding_edit.clicked.connect(self.edit_selected_finding)
        self.btn_finding_delete.clicked.connect(self.delete_selected_finding)
        self.btn_finding_jump.clicked.connect(self.jump_to_selected_finding)

        self.btn_finding_edit.setEnabled(False)
        self.btn_finding_delete.setEnabled(False)
        self.btn_finding_jump.setEnabled(False)

        # connect filters
        self.cmb_find_status.currentTextChanged.connect(lambda _: self.apply_findings_filter())
        self.cmb_find_sort.currentTextChanged.connect(lambda _: self.apply_findings_filter())
        self.txt_find_search.textChanged.connect(lambda _: self.apply_findings_filter())
        self.txt_find_tag.textChanged.connect(lambda _: self.apply_findings_filter())
        self.btn_find_clear.clicked.connect(self.clear_findings_filters)

        # Notes tab
        notes_tab = QWidget()
        notes_root = QHBoxLayout(notes_tab)

        left = QVBoxLayout()
        left.addWidget(QLabel("Project notes"))
        self.txt_notes = QTextEdit()
        self.txt_notes.setPlaceholderText("Write case notes here… (autosave)")
        self.txt_notes.textChanged.connect(self.on_notes_changed)
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
        explore_layout.addWidget(self.search)
        explore_layout.addWidget(self.tabs, 1)

        # Add pages
        self.pages.addWidget(projects_page)
        self.pages.addWidget(explore_container)

        # Nav + actions
        btn_projects.clicked.connect(lambda: self.pages.setCurrentIndex(0))
        btn_explore.clicked.connect(lambda: self.pages.setCurrentIndex(1))
        self.btn_load.clicked.connect(self.load_dataset_dialog)

        root.addLayout(sidebar, 1)
        root.addWidget(self.pages, 8)

        # init
        self.refresh_projects()
        self.update_detail(None)
        self.update_mode_label()
        self.refresh_findings_ui()
        self.refresh_notes_ui()

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
            # reset conversation + clear global search
            self.proxy.clear_conversation()
            self._conversation_on = False
            self.btn_toggle_conv.setText("Conversation: OFF")
            self.update_mode_label()
            self.search.setText("")
            self.update_showing()
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
        self.pages.setCurrentIndex(1)

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

        self.current_folder = Path(folder)
        files, flows = load_folder(folder, debug=False)
        self.flows = flows

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
        self.proxy.clear_conversation()
        self._conversation_on = False
        self.btn_toggle_conv.setText("Conversation: OFF")
        self.update_mode_label()
        self.update_showing()

        self.update_loaded_label()
        self.update_load_more_enabled()

        self.tabs.setCurrentIndex(1)
        self.table.resizeColumnsToContents()
        self.splitter.setSizes([920, 420])
        self.update_detail(None)

    def render_summary(self):
        if not self.flows:
            self.txt_summary.setText("No flows loaded.")
            return

        lines = []
        lines.append("=== TOP SOURCE IPs (count) ===")
        for ip, c in top_src_ips(self.flows, limit=10):
            lines.append(f"{ip:20} {c}")

        lines.append("\n=== TOP DESTINATION IPs (count) ===")
        for ip, c in top_dst_ips(self.flows, limit=10):
            lines.append(f"{ip:20} {c}")

        lines.append("\n=== TOP PROTOCOLS (count) ===")
        for proto, c in top_protocols(self.flows, limit=10):
            lines.append(f"{proto:20} {c}")

        lines.append("\n=== TOP APPLICATIONS (count) ===")
        for app, c in top_applications(self.flows, limit=10):
            lines.append(f"{app:30} {c}")

        if self.current_project_id is None:
            lines.append("\nNOTE: No active project selected. Dataset load won't be stored.")
        else:
            lines.append(f"\nProject: {self.current_project_name}")

        lines.append("\n(Table is paged. Scroll to auto-load more, or click Load next.)")
        self.txt_summary.setText("\n".join(lines))

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
        self.d_proto.setText(str(flow.get("protocol", "")))
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
        if not self._current_flow:
            return

        src = self.current_value("src_ip")
        dst = self.current_value("dst_ip")
        if not src or not dst:
            return

        if not self._conversation_on:
            self.proxy.set_conversation(src, dst)
            self._conversation_on = True
            self.btn_toggle_conv.setText("Conversation: ON")
        else:
            self.proxy.clear_conversation()
            self._conversation_on = False
            self.btn_toggle_conv.setText("Conversation: OFF")

        self.update_mode_label()
        self.update_showing()

    def update_mode_label(self):
        if self._conversation_on and self._current_flow:
            a = self.current_value("src_ip")
            b = self.current_value("dst_ip")
            self.lbl_mode.setText(f"Mode: Conversation between {a} ⇄ {b}")
        else:
            self.lbl_mode.setText("")

    # ---------- Findings ----------
    def selected_finding_id(self) -> int | None:
        item = self.findings_list.currentItem()
        if not item:
            return None
        fid = item.data(Qt.UserRole)
        if not fid or str(item.text()).startswith("("):
            return None
        try:
            return int(fid)
        except Exception:
            return None

    def set_findings_actions_enabled(self, enabled: bool):
        self.btn_finding_edit.setEnabled(enabled)
        self.btn_finding_delete.setEnabled(enabled)
        self.btn_finding_jump.setEnabled(enabled)

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

    def _matches_findings_filters(self, r) -> bool:
        status_sel = (self.cmb_find_status.currentText() or "All").strip()
        search = (self.txt_find_search.text() or "").strip().lower()
        tagq = (self.txt_find_tag.text() or "").strip().lower()

        if status_sel != "All":
            if (r["status"] or "New") != status_sel:
                return False

        if tagq:
            tags = (r["tags"] or "").lower()
            if tagq not in tags:
                return False

        if search:
            hay = " ".join([
                str(r["title"] or ""),
                str(r["note"] or ""),
                str(r["src_ip"] or ""),
                str(r["dst_ip"] or ""),
                str(r["application_name"] or ""),
                str(r["requested_server_name"] or ""),
                str(r["protocol"] or ""),
                str(r["tags"] or ""),
                str(r["created_at"] or ""),
            ]).lower()
            if search not in hay:
                return False

        return True

    def _sort_findings_rows(self, rows: list[Any]) -> list[Any]:
        mode = (self.cmb_find_sort.currentText() or "Newest").strip()

        def status_rank(s: str) -> int:
            order = {"Confirmed": 0, "Investigating": 1, "New": 2, "False Positive": 3}
            return order.get((s or "New"), 9)

        if mode == "Oldest":
            return sorted(rows, key=lambda r: (r["created_at"], int(r["id"])))
        if mode == "Status":
            return sorted(rows, key=lambda r: (status_rank(r["status"]), r["created_at"], int(r["id"])), reverse=False)
        if mode == "Title":
            return sorted(rows, key=lambda r: ((r["title"] or "").lower(), r["created_at"]), reverse=False)

        # Newest (default)
        return sorted(rows, key=lambda r: (r["created_at"], int(r["id"])), reverse=True)

    def apply_findings_filter(self):
        keep_id = self.selected_finding_id()

        rows = [r for r in self._findings_rows if self._matches_findings_filters(r)]
        rows = self._sort_findings_rows(rows)
        self._findings_view_rows = rows

        self.findings_list.blockSignals(True)
        self.findings_list.clear()
        self.finding_detail.clear()
        self.set_findings_actions_enabled(False)

        if self.current_project_id is None:
            self.findings_list.addItem(QListWidgetItem("(no active project)"))
            self.findings_list.blockSignals(False)
            return

        if not rows:
            self.findings_list.addItem(QListWidgetItem("(no findings match filters)"))
            self.findings_list.blockSignals(False)
            return

        for r in rows:
            badge = status_emoji(r["status"])
            title = r["title"]
            src = f"{r['src_ip']}:{r['src_port'] or ''}"
            dst = f"{r['dst_ip']}:{r['dst_port'] or ''}"
            app = r["application_name"] or ""
            created = r["created_at"]
            tags = (r["tags"] or "").strip()
            tag_part = f" | #{tags}" if tags else ""
            label = f"{created} | {badge} {title} | {src} -> {dst} | {app}{tag_part}"

            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, int(r["id"]))
            self.findings_list.addItem(item)

        self.findings_list.blockSignals(False)

        if keep_id is not None:
            for i in range(self.findings_list.count()):
                it = self.findings_list.item(i)
                if int(it.data(Qt.UserRole) or 0) == keep_id:
                    self.findings_list.setCurrentItem(it)
                    break

    def refresh_findings_ui(self):
        self._findings_rows = []
        self._findings_view_rows = []

        if self.current_project_id is None:
            self.findings_list.clear()
            self.findings_list.addItem(QListWidgetItem("(no active project)"))
            self.finding_detail.clear()
            self.set_findings_actions_enabled(False)
            return

        rows = list_findings(self.current_project_id, limit=500)
        self._findings_rows = list(rows)

        self.apply_findings_filter()

    def on_finding_selected(self):
        fid = self.selected_finding_id()
        if fid is None:
            self.finding_detail.setText("")
            self.set_findings_actions_enabled(False)
            return

        row = get_finding(fid)
        if row is None:
            self.finding_detail.setText("Finding not found.")
            self.set_findings_actions_enabled(False)
            return

        self.set_findings_actions_enabled(True)

        lines = []
        lines.append(f"Finding ID: {row['id']}")
        lines.append(f"Created: {row['created_at']}")
        lines.append(f"Status: {status_emoji(row['status'])} {row['status']}")
        lines.append(f"Tags: {row['tags'] or ''}")
        lines.append(f"Title: {row['title']}")
        lines.append("")
        lines.append(f"Source: {row['src_ip']}:{row['src_port'] or ''}")
        lines.append(f"Dest: {row['dst_ip']}:{row['dst_port'] or ''}")
        lines.append(f"Protocol: {row['protocol']}")
        lines.append(f"App: {row['application_name']}")
        lines.append(f"SNI: {row['requested_server_name']}")
        lines.append(f"Bytes: {row['bidirectional_bytes']}")
        lines.append(f"Packets: {row['bidirectional_packets']}")
        lines.append(f"Duration(ms): {row['bidirectional_duration_ms']}")
        lines.append("")
        lines.append("Note:")
        lines.append(row["note"] or "")
        self.finding_detail.setText("\n".join(lines))

    def jump_to_selected_finding(self):
        fid = self.selected_finding_id()
        if fid is None:
            return

        row = get_finding(fid)
        if row is None:
            return

        src = row["src_ip"]
        dst = row["dst_ip"]

        self.pages.setCurrentIndex(1)
        self.tabs.setCurrentIndex(1)

        self.search.setText("")
        self.proxy.clear_conversation()

        self.proxy.set_conversation(src, dst)
        self._conversation_on = True
        self.btn_toggle_conv.setText("Conversation: ON")
        self.update_mode_label()

        def _do_select():
            self.table.clearSelection()
            for r_idx in range(self.proxy.rowCount()):
                idx0 = self.proxy.index(r_idx, 0)
                src_ip = self.proxy.data(idx0, Qt.DisplayRole)
                dst_ip = self.proxy.data(self.proxy.index(r_idx, 2), Qt.DisplayRole)

                if (src_ip == src and dst_ip == dst) or (src_ip == dst and dst_ip == src):
                    self.table.setCurrentIndex(idx0)
                    self.table.selectRow(r_idx)
                    self.table.scrollTo(idx0, QTableView.PositionAtCenter)
                    break
            self.update_showing()

        QTimer.singleShot(0, _do_select)

    def edit_selected_finding(self):
        fid = self.selected_finding_id()
        if fid is None:
            return

        row = get_finding(fid)
        if row is None:
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

        for i in range(self.findings_list.count()):
            it = self.findings_list.item(i)
            if int(it.data(Qt.UserRole) or 0) == fid:
                self.findings_list.setCurrentItem(it)
                break

    def delete_selected_finding(self):
        fid = self.selected_finding_id()
        if fid is None:
            return

        row = get_finding(fid)
        if row is None:
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
    w = App()
    w.showMaximized()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
