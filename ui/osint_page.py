from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

if TYPE_CHECKING:
    from ui.app import App

BTN_H = 28


def _btn(text: str) -> QPushButton:
    button = QPushButton(text)
    button.setObjectName("OutlineButton")
    button.setFixedHeight(BTN_H)
    button.setMinimumWidth(max(72, len(text) * 8 + 24))
    button.setCursor(Qt.PointingHandCursor)
    return button


def build_osint_page(app: App) -> QWidget:
    page = QWidget()
    root = QVBoxLayout(page)
    root.setContentsMargins(10, 8, 10, 10)
    root.setSpacing(8)

    # --- compact header ---
    header = QFrame()
    header.setObjectName("CaseDashboardCompact")
    header_layout = QVBoxLayout(header)
    header_layout.setContentsMargins(12, 8, 12, 8)
    header_layout.setSpacing(2)

    title_row = QHBoxLayout()
    title = QLabel("OSINT")
    title.setObjectName("CaseDashboardTitle")
    app.lbl_osint_case = QLabel("No active project")
    app.lbl_osint_case.setObjectName("Muted")
    title_row.addWidget(title)
    title_row.addSpacing(12)
    title_row.addWidget(app.lbl_osint_case, 1)
    header_layout.addLayout(title_row)

    app.lbl_osint_subject = QLabel("Open a project to inspect identifiers, IPs and domains from saved case evidence.")
    app.lbl_osint_subject.setObjectName("Muted")
    app.lbl_osint_subject.setWordWrap(True)
    header_layout.addWidget(app.lbl_osint_subject)

    root.addWidget(header)

    # --- main split ---
    splitter = QSplitter(Qt.Horizontal)
    splitter.setChildrenCollapsible(False)

    # LEFT: browse
    browse = QFrame()
    browse.setObjectName("ProfilePanel")
    browse_layout = QVBoxLayout(browse)
    browse_layout.setContentsMargins(12, 10, 12, 10)
    browse_layout.setSpacing(8)

    browse_title = QLabel("Browse entities")
    browse_title.setObjectName("SectionTitle")
    browse_layout.addWidget(browse_title)

    app.txt_osint_filter = QLineEdit()
    app.txt_osint_filter.setPlaceholderText("Filter list…")
    app.txt_osint_filter.setClearButtonEnabled(True)
    app.txt_osint_filter.setMinimumHeight(34)
    browse_layout.addWidget(app.txt_osint_filter)

    tabs = QTabWidget()
    tabs.setDocumentMode(True)
    app.list_osint_identifiers = QListWidget()
    app.list_osint_ips = QListWidget()
    app.list_osint_domains = QListWidget()
    for lst in (app.list_osint_identifiers, app.list_osint_ips, app.list_osint_domains):
        lst.setAlternatingRowColors(True)
        lst.setSpacing(1)
    tabs.addTab(app.list_osint_identifiers, "Identifiers")
    tabs.addTab(app.list_osint_ips, "IPs")
    tabs.addTab(app.list_osint_domains, "Domains")
    app.osint_entity_tabs = tabs
    browse_layout.addWidget(tabs, 1)

    app.lbl_osint_checklist = QLabel("")
    app.lbl_osint_checklist.setObjectName("Muted")
    app.lbl_osint_checklist.setWordWrap(True)
    app.lbl_osint_checklist.hide()
    browse_layout.addWidget(app.lbl_osint_checklist)

    # RIGHT: workspace (single panel, scrollable so nothing is clipped)
    workspace_scroll = QScrollArea()
    workspace_scroll.setWidgetResizable(True)
    workspace_scroll.setFrameShape(QFrame.NoFrame)
    workspace = QFrame()
    workspace.setObjectName("ProfilePanel")
    ws = QVBoxLayout(workspace)
    ws.setContentsMargins(14, 12, 14, 12)
    ws.setSpacing(10)

    # entity block
    type_row = QHBoxLayout()
    app.lbl_osint_entity_type = QLabel("—")
    app.lbl_osint_entity_type.setObjectName("ProjectSelectionBadge")
    type_row.addWidget(app.lbl_osint_entity_type)
    type_row.addStretch(1)
    app.btn_osint_leaks = _btn("Repository")
    type_row.addWidget(app.btn_osint_leaks)
    ws.addLayout(type_row)

    app.lbl_osint_selected_value = QLabel("Select an entity")
    app.lbl_osint_selected_value.setObjectName("FlowFieldValue")
    app.lbl_osint_selected_value.setWordWrap(True)
    app.lbl_osint_selected_value.setTextInteractionFlags(Qt.TextSelectableByMouse)
    app.lbl_osint_selected_value.setMinimumHeight(42)
    ws.addWidget(app.lbl_osint_selected_value)

    # Green "found in internal database" banner (hidden until there is a hit).
    app.lbl_osint_hit = QLabel("")
    app.lbl_osint_hit.setObjectName("HitBanner")
    app.lbl_osint_hit.setWordWrap(True)
    app.lbl_osint_hit.hide()
    ws.addWidget(app.lbl_osint_hit)

    app.lbl_osint_registrable = QLabel("")
    app.lbl_osint_registrable.setObjectName("Muted")
    app.lbl_osint_registrable.setWordWrap(True)
    app.lbl_osint_registrable.hide()
    ws.addWidget(app.lbl_osint_registrable)

    identifier_label = QLabel("Identifier intelligence")
    identifier_label.setObjectName("SectionTitle")
    ws.addWidget(identifier_label)

    identifier_row = QHBoxLayout()
    identifier_row.setSpacing(6)
    app.btn_osint_decode_imei = _btn("Decode IMEI")
    app.btn_osint_decode_operator = _btn("Decode operator")
    app.btn_osint_decode_imei.hide()
    app.btn_osint_decode_operator.hide()
    identifier_row.addWidget(app.btn_osint_decode_imei)
    identifier_row.addWidget(app.btn_osint_decode_operator)
    identifier_row.addStretch(1)
    ws.addLayout(identifier_row)

    # actions (Copy / Copy results moved to the right-click menu on Results)
    actions = QHBoxLayout()
    actions.setSpacing(6)
    app.btn_osint_notes = _btn("Save to Notes")
    app.btn_osint_history = _btn("History")
    app.btn_osint_flows = _btn("Flows")
    app.btn_osint_pcap = _btn("PCAP")
    for b in (
        app.btn_osint_notes,
        app.btn_osint_history,
        app.btn_osint_flows,
        app.btn_osint_pcap,
    ):
        actions.addWidget(b)
    actions.addStretch(1)
    ws.addLayout(actions)

    # external links
    links_label = QLabel("External links")
    links_label.setObjectName("SectionTitle")
    ws.addWidget(links_label)

    app.osint_links_host = QWidget()
    app.osint_links_layout = QHBoxLayout(app.osint_links_host)
    app.osint_links_layout.setContentsMargins(0, 0, 0, 0)
    app.osint_links_layout.setSpacing(6)
    app.osint_links_layout.addStretch(1)
    ws.addWidget(app.osint_links_host)

    app.lbl_osint_links_empty = QLabel("")
    app.lbl_osint_links_empty.setObjectName("Muted")
    app.lbl_osint_links_empty.hide()
    ws.addWidget(app.lbl_osint_links_empty)

    # online lookup
    fetch_label = QLabel("Online lookup")
    fetch_label.setObjectName("SectionTitle")
    ws.addWidget(fetch_label)

    fetch_row = QHBoxLayout()
    fetch_row.setSpacing(6)
    app.btn_osint_fetch_dns = _btn("DNS")
    app.btn_osint_fetch_rdap = _btn("RDAP")
    app.btn_osint_fetch_reverse = _btn("Reverse DNS")
    app.btn_osint_fetch_geo = _btn("GeoIP")
    app.btn_osint_fetch_vt = _btn("VirusTotal")
    app.btn_osint_fetch_shodan = _btn("Shodan")
    for b in (
        app.btn_osint_fetch_dns,
        app.btn_osint_fetch_rdap,
        app.btn_osint_fetch_reverse,
        app.btn_osint_fetch_geo,
        app.btn_osint_fetch_vt,
        app.btn_osint_fetch_shodan,
    ):
        fetch_row.addWidget(b)
    fetch_row.addStretch(1)
    ws.addLayout(fetch_row)

    app.lbl_osint_status = QLabel("Ready.")
    app.lbl_osint_status.setObjectName("Muted")
    ws.addWidget(app.lbl_osint_status)

    # results
    results_label = QLabel("Results")
    results_label.setObjectName("SectionTitle")
    ws.addWidget(results_label)

    app.txt_osint_detail = QTextEdit()
    app.txt_osint_detail.setReadOnly(True)
    app.txt_osint_detail.setPlaceholderText("Lookup output will appear here. Right-click to copy.")
    app.txt_osint_detail.setMinimumHeight(140)
    app.txt_osint_detail.setContextMenuPolicy(Qt.CustomContextMenu)
    ws.addWidget(app.txt_osint_detail, 1)

    workspace_scroll.setWidget(workspace)
    splitter.addWidget(browse)
    splitter.addWidget(workspace_scroll)
    splitter.setStretchFactor(0, 2)
    splitter.setStretchFactor(1, 3)
    splitter.setSizes([340, 620])
    root.addWidget(splitter, 1)

    app.list_osint_links = app.osint_links_host
    return page
