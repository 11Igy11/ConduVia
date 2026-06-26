from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTabWidget,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.analysis_limits import (
    EMBEDDED_SUMMARY_TOP_N,
    SUMMARY_CARD_HEIGHT,
    SUMMARY_CARD_WIDTH,
    SUMMARY_CARDS_WRAP_HEIGHT,
    SUMMARY_CARDS_WRAP_WIDTH,
    SUMMARY_VALUE_COL_WIDTH,
)
from ui.buttons import make_action_button, style_action_button
from ui.period_selector_panel import (
    build_period_selector_row,
    make_period_day_combo,
    make_period_label,
    make_period_mode_combo,
    make_pick_range_button,
)
from ui.dataset_header_layout import (
    DATASET_HEADER_MARGINS,
    DATASET_HEADER_SPACING,
    DATASET_PAGE_SPACING,
    PERIOD_COMBO_FILE_MIN_WIDTH,
    PERIOD_CONTROL_HEIGHT,
)
from ui.explore_models import FlowTableModel, NumericSortProxy
from ui.explore_widgets import FlowTableView
from ui.findings_page import FindingsPage

if TYPE_CHECKING:
    from ui.app import App


def build_explore_workspace(app: App) -> tuple[QWidget, QFrame]:
    # -------- Explore page --------
    explore_container = QWidget()
    explore_layout = QVBoxLayout(explore_container)

    app.lbl_project_banner = QLabel("Project: (none)")
    app.lbl_project_banner.setObjectName("HeaderProjectLabel")

    app.btn_load = make_action_button("Load dataset", object_name="ExploreTabActionButton")

    app.lbl_path = QLabel("No dataset loaded")
    app.lbl_path.setObjectName("HeaderPathLabel")
    app.lbl_path.setWordWrap(True)

    app.lbl_stats = QLabel("")
    app.lbl_stats.setObjectName("HeaderStatLabel")
    app.lbl_stats.setWordWrap(False)

    app.lbl_loaded = QLabel("")
    app.lbl_loaded.setObjectName("HeaderStatLabel")

    app.lbl_showing = QLabel("")
    app.lbl_showing.setObjectName("HeaderStatLabel")

    header_card = QFrame()
    header_card.setObjectName("ExploreHeaderCard")

    app.lbl_json_day = make_period_label(header_card)
    app.cmb_json_day = make_period_day_combo(header_card)

    app.cmb_json_file = QComboBox(header_card)
    app.cmb_json_file.setMinimumWidth(PERIOD_COMBO_FILE_MIN_WIDTH)
    app.cmb_json_file.setObjectName("CompactControl")
    app.cmb_json_file.setFixedHeight(PERIOD_CONTROL_HEIGHT)
    app.cmb_json_file.setVisible(False)

    app.lbl_json_meta = QLabel("")
    app.lbl_json_meta.setObjectName("HeaderStatLabel")
    app.lbl_json_meta.setWordWrap(False)
    app.lbl_json_meta.setTextInteractionFlags(Qt.TextSelectableByMouse)

    app.lbl_mode = QLabel("")
    app.lbl_mode.hide()

    app.lbl_conv_summary = QLabel("")
    app.lbl_conv_summary.hide()

    app.btn_load_more = make_action_button("Load next", enabled=False)

    app.cmb_page_size = QComboBox()
    app.cmb_page_size.setObjectName("CompactControl")
    app.cmb_page_size.setFixedHeight(28)
    app.cmb_page_size.addItems(["1000", "2000", "5000", "10000"])
    app.cmb_page_size.setCurrentText("2000")

    header_layout = QVBoxLayout(header_card)
    header_layout.setContentsMargins(*DATASET_HEADER_MARGINS)
    header_layout.setSpacing(DATASET_HEADER_SPACING)

    # row 1
    header_top = QHBoxLayout()
    header_top.setSpacing(4)

    header_top.addWidget(app.lbl_project_banner)
    header_top.addStretch()
    header_top.addWidget(QLabel("Page size:"))
    header_top.addWidget(app.cmb_page_size)
    header_top.addWidget(app.btn_load_more)

    # row 2
    header_mid = QHBoxLayout()
    header_mid.setSpacing(4)
    header_mid.setContentsMargins(0, 0, 0, 0)
    header_mid.addWidget(app.lbl_path, 1)

    # row 3 — stats only; period controls sit in the bottom row above tabs
    header_bottom = QHBoxLayout()
    header_bottom.setSpacing(2)
    header_bottom.setContentsMargins(0, 0, 0, 0)
    header_bottom.addWidget(app.lbl_stats, 1)

    app.cmb_json_period_mode = make_period_mode_combo(header_card)
    app.btn_json_pick_range = make_pick_range_button(header_card)
    app.json_period_row = build_period_selector_row(
        header_card,
        period_label=app.lbl_json_day,
        day_combo=app.cmb_json_day,
        mode_combo=app.cmb_json_period_mode,
        pick_range_button=app.btn_json_pick_range,
        middle_widgets=[app.cmb_json_file],
    )

    header_meta = QHBoxLayout()
    header_meta.setSpacing(4)
    header_meta.setContentsMargins(0, 0, 0, 0)
    header_meta.addWidget(app.lbl_json_meta, 1)

    app.lbl_json_gaps = QLabel("")
    app.lbl_json_gaps.setObjectName("MutedLabel")
    app.lbl_json_gaps.setWordWrap(True)
    app.btn_expand_json_gaps = make_action_button("Missing days")
    app.btn_expand_json_gaps.setVisible(False)

    json_gap_row = QHBoxLayout()
    json_gap_row.setSpacing(6)
    json_gap_row.addWidget(app.lbl_json_gaps, 1)
    json_gap_row.addWidget(app.btn_expand_json_gaps)

    app.lbl_json_load_progress = QLabel("")
    app.lbl_json_load_progress.setObjectName("MutedLabel")
    app.lbl_json_load_progress.setWordWrap(True)
    app.lbl_json_load_progress.hide()

    header_layout.addLayout(header_top)
    header_layout.addLayout(header_mid)
    header_layout.addLayout(header_bottom)
    header_layout.addLayout(header_meta)
    header_layout.addLayout(json_gap_row)
    header_layout.addWidget(app.lbl_json_load_progress)

    app.json_load_progress = QProgressBar()
    app.json_load_progress.setObjectName("InlineLoadProgress")
    app.json_load_progress.setFixedHeight(10)
    app.json_load_progress.setTextVisible(False)
    app.json_load_progress.hide()
    header_layout.addWidget(app.json_load_progress)
    header_layout.addWidget(app.json_period_row)

    app.search = QLineEdit()
    app.search.setPlaceholderText("Search IP / SNI / app...")
    app.search.setObjectName("CompactControl")
    app.search.setFixedHeight(28)

    app.tabs = QTabWidget()
    app.tabs.setObjectName("ExploreSubTabs")
    app.tabs.setDocumentMode(True)

    app.btn_ai_summary = make_action_button("Generate AI Summary", object_name="ExploreTabActionButton")
    app.btn_add_ai_to_notes = make_action_button(
        "Add AI to Notes",
        object_name="ExploreTabActionButton",
        enabled=True,
    )

    summary_tab = QWidget()
    summary_layout = QVBoxLayout(summary_tab)
    summary_layout.setContentsMargins(8, 8, 8, 8)
    summary_layout.setSpacing(8)

    app.summary_preview_rows: dict[str, list[tuple[QLabel, QLabel]]] = {}
    app.summary_preview_cards: dict[str, QGroupBox] = {}
    app.summary_expand_buttons: dict[str, QPushButton] = {}

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
            lbl_name.setWordWrap(False)
            lbl_name.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            lbl_name.setMinimumWidth(0)
            lbl_name.setTextInteractionFlags(Qt.TextSelectableByMouse)

            lbl_count = QLabel()
            lbl_count.setObjectName("SummaryPreviewCount")
            lbl_count.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            lbl_count.setFixedWidth(SUMMARY_VALUE_COL_WIDTH)
            lbl_count.setTextInteractionFlags(Qt.TextSelectableByMouse)

            row_layout.addWidget(lbl_name, 1)
            row_layout.addWidget(lbl_count, 0)
            rows.append((lbl_name, lbl_count))
            rows_layout.addLayout(row_layout)

        app.summary_preview_rows[key] = rows
        app.summary_preview_cards[key] = box
        layout.addLayout(rows_layout)
        layout.addStretch(1)

        expand = make_action_button("Expand table", object_name="SummaryExpandButton", enabled=False)
        expand.clicked.connect(lambda _checked=False, kind=key: app.dataset_controller.expand_dataset_summary(kind))
        app.summary_expand_buttons[key] = expand
        expand_row = QHBoxLayout()
        expand_row.addStretch()
        expand_row.addWidget(expand)
        layout.addLayout(expand_row)
        return box

    app.lbl_dataset_summary = QLabel("Dataset summary")
    app.lbl_dataset_summary.setObjectName("SectionTitle")

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
    dataset_column.addWidget(app.lbl_dataset_summary)
    dataset_column.addWidget(cards_panel)

    app.lbl_ai_summary = QLabel("AI assistant output")
    app.lbl_ai_summary.setObjectName("SectionTitle")

    app.txt_ai_summary = QTextEdit()
    app.txt_ai_summary.setReadOnly(True)
    app.txt_ai_summary.setPlaceholderText("Generate AI summary to populate this panel.")

    ai_output_card = QFrame()
    ai_output_card.setObjectName("Card")
    ai_output_card.setMinimumHeight(SUMMARY_CARDS_WRAP_HEIGHT)
    ai_output_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    ai_output_card_layout = QVBoxLayout(ai_output_card)
    ai_output_card_layout.setContentsMargins(10, 10, 10, 10)
    ai_output_card_layout.setSpacing(0)
    ai_output_card_layout.addWidget(app.txt_ai_summary, 1)

    ai_column = QVBoxLayout()
    ai_column.setContentsMargins(0, 0, 0, 0)
    ai_column.setSpacing(6)
    ai_column.addWidget(app.lbl_ai_summary)
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

    app.tabs.addTab(summary_tab, "Summary")

    flows_tab = QWidget()
    flows_tab_layout = QVBoxLayout(flows_tab)
    flows_tab_layout.setContentsMargins(8, 8, 8, 8)
    flows_tab_layout.setSpacing(8)

    # ----- FLOW TOOLBAR -----        
    toolbar_wrap = QFrame()
    toolbar_wrap.setObjectName("FlowToolbarCard")
    toolbar_wrap.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    toolbar_wrap.setFixedHeight(40)

    toolbar = QHBoxLayout(toolbar_wrap)
    toolbar.setContentsMargins(10, 6, 10, 6)
    toolbar.setSpacing(10)
    toolbar.setAlignment(Qt.AlignVCenter)

    left_actions = QHBoxLayout()
    left_actions.setSpacing(8)

    right_actions = QHBoxLayout()
    right_actions.setSpacing(8)

    app.btn_filter_src = make_action_button("Filter source")
    app.btn_filter_dst = make_action_button("Filter destination")
    app.btn_filter_sni = make_action_button("Filter SNI")

    app.btn_toggle_conv = make_action_button("Conversation: OFF")
    app.btn_expand_flows = make_action_button("Expand Flows")
    app.btn_mark_finding = make_action_button("Mark as Finding")
    app.btn_ai_explain = make_action_button("Explain with AI")

    app.btn_export_flows = make_action_button("Export table")

    left_actions.addSpacing(6)
    left_actions.addWidget(app.btn_filter_src)
    left_actions.addWidget(app.btn_filter_dst)
    left_actions.addWidget(app.btn_filter_sni)

    right_actions.addWidget(app.btn_toggle_conv)
    right_actions.addWidget(app.btn_expand_flows)
    right_actions.addWidget(app.btn_export_flows)
    right_actions.addWidget(app.btn_mark_finding)
    right_actions.addWidget(app.btn_ai_explain)

    toolbar.addLayout(left_actions)
    toolbar.addStretch()
    toolbar.addLayout(right_actions)

    flows_tab_layout.addWidget(app.search)
    flows_tab_layout.addWidget(toolbar_wrap)
    app.splitter = QSplitter(Qt.Horizontal)

    app.table = FlowTableView(app)
    app.table.setSortingEnabled(True)
    app.table.setAlternatingRowColors(True)
    app.table.setSelectionBehavior(QTableView.SelectRows)
    app.table.setSelectionMode(QTableView.SingleSelection)
    app.table.setWordWrap(False)
    app.table.setShowGrid(False)
    app.table.setCornerButtonEnabled(False)
    app.table.setEditTriggers(QTableView.NoEditTriggers)
    app.table.setFocusPolicy(Qt.StrongFocus)

    app.table.verticalHeader().setVisible(False)
    app.table.verticalHeader().setDefaultSectionSize(34)

    header = app.table.horizontalHeader()
    header.setStretchLastSection(False)
    header.setMinimumSectionSize(70)
    header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    header.setSectionResizeMode(QHeaderView.Interactive)

    app.model = FlowTableModel([])
    app.proxy = NumericSortProxy()
    app.proxy.setSourceModel(app.model)
    app.table.setModel(app.proxy)

    header = app.table.horizontalHeader()
    header.setSectionResizeMode(0, QHeaderView.Interactive)        # Source IP
    header.setSectionResizeMode(1, QHeaderView.Fixed)              # Source Port
    header.setSectionResizeMode(2, QHeaderView.Interactive)        # Destination IP
    header.setSectionResizeMode(3, QHeaderView.Fixed)              # Destination Port
    header.setSectionResizeMode(4, QHeaderView.Fixed)              # Protocol
    header.setSectionResizeMode(5, QHeaderView.Interactive)        # App
    header.setSectionResizeMode(6, QHeaderView.Fixed)              # Bytes
    header.setSectionResizeMode(7, QHeaderView.Fixed)              # Duration
    header.setSectionResizeMode(8, QHeaderView.Stretch)            # SNI
    app.table.setColumnWidth(0, 138)
    app.table.setColumnWidth(1, 92)
    app.table.setColumnWidth(2, 138)
    app.table.setColumnWidth(3, 116)
    app.table.setColumnWidth(4, 86)
    app.table.setColumnWidth(5, 140)
    app.table.setColumnWidth(6, 96)
    app.table.setColumnWidth(7, 104)

    app.splitter.addWidget(app.table)

    app.details_panel = QWidget()
    details_panel = app.details_panel
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

    app.d_src = QLabel("-"); app.d_src.setTextInteractionFlags(Qt.TextSelectableByMouse)
    app.d_dst = QLabel("-"); app.d_dst.setTextInteractionFlags(Qt.TextSelectableByMouse)
    app.d_proto = QLabel("-")
    app.d_app = QLabel("-")
    app.d_bytes = QLabel("-")
    app.d_packets = QLabel("-")
    app.d_duration = QLabel("-")
    app.d_sni = QLabel("-"); app.d_sni.setTextInteractionFlags(Qt.TextSelectableByMouse)

    for w in (app.d_src, app.d_dst, app.d_proto, app.d_app, app.d_bytes, app.d_packets, app.d_duration, app.d_sni):
        w.setWordWrap(True)
        w.setMinimumHeight(36)
        w.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)

    app.d_src.setTextFormat(Qt.PlainText)
    app.d_dst.setTextFormat(Qt.PlainText)
    app.d_sni.setTextFormat(Qt.PlainText)

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

    for val in (app.d_src, app.d_dst, app.d_proto, app.d_app, app.d_bytes, app.d_packets, app.d_duration, app.d_sni):
        val.setObjectName("FlowFieldValue")

    details_grid.addWidget(lbl_src,      0, 0)
    details_grid.addWidget(lbl_dst,      0, 1)
    details_grid.addWidget(app.d_src,   1, 0)
    details_grid.addWidget(app.d_dst,   1, 1)

    details_grid.addWidget(lbl_proto,    2, 0)
    details_grid.addWidget(lbl_app,      2, 1)
    details_grid.addWidget(app.d_proto, 3, 0)
    details_grid.addWidget(app.d_app,   3, 1)

    details_grid.addWidget(lbl_bytes,    4, 0)
    details_grid.addWidget(lbl_packets,  4, 1)
    details_grid.addWidget(app.d_bytes, 5, 0)
    details_grid.addWidget(app.d_packets, 5, 1)

    details_grid.addWidget(lbl_duration,    6, 0)
    details_grid.addWidget(app.d_duration, 7, 0)

    details_grid.addWidget(lbl_sni,         8, 0, 1, 2)
    details_grid.addWidget(app.d_sni,      9, 0, 1, 2)

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

    app.splitter.addWidget(details_panel)
    app.splitter.setStretchFactor(0, 5)
    app.splitter.setStretchFactor(1, 2)
    app.splitter.setCollapsible(1, False)

    flows_tab_layout.addWidget(app.splitter)
    app.tabs.addTab(flows_tab, "Flows")

    # Findings tab
    app.findings_page = FindingsPage()

    app.btn_finding_edit = app.findings_page.btn_finding_edit
    app.btn_finding_delete = app.findings_page.btn_finding_delete
    app.btn_finding_jump = app.findings_page.btn_finding_jump
    app.btn_finding_ai = app.findings_page.btn_finding_ai

    app.cmb_find_status = app.findings_page.cmb_find_status
    app.cmb_find_sort = app.findings_page.cmb_find_sort
    app.txt_find_search = app.findings_page.txt_find_search
    app.txt_find_tag = app.findings_page.txt_find_tag
    app.btn_find_clear = app.findings_page.btn_find_clear

    app.findings_list = app.findings_page.findings_list
    app.finding_detail = app.findings_page.finding_detail
    app.findings_split = app.findings_page.findings_split

    app.tabs.addTab(app.findings_page, "Findings")

    explore_ai_actions = QHBoxLayout()
    explore_ai_actions.setContentsMargins(0, 0, 8, 0)
    explore_ai_actions.setSpacing(6)
    explore_ai_actions.addWidget(app.btn_load)
    explore_ai_actions.addWidget(app.btn_ai_summary)
    explore_ai_actions.addWidget(app.btn_add_ai_to_notes)
    explore_ai_actions_widget = QWidget()
    explore_ai_actions_widget.setObjectName("ExploreTabActions")
    explore_ai_actions_widget.setLayout(explore_ai_actions)
    explore_ai_actions_widget.setFixedHeight(32)
    app.tabs.setCornerWidget(explore_ai_actions_widget, Qt.TopRightCorner)
    # Explore layout
    explore_layout.addWidget(app.lbl_mode)
    explore_layout.addWidget(app.lbl_conv_summary)
    explore_layout.addWidget(app.tabs, 1)
    return explore_container, header_card
