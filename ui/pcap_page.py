from __future__ import annotations

import hashlib
import os
import re
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QModelIndex, QObject, QThread, QTimer, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTableView,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)

from core.exporters.pcap_metadata_exporter import export_pcap_dns_csv, export_pcap_tls_csv
from core.analysis_limits import PROFILE_CHART_PREVIEW_ROWS
from ui.expand_dialogs import (
    build_dict_table,
    open_communication_indicators_dialog,
    open_dict_rows_expand_dialog,
    open_dict_table_expand_dialog,
    open_missing_period_days_dialog,
    set_dict_table_rows,
)
from ui.table_export import append_table_export_footer
from ui.buttons import make_action_button, style_action_button
from ui.dataset_header_layout import (
    DATASET_HEADER_MARGINS,
    DATASET_HEADER_SPACING,
    DATASET_PAGE_SPACING,
    DATASET_PERIOD_ROW_SPACING,
    DATASET_PERIOD_ROW_TOP_MARGIN,
    PERIOD_COMBO_DAY_MIN_WIDTH,
    PERIOD_COMBO_MODE_MIN_WIDTH,
    PERIOD_CONTROL_HEIGHT,
)
from core.formatters import format_duration_compact_ms, format_pcap_datetime, human_bytes
from core.evidence_policy import format_period_day_label, period_combo_label
from core.period_gaps import (
    calendar_days_between,
    format_period_gap_summary,
    missing_period_days,
    normalize_period_day,
    summarize_partial_months,
)
from core.period_groups import is_range_period_key, month_key, period_group_label
from core.period_selector import (
    PERIOD_MODE_OPTIONS,
    PeriodSelectorState,
    build_period_combo_entries,
    month_view_available,
    rebuild_period_selector,
)
from core.limit_notices import pcap_flow_cap_notice
from core.pcap_analyzer import (
    PcapSummary,
    analyze_pcap,
    analyze_pcap_files,
    build_investigator_view,
    merge_pcap_summaries,
)
from core.pcap_period import aggregate_hash_for_paths, capture_span_note, resolve_period_day, _iso_day_from_path
from core.protocols import format_ip_proto
from core.workspace import workspace_export_path
from core.db import (
    add_activity,
    file_sha256,
    save_pcap_period_summary,
    get_app_settings,
    get_project,
    list_project_pcap_device_ips,
    mark_ingest_item,
    set_project_subject,
    upsert_ingest_items,
)
from core.osint.public_ips import collect_public_ips_from_pcap_summary, merge_public_ips_into_profile
from core.project_evidence import get_saved_pcap_period_source
from ui.bar_chart_widget import BarChartWidget
from ui.dict_table_model import DictTableModel
from ui.explore_widgets import AITextWorker, CopyableTableView
from ui.font_utils import apply_named_style, refresh_widget_style
from ui.thread_utils import stop_qthread
from ui.worker_runner import WorkerRunner
from ui.workers.pcap_workers import PcapBatchWorker, PcapWorker


class VisibilityIndicatorRow(QFrame):
    def __init__(self, label: str, value: str, kind: str, opener, parent=None):
        super().__init__(parent)
        self._kind = kind
        self._opener = opener
        self.setObjectName("ProfileCountRow")
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip(f"Open table for {label}")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 7, 10, 7)
        layout.setSpacing(10)

        name = QLabel(label)
        name.setWordWrap(True)
        name.setObjectName("ChartLinkLabel")

        badge = QLabel(value)
        badge.setObjectName("ProfileCountBadge")
        badge.setAlignment(Qt.AlignCenter)
        badge.setMinimumWidth(96)

        layout.addWidget(name, 1)
        layout.addWidget(badge, 0)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self._opener(self._kind)
        super().mousePressEvent(event)


class PcapPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.app = parent
        self.summary: PcapSummary | None = None
        self._thread: QThread | None = None
        self._worker: PcapWorker | None = None
        self._batch_thread: QThread | None = None
        self._batch_worker: PcapBatchWorker | None = None
        self._ai_runner = WorkerRunner(self._thread_parent())
        self._saved_source_id: int | None = None
        self._pcap_queue: list[str] = []
        self._pcap_queue_auto_save = False
        self._pcap_queue_auto_process = False
        self._pcap_batch_total = 0
        self._pcap_batch_processed = 0
        self._pcap_batch_failed = 0
        self._pcap_batch_current_label = ""
        self._pcap_batch_last_ui_ts = 0.0
        self._batch_finish_guard = False
        self._project_batch_refresh_running = False
        self._batch_faulthandler_cancel = None
        self._pcap_day_groups_raw: dict[str, list[str]] = {}
        self._pcap_day_groups: dict[str, list[str]] = {}
        self._pcap_period_granularity = "day"
        self._pcap_period_range_start = ""
        self._pcap_period_range_end = ""
        self._pcap_active_day = ""
        self._period_load_progress: QProgressBar | None = None
        self._service_chart_full_rows: list[dict[str, Any]] = []
        self._activity_chart_full_rows: list[dict[str, Any]] = []
        self._all_artifacts: list[dict[str, Any]] = []
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(DATASET_PAGE_SPACING)

        header = QFrame()
        header.setObjectName("ExploreHeaderCard")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(*DATASET_HEADER_MARGINS)
        header_layout.setSpacing(DATASET_HEADER_SPACING)

        top = QHBoxLayout()
        top.setSpacing(4)
        self.lbl_title = QLabel("PCAP analysis")
        self.lbl_title.setObjectName("HeaderProjectLabel")
        self.btn_open = make_action_button("Load dataset")
        self.btn_save_project = make_action_button("Save Period to Project", enabled=False)
        self.btn_ai_summary = make_action_button("AI Summary", enabled=False)
        self.btn_add_notes = make_action_button("Add to Notes", enabled=False)
        self.btn_export = make_action_button("Export Summary", enabled=False)
        top.addWidget(self.lbl_title)
        top.addStretch()
        top.addWidget(self.btn_open)
        top.addWidget(self.btn_save_project)
        top.addWidget(self.btn_ai_summary)
        top.addWidget(self.btn_add_notes)
        top.addWidget(self.btn_export)

        self.lbl_file = QLabel("No PCAP loaded")
        self.lbl_file.setObjectName("HeaderPathLabel")
        self.lbl_file.setWordWrap(True)
        self.lbl_stats = QLabel("")
        self.lbl_stats.setObjectName("HeaderStatLabel")
        self.lbl_stats.setWordWrap(False)

        self.lbl_pcap_day = QLabel("Period:")
        self.lbl_pcap_day.setObjectName("HeaderStatLabel")
        self.lbl_pcap_day.setVisible(False)
        self.cmb_pcap_day = QComboBox()
        self.cmb_pcap_day.setMinimumWidth(PERIOD_COMBO_DAY_MIN_WIDTH)
        self.cmb_pcap_day.setObjectName("CompactControl")
        self.cmb_pcap_day.setFixedHeight(PERIOD_CONTROL_HEIGHT)
        self.cmb_pcap_day.setVisible(False)
        self.cmb_pcap_period_mode = QComboBox()
        self.cmb_pcap_period_mode.setMinimumWidth(PERIOD_COMBO_MODE_MIN_WIDTH)
        self.cmb_pcap_period_mode.setObjectName("CompactControl")
        self.cmb_pcap_period_mode.setFixedHeight(PERIOD_CONTROL_HEIGHT)
        for label, value in PERIOD_MODE_OPTIONS:
            self.cmb_pcap_period_mode.addItem(label, value)
        self.cmb_pcap_period_mode.setVisible(False)
        self.btn_pcap_pick_range = make_action_button("Pick range…")
        self.btn_pcap_pick_range.hide()
        self.btn_reanalyze_period = make_action_button("Re-analyze Period", enabled=False)
        self.btn_reanalyze_period.setToolTip(
            "Re-run PCAP analysis for the selected period from source files."
        )
        self.btn_reanalyze_period.setVisible(False)

        header_bottom = QHBoxLayout()
        header_bottom.setSpacing(2)
        header_bottom.setContentsMargins(0, 0, 0, 0)
        header_bottom.addWidget(self.lbl_stats, 1)

        self.pcap_period_row = QWidget()
        pcap_period_layout = QHBoxLayout(self.pcap_period_row)
        pcap_period_layout.setContentsMargins(0, DATASET_PERIOD_ROW_TOP_MARGIN, 0, 0)
        pcap_period_layout.setSpacing(DATASET_PERIOD_ROW_SPACING)
        pcap_period_layout.addWidget(self.lbl_pcap_day)
        pcap_period_layout.addWidget(self.cmb_pcap_day)
        pcap_period_layout.addWidget(self.cmb_pcap_period_mode)
        pcap_period_layout.addWidget(self.btn_pcap_pick_range)
        pcap_period_layout.addWidget(self.btn_reanalyze_period)
        pcap_period_layout.addStretch(1)
        self.pcap_period_row.setVisible(False)

        self.lbl_pcap_meta = QLabel("")
        self.lbl_pcap_meta.setObjectName("HeaderStatLabel")
        self.lbl_pcap_meta.setWordWrap(False)
        header_meta = QHBoxLayout()
        header_meta.setSpacing(4)
        header_meta.setContentsMargins(0, 0, 0, 0)
        header_meta.addWidget(self.lbl_pcap_meta, 1)

        self.lbl_period_gaps = QLabel("")
        self.lbl_period_gaps.setObjectName("MutedLabel")
        self.lbl_period_gaps.setWordWrap(True)
        self.btn_expand_period_gaps = make_action_button("Missing days")
        self.btn_expand_period_gaps.setVisible(False)
        self.btn_expand_period_gaps.clicked.connect(self._open_missing_days_dialog)
        self._period_gap_info: dict[str, object] = {}
        gap_row = QHBoxLayout()
        gap_row.setSpacing(6)
        gap_row.addWidget(self.lbl_period_gaps, 1)
        gap_row.addWidget(self.btn_expand_period_gaps)
        self._period_gap_row = gap_row

        self.lbl_limit_notice = QLabel("")
        self.lbl_limit_notice.setObjectName("AnalysisLimitNotice")
        self.lbl_limit_notice.setWordWrap(True)
        self.lbl_limit_notice.hide()

        self.lbl_load_progress = QLabel("")
        self.lbl_load_progress.setObjectName("MutedLabel")
        self.lbl_load_progress.setWordWrap(True)
        self.lbl_load_progress.hide()
        self.load_progress = QProgressBar()
        self.load_progress.setObjectName("InlineLoadProgress")
        self.load_progress.setFixedHeight(10)
        self.load_progress.setTextVisible(False)
        self.load_progress.hide()

        header_layout.addLayout(top)
        header_layout.addWidget(self.lbl_file)
        header_layout.addLayout(header_bottom)
        header_layout.addLayout(header_meta)
        header_layout.addLayout(gap_row)
        header_layout.addWidget(self.lbl_limit_notice)
        header_layout.addWidget(self.lbl_load_progress)
        header_layout.addWidget(self.load_progress)

        self.batch_status_panel = QFrame()
        self.batch_status_panel.setObjectName("InlinePanel")
        batch_layout = QHBoxLayout(self.batch_status_panel)
        batch_layout.setContentsMargins(8, 6, 8, 6)
        batch_layout.setSpacing(8)
        self.lbl_batch_status = QLabel("")
        self.lbl_batch_status.setObjectName("MutedLabel")
        self.lbl_batch_status.setWordWrap(True)
        batch_layout.addWidget(self.lbl_batch_status, 1)
        self.batch_status_panel.setVisible(False)
        header_layout.addWidget(self.batch_status_panel)
        header_layout.addWidget(self.pcap_period_row)
        root.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_investigator_tab(), "Summary")
        self.tabs.addTab(self._build_highlights_tab(), "Communications")
        self.tabs.addTab(self._build_evidence_section(), "Evidence")
        self.tabs.addTab(self._build_network_section(), "Network")
        self.ai_summary_tab = self._build_ai_tab()
        self.tabs.addTab(self.ai_summary_tab, "AI Summary")
        root.addWidget(self.tabs, 1)

        self.btn_open.clicked.connect(self.open_pcap_dialog)
        self.btn_save_project.clicked.connect(self.save_to_project)
        self.btn_ai_summary.clicked.connect(self.generate_ai_summary)
        self.btn_add_notes.clicked.connect(self.add_summary_to_notes)
        self.btn_export.clicked.connect(self.export_summary)
        self.btn_reanalyze_period.clicked.connect(self.reanalyze_current_period)
        self.cmb_pcap_day.currentIndexChanged.connect(self._on_pcap_day_changed)
        self.cmb_pcap_period_mode.currentIndexChanged.connect(self._on_pcap_period_mode_changed)
        self.btn_pcap_pick_range.clicked.connect(self.configure_pcap_period_range)

    def _build_summary_section(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.summary_tabs = QTabWidget()
        self.summary_tabs.addTab(self._build_highlights_tab(), "Highlights")
        self.summary_tabs.addTab(self._build_investigator_tab(), "Investigator View")
        self.summary_tabs.addTab(self._build_overview_tab(), "Overview")
        self.ai_summary_tab = self._build_ai_tab()
        self.summary_tabs.addTab(self.ai_summary_tab, "AI Summary")
        layout.addWidget(self.summary_tabs)
        return page

    def _build_evidence_section(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.evidence_tabs = QTabWidget()
        self.evidence_tabs.addTab(self._build_evidence_tab(), "Evidence")
        self.evidence_tabs.addTab(self._build_artifacts_tab(), "Artifacts")
        layout.addWidget(self.evidence_tabs)
        return page

    def _build_network_section(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.network_tabs = QTabWidget()
        self.network_tabs.addTab(self._build_overview_tab(), "Overview")
        self.network_tabs.addTab(self._build_connections_tab(), "Connections")
        layout.addWidget(self.network_tabs)
        return page

    def _build_highlights_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(14, 14, 14, 28)
        layout.setSpacing(14)

        self.lbl_highlights_brief = QLabel("Open a PCAP file to see communication highlights.")
        self.lbl_highlights_brief.setObjectName("PcapPlainSummary")
        self.lbl_highlights_brief.setWordWrap(True)
        self.lbl_highlights_brief.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.communication_full_columns = [
            ("service", "Service"),
            ("activity_type", "Indicator"),
            ("confidence", "Confidence"),
            ("host", "Host / Signal"),
            ("protocol", "Protocol"),
            ("bytes", "Volume"),
            ("packets", "Packets"),
            ("duration_ms", "Duration"),
            ("first_seen", "First Seen"),
        ]
        self.communication_columns = [
            ("service", "Service"),
            ("activity_type", "Indicator"),
            ("host", "Host / Signal"),
            ("bytes", "Volume"),
            ("packets", "Packets"),
            ("duration_ms", "Duration"),
            ("first_seen", "First Seen"),
        ]
        self.communication_fixed_widths = {0: 170, 1: 190, 3: 95, 4: 85, 5: 100, 6: 175}
        self.communication_full_fixed_widths = {0: 170, 1: 190, 2: 95, 3: 240, 4: 80, 5: 95, 6: 85, 7: 105, 8: 175}
        self.tbl_communications = self._table(
            self.communication_columns,
            fixed_widths=self.communication_fixed_widths,
            stretch_columns=[2],
        )
        self.tbl_communications.setMinimumHeight(360)
        self.tbl_communications.setWordWrap(True)
        self.tbl_communications.verticalHeader().setDefaultSectionSize(40)
        self.tbl_communications.sortByColumn(3, Qt.DescendingOrder)
        self.tbl_communications.selectionModel().currentRowChanged.connect(self._on_communication_selected)
        self.tbl_communications.hide()

        self.txt_communication_detail = QTextEdit()
        self.txt_communication_detail.setReadOnly(True)
        self.txt_communication_detail.setMinimumWidth(300)
        self.txt_communication_detail.setPlaceholderText("Select a communication indicator to see the evidence used for classification.")
        self.txt_communication_detail.hide()

        self.btn_expand_communications = QPushButton("Open full communication table")
        self.btn_expand_communications.setMinimumHeight(38)
        self.btn_expand_communications.clicked.connect(self._open_communications_dialog)

        brief_group = self._group("Investigation brief", self.lbl_highlights_brief)
        brief_group.setMaximumHeight(160)

        self.lbl_communication_count = QLabel("0 indicators")
        self.lbl_communication_count.setObjectName("ProfileMetric")
        self.lbl_communication_count.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_communication_breakdown = QLabel("Messaging/push: 0 | Possible call/media: 0 | Services: 0")
        self.lbl_communication_breakdown.setObjectName("MutedLabel")
        self.lbl_communication_breakdown.setWordWrap(True)
        self.lbl_communication_breakdown.setTextInteractionFlags(Qt.TextSelectableByMouse)

        communication_card = self._evidence_launcher_card(
            "Communication indicators",
            "Metadata-based app/service indicators. Open the full table to sort, copy and inspect evidence for each row.",
            self.lbl_communication_count,
            self.lbl_communication_breakdown,
            self.btn_expand_communications,
        )
        layout.addWidget(brief_group)
        layout.addWidget(communication_card, 0)
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

        return page

    def _build_investigator_tab(self) -> QWidget:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(14)

        self.investigator_card = QFrame()
        self.investigator_card.setObjectName("PcapInvestigatorCard")
        self.investigator_card.setMinimumHeight(165)
        self.investigator_card.setMaximumHeight(240)
        card_layout = QVBoxLayout(self.investigator_card)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(8)

        self.lbl_plain_summary = QLabel("Open a PCAP file to see a plain-language investigation view.")
        self.lbl_plain_summary.setObjectName("PcapPlainSummary")
        self.lbl_plain_summary.setWordWrap(True)
        self.lbl_plain_summary.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.lbl_key_points = QLabel("")
        self.lbl_key_points.setObjectName("PcapKeyPoints")
        self.lbl_key_points.setWordWrap(True)
        self.lbl_key_points.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.lbl_limitations = QLabel("")
        self.lbl_limitations.setObjectName("PcapLimitations")
        self.lbl_limitations.setWordWrap(True)
        self.lbl_limitations.setTextInteractionFlags(Qt.TextSelectableByMouse)

        card_layout.addWidget(self.lbl_plain_summary)
        card_layout.addWidget(self.lbl_key_points)
        card_layout.addWidget(self.lbl_limitations)

        self.chart_services = BarChartWidget(
            "Visible service groups",
            value_key="count",
            value_label_key="value",
            label_width=175,
            label_limit=34,
            max_rows=PROFILE_CHART_PREVIEW_ROWS,
        )
        self.chart_activity = BarChartWidget(
            "Hourly activity (peak hours)",
            value_key="count",
            value_label_key="value",
            label_width=175,
            label_limit=28,
            max_rows=PROFILE_CHART_PREVIEW_ROWS,
        )
        self.visibility_panel = self._build_visibility_panel()
        self.chart_services.set_rows([], empty_text="Open a PCAP file to show visible service groups.")
        self.chart_activity.set_rows([], empty_text="Open a PCAP file to show hourly packet activity.")

        self.btn_expand_chart_services = make_action_button(
            "Expand table",
            object_name="SummaryExpandButton",
            enabled=False,
        )
        self.btn_expand_chart_services.clicked.connect(self._expand_service_chart)

        self.btn_expand_chart_activity = make_action_button(
            "Expand table",
            object_name="SummaryExpandButton",
            enabled=False,
        )
        self.btn_expand_chart_activity.clicked.connect(self._expand_activity_chart)

        services_box = QVBoxLayout()
        services_box.setSpacing(6)
        services_box.addWidget(self.chart_services, 1)
        expand_services = QHBoxLayout()
        expand_services.addStretch()
        expand_services.addWidget(self.btn_expand_chart_services)
        services_box.addLayout(expand_services)

        activity_box = QVBoxLayout()
        activity_box.setSpacing(6)
        activity_box.addWidget(self.chart_activity, 1)
        expand_activity = QHBoxLayout()
        expand_activity.addStretch()
        expand_activity.addWidget(self.btn_expand_chart_activity)
        activity_box.addLayout(expand_activity)

        services_widget = QWidget()
        services_widget.setLayout(services_box)
        activity_widget = QWidget()
        activity_widget.setLayout(activity_box)

        top = QHBoxLayout()
        top.setSpacing(10)
        self.chart_services.setMinimumHeight(260)
        self.chart_activity.setMinimumHeight(260)
        self.visibility_panel.setMinimumHeight(170)

        top.addWidget(services_widget, 1)
        top.addWidget(activity_widget, 1)

        layout.addWidget(self.investigator_card, 0)
        layout.addLayout(top, 2)
        layout.addWidget(self.visibility_panel, 1)
        layout.addStretch()

        scroll.setWidget(content)
        page_layout.addWidget(scroll, 1)
        return page

    def _build_ai_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        self.txt_pcap_ai_summary = QTextEdit()
        self.txt_pcap_ai_summary.setReadOnly(True)
        self.txt_pcap_ai_summary.setPlaceholderText("Open a PCAP file, then generate an AI explanation grounded in the extracted evidence.")
        layout.addWidget(self.txt_pcap_ai_summary, 1)
        return page

    def _build_overview_tab(self) -> QWidget:
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(14)

        self.overview_card = QFrame()
        self.overview_card.setObjectName("PcapInvestigatorCard")
        self.overview_card.setMinimumHeight(190)
        overview_card_layout = QVBoxLayout(self.overview_card)
        overview_card_layout.setContentsMargins(14, 12, 14, 12)

        self.lbl_overview_text = QLabel("Open a PCAP file to see a readable investigation overview.")
        self.lbl_overview_text.setObjectName("PcapKeyPoints")
        self.lbl_overview_text.setWordWrap(True)
        self.lbl_overview_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        overview_card_layout.addWidget(self.lbl_overview_text)

        self.tbl_network_overview = self._table(
            [
                ("section", "Section"),
                ("value", "Value"),
                ("detail", "Detail"),
                ("packets", "Packets"),
            ],
            fixed_widths={0: 145, 3: 105},
            stretch_columns=[1, 2],
        )
        self.tbl_network_overview.setMinimumHeight(430)
        self.tbl_network_overview.verticalHeader().setDefaultSectionSize(38)
        self.tbl_network_overview.hide()
        self.btn_expand_network_overview = make_action_button("Open full network table")
        self.btn_expand_network_overview.clicked.connect(
            lambda: self._open_table_dialog("Network overview", self.tbl_network_overview)
        )

        self.lbl_network_overview_count = QLabel("0 rows")
        self.lbl_network_overview_count.setObjectName("ProfileMetric")
        self.lbl_network_overview_count.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_network_overview_breakdown = QLabel("Protocols: 0 | Endpoints: 0 | Ports: 0")
        self.lbl_network_overview_breakdown.setObjectName("MutedLabel")
        self.lbl_network_overview_breakdown.setWordWrap(True)
        self.lbl_network_overview_breakdown.setTextInteractionFlags(Qt.TextSelectableByMouse)

        network_card = self._evidence_launcher_card(
            "Network overview",
            "Combined view of protocols, top endpoints and top ports observed in the capture.",
            self.lbl_network_overview_count,
            self.lbl_network_overview_breakdown,
            self.btn_expand_network_overview,
        )

        layout.addWidget(self.overview_card)
        layout.addWidget(network_card, 0)
        layout.addStretch()

        scroll.setWidget(content)
        page_layout.addWidget(scroll, 1)
        return page

    def _build_evidence_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(14, 14, 14, 28)
        layout.setSpacing(14)

        self.lbl_evidence_hint = QLabel(
            "This view shows readable metadata and unencrypted payload snippets only. "
            "Encrypted HTTPS, QUIC and app content remain metadata-level indicators."
        )
        self.lbl_evidence_hint.setObjectName("MutedLabel")
        self.lbl_evidence_hint.setWordWrap(True)
        self.lbl_evidence_hint.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.lbl_evidence_hint)

        self.tbl_visible_metadata = self._table(
            [("type", "Type"), ("value", "Visible Value"), ("count", "Count")],
            fixed_widths={0: 140, 2: 90},
            stretch_columns=[1],
        )
        self.tbl_samples = self._table([
            ("time", "Time"),
            ("type", "Type"),
            ("source", "Source"),
            ("destination", "Destination"),
            ("value", "Visible Value"),
        ], fixed_widths={0: 178, 1: 130, 2: 180, 3: 180}, stretch_columns=[4])

        self.tbl_visible_metadata.setMinimumHeight(250)
        self.tbl_samples.setMinimumHeight(320)
        self.tbl_samples.verticalHeader().setDefaultSectionSize(38)
        self.tbl_visible_metadata.hide()
        self.tbl_samples.hide()

        self.btn_expand_metadata = make_action_button("Open full metadata table")
        self.btn_expand_metadata.clicked.connect(
            lambda: self._open_table_dialog("Visible metadata", self.tbl_visible_metadata)
        )

        self.btn_expand_samples = make_action_button("Open full samples table")
        self.btn_expand_samples.clicked.connect(
            lambda: self._open_table_dialog("Readable payload / metadata samples", self.tbl_samples)
        )

        self.lbl_visible_metadata_count = QLabel("0 rows")
        self.lbl_visible_metadata_count.setObjectName("ProfileMetric")
        self.lbl_visible_metadata_count.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_visible_metadata_breakdown = QLabel("DNS: 0 | TLS SNI: 0 | HTTP hosts: 0")
        self.lbl_visible_metadata_breakdown.setObjectName("MutedLabel")
        self.lbl_visible_metadata_breakdown.setWordWrap(True)
        self.lbl_visible_metadata_breakdown.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.lbl_samples_count = QLabel("0 rows")
        self.lbl_samples_count.setObjectName("ProfileMetric")
        self.lbl_samples_count.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_samples_hint = QLabel(
            "Visible values are extracted from DNS names, TLS SNI, HTTP host/header data and plaintext payload previews. "
            "Treat them as observable network evidence, not as decrypted message content."
        )
        self.lbl_samples_hint.setObjectName("MutedLabel")
        self.lbl_samples_hint.setWordWrap(True)
        self.lbl_samples_hint.setTextInteractionFlags(Qt.TextSelectableByMouse)

        cards = QGridLayout()
        cards.setSpacing(14)
        cards.addWidget(
            self._evidence_launcher_card(
                "Visible metadata",
                "DNS queries, TLS SNI names and HTTP host values observed in the capture.",
                self.lbl_visible_metadata_count,
                self.lbl_visible_metadata_breakdown,
                self.btn_expand_metadata,
            ),
            0,
            0,
        )
        cards.addWidget(
            self._evidence_launcher_card(
                "Readable payload / metadata samples",
                "Timestamped values that can be inspected as rows when the full table is opened.",
                self.lbl_samples_count,
                self.lbl_samples_hint,
                self.btn_expand_samples,
            ),
            0,
            1,
        )
        cards.setColumnStretch(0, 1)
        cards.setColumnStretch(1, 1)

        layout.addLayout(cards)

        export_row = QHBoxLayout()
        export_row.setSpacing(10)
        self.btn_export_full_dns = QPushButton("Export full DNS CSV")
        self.btn_export_full_dns.setEnabled(False)
        self.btn_export_full_tls = QPushButton("Export full TLS CSV")
        self.btn_export_full_tls.setEnabled(False)
        self.btn_export_full_dns.clicked.connect(lambda: self._export_full_metadata("dns"))
        self.btn_export_full_tls.clicked.connect(lambda: self._export_full_metadata("tls"))
        export_row.addWidget(self.btn_export_full_dns)
        export_row.addWidget(self.btn_export_full_tls)
        export_row.addStretch()
        layout.addLayout(export_row)

        workflow_hint = QLabel(
            "Use the full table view for investigation work: sorting, copying values and reading wide columns. "
            "The embedded Evidence page is intentionally a compact overview."
        )
        workflow_hint.setObjectName("MutedLabel")
        workflow_hint.setWordWrap(True)
        workflow_hint.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(workflow_hint)
        layout.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll, 1)
        return page

    def _evidence_launcher_card(
        self,
        title: str,
        description: str,
        count_label: QLabel,
        detail_label: QLabel,
        button: QPushButton,
    ) -> QFrame:
        card = QFrame()
        card.setObjectName("Card")
        card.setMinimumHeight(190)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 16, 18, 18)
        layout.setSpacing(8)

        lbl_title = QLabel(title)
        lbl_title.setObjectName("SectionTitle")
        lbl_title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lbl_description = QLabel(description)
        lbl_description.setObjectName("MutedLabel")
        lbl_description.setWordWrap(True)
        lbl_description.setTextInteractionFlags(Qt.TextSelectableByMouse)

        count_label.setMinimumHeight(28)
        detail_label.setMinimumHeight(36)

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_description)
        layout.addWidget(count_label)
        layout.addWidget(detail_label)

        button.setMinimumHeight(38)
        button_row = QHBoxLayout()
        button_row.setContentsMargins(0, 6, 0, 0)
        button_row.addStretch()
        button_row.addWidget(button)
        layout.addLayout(button_row)
        return card

    def _sync_save_period_button(self, *, visible: bool | None = None, saved: bool = False, hide: bool = False) -> None:
        btn = getattr(self, "btn_save_project", None)
        if btn is None:
            return
        if saved:
            btn.setText("Saved to Project")
            btn.setEnabled(False)
            btn.setToolTip("This period is already saved to the project.")
            btn.setVisible(not hide)
            return
        if visible is not None:
            btn.setVisible(visible)
        elif self._pcap_queue_auto_save:
            btn.setVisible(False)
        else:
            btn.setVisible(True)

    def _current_period_day(self) -> str:
        if self._pcap_active_day:
            return str(self._pcap_active_day)
        summary = getattr(self, "summary", None)
        if summary is None:
            return ""
        source_paths = list(getattr(summary, "source_paths", None) or [])
        if not source_paths and getattr(summary, "file_path", ""):
            source_paths = [summary.file_path]
        return resolve_period_day(
            active_day=self._pcap_active_day,
            file_paths=source_paths,
            first_seen=getattr(summary, "first_seen", None),
            last_seen=getattr(summary, "last_seen", None),
        )

    def _current_period_already_saved(self) -> bool:
        project_id = self._current_project_id()
        day = self._current_period_day()
        if project_id is None or not day:
            return False
        return get_saved_pcap_period_source(project_id, day) is not None

    def _update_period_gap_banner(self, present_days: list[str] | None = None) -> None:
        raw_days = [
            day
            for day in (self._pcap_day_groups_raw.keys() if self._pcap_day_groups_raw else [])
            if str(day or "").strip()
        ]
        days = list(present_days if present_days is not None else raw_days or self._pcap_day_groups.keys())
        gap = missing_period_days(days)
        self._period_gap_info = gap
        summary = format_period_gap_summary(
            days,
            granularity="day" if raw_days else getattr(self, "_pcap_period_granularity", "day"),
        )
        if getattr(self, "_pcap_period_granularity", "day") == "day":
            partial = summarize_partial_months(days)
            if partial:
                summary = f"{summary}\n{partial}" if summary else partial
        if hasattr(self, "lbl_period_gaps"):
            self.lbl_period_gaps.setText(summary)
            self.lbl_period_gaps.setToolTip(summary)
        if hasattr(self, "btn_expand_period_gaps"):
            missing_count = int(gap.get("missing_count") or 0)
            self.btn_expand_period_gaps.setVisible(missing_count > 0)
            self.btn_expand_period_gaps.setText(f"Missing days ({missing_count:,})")
        self._sync_period_gap_visibility()

    def _sync_period_gap_visibility(self) -> None:
        # Hide coverage row only while a period is actively being analyzed on the worker thread.
        # Day groups are known during batch import — keep the gap banner visible like on JSON.
        loading = self._thread is not None
        if hasattr(self, "lbl_period_gaps"):
            self.lbl_period_gaps.setVisible(bool(str(self.lbl_period_gaps.text() or "").strip()) and not loading)
        if hasattr(self, "btn_expand_period_gaps"):
            missing_count = int(self._period_gap_info.get("missing_count") or 0)
            self.btn_expand_period_gaps.setVisible(missing_count > 0 and not loading)

    def _update_limit_notice(self, summary: PcapSummary | None = None) -> None:
        banner = getattr(self, "lbl_limit_notice", None)
        if banner is None:
            return
        summary = summary or getattr(self, "summary", None)
        if summary is None:
            banner.hide()
            banner.clear()
            return
        text = pcap_flow_cap_notice(
            flows_capped=bool(getattr(summary, "flows_capped", False)),
            flow_map_limit=int(getattr(summary, "flow_map_limit", 0) or 0),
            total_flows=int(getattr(summary, "total_flows", 0) or len(summary.flows or [])),
        )
        if text:
            banner.setText(text)
            banner.show()
        else:
            banner.hide()
            banner.clear()

    def _open_missing_days_dialog(self) -> None:
        open_missing_period_days_dialog(
            self,
            title="Missing PCAP days",
            missing_days=list(self._period_gap_info.get("missing_days") or []),
            first_day_label=self._format_day_label(str(self._period_gap_info.get("first_day") or "")),
            last_day_label=self._format_day_label(str(self._period_gap_info.get("last_day") or "")),
            evidence_kind="PCAP",
            format_day_label=self._format_day_label,
            on_empty=self._info,
            append_export_footer=lambda footer, table: self._append_export_footer(
                footer, title="Missing PCAP days", table=table
            ),
        )

    def _build_visibility_panel(self) -> QFrame:
        panel = QFrame()
        panel.setObjectName("Card")
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 10, 12, 12)
        layout.setSpacing(8)

        title = QLabel("Visible vs encrypted indicators")
        title.setObjectName("SectionTitle")
        layout.addWidget(title)

        self.lbl_visibility_empty = QLabel("Open a PCAP file to show readable vs encrypted indicators.")
        self.lbl_visibility_empty.setObjectName("MutedLabel")
        self.lbl_visibility_empty.setWordWrap(True)
        layout.addWidget(self.lbl_visibility_empty)

        self.visibility_rows_layout = QVBoxLayout()
        self.visibility_rows_layout.setSpacing(6)
        layout.addLayout(self.visibility_rows_layout)
        layout.addStretch()
        return panel

    def _build_artifacts_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(14, 14, 14, 28)
        layout.setSpacing(14)

        controls = QHBoxLayout()
        controls.setSpacing(10)
        controls.addWidget(QLabel("Category"))
        self.cmb_artifact_category = QComboBox()
        self.cmb_artifact_category.setMinimumWidth(240)
        self.cmb_artifact_category.currentIndexChanged.connect(self._apply_artifact_filter)
        self.lbl_artifact_count = QLabel("")
        self.lbl_artifact_count.setObjectName("MutedLabel")
        self.btn_expand_artifacts = make_action_button("Open full artifacts table")
        self.btn_expand_artifacts.clicked.connect(
            lambda: self._open_table_dialog("Extracted artifacts", self.tbl_artifacts)
        )
        controls.addWidget(self.cmb_artifact_category)
        controls.addWidget(self.lbl_artifact_count)
        controls.addStretch()

        columns = [
            ("category", "Category"),
            ("type", "Type"),
            ("value", "Value"),
            ("count", "Count"),
            ("visibility", "Visibility"),
            ("first_seen", "First Seen"),
            ("last_seen", "Last Seen"),
            ("source", "Source"),
            ("destination", "Destination"),
            ("explanation", "Meaning"),
        ]

        self.tbl_artifacts = self._table(
            columns,
            fixed_widths={0: 150, 1: 180, 2: 360, 3: 80, 4: 150, 5: 170, 6: 170, 7: 210, 8: 210, 9: 380},
            stretch_columns=[],
        )
        self.tbl_artifacts.setMinimumHeight(360)
        self.tbl_artifacts.selectionModel().currentRowChanged.connect(self._on_artifact_selected)
        self.tbl_artifacts.hide()

        self.txt_artifact_detail = QTextEdit()
        self.txt_artifact_detail.setReadOnly(True)
        self.txt_artifact_detail.setMinimumHeight(150)
        self.txt_artifact_detail.setPlaceholderText("Select an artifact to see source, destination and explanation.")
        self.txt_artifact_detail.hide()

        self.lbl_artifact_total = QLabel("0 artifacts")
        self.lbl_artifact_total.setObjectName("ProfileMetric")
        self.lbl_artifact_total.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_artifact_preview = QLabel("No artifact categories loaded.")
        self.lbl_artifact_preview.setObjectName("SummaryTextBox")
        self.lbl_artifact_preview.setWordWrap(True)
        self.lbl_artifact_preview.setMinimumHeight(72)
        self.lbl_artifact_preview.setTextInteractionFlags(Qt.TextSelectableByMouse)

        artifact_card = QFrame()
        artifact_card.setObjectName("Card")
        artifact_card_layout = QVBoxLayout(artifact_card)
        artifact_card_layout.setContentsMargins(18, 16, 18, 18)
        artifact_card_layout.setSpacing(8)

        lbl_title = QLabel("Extracted artifacts")
        lbl_title.setObjectName("SectionTitle")
        lbl_description = QLabel(
            "Visible web, local network, credential and Windows/enterprise indicators extracted from readable capture data."
        )
        lbl_description.setObjectName("MutedLabel")
        lbl_description.setWordWrap(True)
        artifact_card_layout.addWidget(lbl_title)
        artifact_card_layout.addWidget(lbl_description)
        artifact_card_layout.addWidget(self.lbl_artifact_total)
        artifact_card_layout.addWidget(self.lbl_artifact_preview)

        button_row = QHBoxLayout()
        button_row.addStretch()
        button_row.addWidget(self.btn_expand_artifacts)
        artifact_card_layout.addLayout(button_row)

        layout.addLayout(controls)
        layout.addWidget(artifact_card, 0)
        layout.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll, 1)
        return page

    def _build_connections_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 28)
        layout.setSpacing(14)

        self.btn_expand_connections = make_action_button("Open full connections table")
        self.btn_expand_connections.clicked.connect(
            lambda: self._open_table_dialog("Connections", self.tbl_connections)
        )
        self.tbl_connections = self._table([
            ("src_ip", "Source IP"),
            ("src_port", "Source Port"),
            ("dst_ip", "Destination IP"),
            ("dst_port", "Destination Port"),
            ("protocol", "Protocol"),
            ("application_name", "Application"),
            ("requested_server_name", "Host/Query"),
            ("bidirectional_bytes", "Bytes"),
            ("bidirectional_packets", "Packets"),
            ("bidirectional_first_seen_ms", "First Seen"),
            ("bidirectional_last_seen_ms", "Last Seen"),
            ("pcap_payload_preview", "Visible Preview"),
        ], fixed_widths={0: 145, 1: 105, 2: 145, 3: 125, 4: 92, 5: 145, 6: 260, 7: 110, 8: 105, 9: 180, 10: 180, 11: 300}, stretch_columns=[])
        self.tbl_connections.hide()

        self.lbl_connections_count = QLabel("0 connections")
        self.lbl_connections_count.setObjectName("ProfileMetric")
        self.lbl_connections_count.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_connections_breakdown = QLabel("No connection rows loaded.")
        self.lbl_connections_breakdown.setObjectName("MutedLabel")
        self.lbl_connections_breakdown.setWordWrap(True)
        self.lbl_connections_breakdown.setTextInteractionFlags(Qt.TextSelectableByMouse)

        layout.addWidget(
            self._evidence_launcher_card(
                "Connections",
                "Full flow-level connection rows from the capture, including endpoints, ports, protocol, volume, timing and visible previews.",
                self.lbl_connections_count,
                self.lbl_connections_breakdown,
                self.btn_expand_connections,
            ),
            0,
        )
        layout.addStretch()
        return page

    def _table(
        self,
        columns: list[tuple[str, str]],
        *,
        stretch_last: bool = False,
        fixed_widths: dict[int, int] | None = None,
        stretch_columns: list[int] | None = None,
    ) -> CopyableTableView:
        return build_dict_table(
            self.app,
            columns,
            stretch_last=stretch_last,
            fixed_widths=fixed_widths,
            stretch_columns=stretch_columns,
        )

    def _group(self, title: str, widget: QWidget) -> QGroupBox:
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        layout.addWidget(widget)
        return group

    def _open_table_dialog(self, title: str, source_table: QTableView) -> None:
        open_dict_table_expand_dialog(
            self,
            title=title,
            source_table=source_table,
            on_empty=self._info,
            append_export_footer=lambda footer, table: self._append_export_footer(
                footer, title=title, table=table
            ),
        )

    def _append_export_footer(self, footer: QHBoxLayout, *, title: str, table: QTableView) -> None:
        append_table_export_footer(
            self,
            footer,
            title=title,
            table=table,
            project_id=self._current_project_id(),
            category="pcap",
            source_label=self.lbl_file.text() or "",
        )

    def _open_rows_dialog(self, title: str, columns: list[tuple[str, str]], rows: list[dict[str, Any]]) -> None:
        open_dict_rows_expand_dialog(
            self,
            title=title,
            columns=columns,
            rows=rows,
            on_empty=self._info,
            append_export_footer=lambda footer, table: self._append_export_footer(
                footer, title=title, table=table
            ),
            hint_text=(
                "Click an indicator above to inspect the underlying rows. "
                "Sort columns or right-click to copy values."
            ),
        )

    def _format_pcap_time(self, value: Any) -> str:
        text = format_pcap_datetime(value)
        return text or "-"

    def _format_pcap_range(self, start: Any, end: Any) -> str:
        return f"{self._format_pcap_time(start)} - {self._format_pcap_time(end)}"

    def open_pcap_dialog(self):
        if self._pcap_queue and self._thread is None and self._batch_thread is None:
            self._load_next_queued_pcap()
            return

        controller = getattr(self.app, "dataset_controller", None)
        if controller is not None:
            controller.load_dataset_dialog()
            return

        if not self._ensure_project_workspace():
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP file",
            "",
            "Capture files (*.pcap *.pcapng);;All files (*.*)",
        )
        if file_path:
            self.load_pcap(file_path)

    def load_pcap(self, file_path: str):
        self._pcap_queue = []
        self._pcap_queue_auto_save = False
        self._pcap_queue_auto_process = False
        self._clear_day_groups()
        self._reset_batch_status()
        self._load_pcap_file(file_path)

    def load_pcap_queue(
        self,
        file_paths: list[str],
        *,
        auto_save: bool = False,
        auto_process: bool = False,
        day_groups: dict[str, list[str]] | None = None,
        period_start: str = "",
        period_end: str = "",
    ) -> None:
        paths = [str(path) for path in (file_paths or []) if str(path or "").strip()]
        if not paths:
            return

        grouped_day = False
        if day_groups:
            if auto_process:
                paths = self._store_day_groups_raw(day_groups) or paths
                grouped_day = bool(self._pcap_day_groups_raw)
                if grouped_day:
                    self._apply_imported_period_range_only(period_start, period_end)
                    self._rebuild_pcap_period_combo()
            else:
                paths = self._set_day_groups(day_groups) or paths
                grouped_day = bool(self._pcap_day_groups)
                if grouped_day:
                    self._apply_imported_period_as_default(period_start, period_end)
        else:
            self._clear_day_groups()

        if auto_process:
            self._start_auto_pcap_batch(paths, auto_save=auto_save)
            return

        self._pcap_queue = [] if grouped_day else paths[1:]
        self._pcap_queue_auto_save = bool(auto_save and not grouped_day)
        self._pcap_queue_auto_process = bool(auto_process)
        self._pcap_batch_total = len(paths)
        self._pcap_batch_processed = 0
        self._pcap_batch_failed = 0
        if grouped_day and len(paths) > 1:
            label = f"{self._format_day_label(self._pcap_active_day)} ({len(paths):,} PCAP files)"
            self._update_batch_status(label)
            self._load_pcap_files(paths, label=label)
        else:
            self._update_batch_status(Path(paths[0]).name)
            self._load_pcap_file(paths[0])

    def _thread_parent(self) -> QObject:
        return self.app if self.app is not None else self

    def _raw_daily_day_groups(self) -> dict[str, list[str]]:
        raw = {
            str(day): [str(path) for path in (paths or []) if str(path or "").strip()]
            for day, paths in (self._pcap_day_groups_raw or {}).items()
            if str(day or "").strip()
        }
        return {
            day: paths
            for day, paths in raw.items()
            if paths and normalize_period_day(day)
        }

    def _batch_analysis_day_groups(self) -> dict[str, list[str]]:
        """Per-calendar-day groups for batch analyze/save (never one merged range/month job)."""
        raw = self._raw_daily_day_groups()
        if raw:
            granularity = str(self._pcap_period_granularity or "day").strip().casefold()
            if granularity in {"range", "selected", "selected period", "selected_period"}:
                start = normalize_period_day(self._pcap_period_range_start)
                end = normalize_period_day(self._pcap_period_range_end)
                if start and end:
                    allowed = set(calendar_days_between(start, end))
                    filtered = {
                        day: paths
                        for day, paths in raw.items()
                        if normalize_period_day(day) in allowed
                    }
                    if filtered:
                        return dict(sorted(filtered.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True))
            if granularity.startswith("month"):
                month = str(self._pcap_active_day or "").strip()
                if len(month) == 7 and month[4:5] == "-":
                    filtered = {
                        day: paths
                        for day, paths in raw.items()
                        if month_key(day) == month or str(day).startswith(f"{month}-")
                    }
                    if filtered:
                        return dict(sorted(filtered.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True))
            return dict(sorted(raw.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True))

        rolled = {
            str(day): [str(path) for path in (paths or []) if str(path or "").strip()]
            for day, paths in (self._pcap_day_groups or {}).items()
        }
        daily = {
            day: paths
            for day, paths in rolled.items()
            if paths and not is_range_period_key(day) and normalize_period_day(day)
        }
        return dict(sorted(daily.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True))

    def _start_auto_pcap_batch(self, paths: list[str], *, auto_save: bool) -> None:
        if self._thread is not None or self._batch_thread is not None:
            self._info("PCAP", "PCAP analysis is already running.")
            return

        project_id = self._current_project_id()
        self._pcap_queue = []
        self._pcap_queue_auto_save = bool(auto_save)
        self._pcap_queue_auto_process = True
        batch_day_groups = self._batch_analysis_day_groups()
        if not batch_day_groups and self._pcap_day_groups_raw:
            batch_day_groups = self._raw_daily_day_groups()
        if batch_day_groups:
            self._pcap_batch_total = sum(len(day_paths) for day_paths in batch_day_groups.values())
        elif self._pcap_day_groups:
            self._pcap_batch_total = sum(len(day_paths) for day_paths in self._pcap_day_groups.values())
        else:
            self._pcap_batch_total = len(paths)
        self._pcap_batch_processed = 0
        self._pcap_batch_failed = 0
        self._pcap_batch_current_label = ""

        self.btn_open.setEnabled(False)
        self.btn_open.setText("Loading...")
        self.btn_export.setEnabled(False)
        self.btn_ai_summary.setEnabled(False)
        self.btn_save_project.setEnabled(False)
        if auto_save:
            self._sync_save_period_button(saved=True, hide=True)
        self.btn_add_notes.setEnabled(False)
        batch_total = max(int(self._pcap_batch_total or 0), len(paths))
        self.lbl_file.setText(self._active_period_title(file_count=batch_total))
        self.lbl_stats.setText("Auto analyzing PCAP batch...")
        self._set_stats_style("PcapLoadingStatus")
        self._update_batch_status()
        self._show_period_load_progress(paths, label="Auto analyzing PCAP batch...", total=batch_total)
        self._start_batch_faulthandler_watch()

        self._batch_thread = QThread(self._thread_parent())
        self._batch_worker = PcapBatchWorker(
            paths,
            project_id=project_id,
            auto_save=auto_save,
            day_groups=batch_day_groups or None,
        )
        self._batch_worker.moveToThread(self._batch_thread)
        self._batch_thread.started.connect(self._batch_worker.run)
        self._batch_worker.progress.connect(self._on_batch_progress, Qt.QueuedConnection)
        self._batch_worker.finished.connect(self._on_batch_finished, Qt.QueuedConnection)
        self._batch_worker.finished.connect(self._batch_thread.quit)
        self._batch_worker.finished.connect(self._batch_worker.deleteLater)
        self._batch_thread.finished.connect(self._cleanup_batch_thread)
        self._batch_thread.start()

    def _load_next_queued_pcap(self) -> None:
        if not self._pcap_queue:
            self._update_open_button_text()
            self._update_batch_status()
            return
        next_path = self._pcap_queue.pop(0)
        self._update_batch_status(Path(next_path).name)
        self._load_pcap_file(next_path)

    def _store_day_groups_raw(self, day_groups: dict[str, list[str]]) -> list[str]:
        cleaned = {
            str(day): [str(path) for path in paths if str(path or "").strip()]
            for day, paths in (day_groups or {}).items()
        }
        cleaned = {day: paths for day, paths in cleaned.items() if paths}
        self._pcap_day_groups_raw = dict(
            sorted(cleaned.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True)
        )
        if not self._pcap_day_groups_raw:
            self._clear_day_groups()
            return []
        self._pcap_day_groups = {}
        return [path for paths in self._pcap_day_groups_raw.values() for path in paths]

    def _apply_imported_period_range_only(self, start: str = "", end: str = "") -> None:
        from core.period_gaps import normalize_period_day

        start_day = normalize_period_day(start)
        end_day = normalize_period_day(end)
        if not start_day or not end_day:
            days = sorted(
                normalize_period_day(day)
                for day in self._pcap_day_groups_raw.keys()
                if normalize_period_day(day)
            )
            if not days:
                return
            start_day, end_day = days[0], days[-1]

        self._pcap_period_range_start = start_day
        self._pcap_period_range_end = end_day
        self._pcap_period_granularity = "range"
        if hasattr(self, "cmb_pcap_period_mode"):
            self.cmb_pcap_period_mode.blockSignals(True)
            idx = self.cmb_pcap_period_mode.findData("range")
            if idx >= 0:
                self.cmb_pcap_period_mode.setCurrentIndex(idx)
            self.cmb_pcap_period_mode.blockSignals(False)
        self._rebuild_pcap_period_combo()

    def _set_day_groups(self, day_groups: dict[str, list[str]], *, allow_empty_days: bool = False) -> list[str]:
        cleaned = {
            str(day): [str(path) for path in paths if str(path or "").strip()]
            for day, paths in (day_groups or {}).items()
        }
        if allow_empty_days:
            cleaned = {day: paths for day, paths in cleaned.items() if day}
        else:
            cleaned = {day: paths for day, paths in cleaned.items() if paths}
        self._pcap_day_groups_raw = dict(
            sorted(cleaned.items(), key=lambda pair: (pair[0] == "undated", pair[0]), reverse=True)
        )
        if not self._pcap_day_groups_raw:
            self._clear_day_groups()
            return []
        return self._rebuild_pcap_period_combo()

    def _rebuild_pcap_period_combo(self) -> list[str]:
        if not self._pcap_day_groups_raw:
            self._reset_period_selector_ui(keep_raw=False)
            return []

        previous_day = str(self._pcap_active_day or self.cmb_pcap_day.currentData() or "")
        previous_granularity = self._pcap_period_granularity
        state = PeriodSelectorState(
            granularity=self._pcap_period_granularity,
            range_start=self._pcap_period_range_start,
            range_end=self._pcap_period_range_end,
            day_groups_raw=self._pcap_day_groups_raw,
            active_key=self._pcap_active_day,
        )
        paths = rebuild_period_selector(
            state,
            kind="PCAP",
            sort_day_view=True,
            previous_key=previous_day,
        )
        if not state.day_groups:
            self._reset_period_selector_ui(keep_raw=True)
            return []

        self._pcap_period_granularity = state.granularity
        self._pcap_period_range_start = state.range_start
        self._pcap_period_range_end = state.range_end
        self._pcap_day_groups = state.day_groups
        if state.granularity != previous_granularity:
            self.cmb_pcap_period_mode.blockSignals(True)
            mode_index = self.cmb_pcap_period_mode.findData(state.granularity or "day")
            if mode_index >= 0:
                self.cmb_pcap_period_mode.setCurrentIndex(mode_index)
            self.cmb_pcap_period_mode.blockSignals(False)

        self.cmb_pcap_day.blockSignals(True)
        self.cmb_pcap_day.clear()
        for key, entry_label, _paths in build_period_combo_entries(
            state.day_groups,
            granularity=state.granularity,
            kind="PCAP",
            label_saved_empty=True,
        ):
            self.cmb_pcap_day.addItem(entry_label, key)
        if previous_day:
            index = self.cmb_pcap_day.findData(previous_day)
            if index >= 0:
                self.cmb_pcap_day.setCurrentIndex(index)
        self.cmb_pcap_day.blockSignals(False)
        self._pcap_active_day = state.active_key
        self._sync_period_selector_panel()
        self._update_reanalyze_button_state()
        self._update_period_gap_banner()
        self._sync_pcap_range_button()
        return paths

    def _apply_imported_period_as_default(self, start: str = "", end: str = "") -> None:
        from core.period_gaps import normalize_period_day

        start_day = normalize_period_day(start)
        end_day = normalize_period_day(end)
        if not start_day or not end_day:
            days = sorted(
                normalize_period_day(day)
                for day in self._pcap_day_groups_raw.keys()
                if normalize_period_day(day)
            )
            if not days:
                return
            start_day, end_day = days[0], days[-1]

        self._pcap_period_range_start = start_day
        self._pcap_period_range_end = end_day
        self._pcap_period_granularity = "range"

        if hasattr(self, "cmb_pcap_period_mode"):
            self.cmb_pcap_period_mode.blockSignals(True)
            idx = self.cmb_pcap_period_mode.findData("range")
            if idx >= 0:
                self.cmb_pcap_period_mode.setCurrentIndex(idx)
            self.cmb_pcap_period_mode.blockSignals(False)
        self._sync_pcap_range_button()
        if self._pcap_day_groups_raw:
            self._rebuild_pcap_period_combo()

    def configure_pcap_period_range(self) -> bool:
        from core.period_gaps import missing_days_in_range, normalize_period_day
        from ui.dialogs import missing_range_import_dialog, period_range_dialog

        days = sorted(
            normalize_period_day(day)
            for day in self._pcap_day_groups_raw.keys()
            if normalize_period_day(day)
        )
        if not days:
            self._info("Selected period", "No indexed PCAP days are available yet.")
            return False
        selected = period_range_dialog(
            self,
            title="Select PCAP period",
            first_day=days[0],
            last_day=days[-1],
            present_days=list(self._pcap_day_groups_raw.keys()),
        )
        if not selected:
            return False
        start, end = selected
        missing = missing_days_in_range(self._pcap_day_groups_raw.keys(), start, end)
        if missing:
            choice = missing_range_import_dialog(
                self,
                title="Missing PCAP datasets",
                missing_days=missing,
            )
            if choice == "Import missing periods…":
                if hasattr(self.app, "dataset_controller"):
                    self.app.dataset_controller.load_dataset_dialog()
                return False
            if choice != "Continue without import":
                return False
        self._pcap_period_range_start = start
        self._pcap_period_range_end = end
        self._sync_pcap_range_button()
        controller = getattr(self.app, "dataset_controller", None) if self.app else None
        if controller is not None and hasattr(controller, "_log_period_selected"):
            controller._log_period_selected("PCAP", start, end)
        if self._pcap_period_granularity == "range" and self._pcap_day_groups_raw:
            self._rebuild_pcap_period_combo()
            self.load_active_period(prefer_saved=True)
        return True

    def _sync_pcap_range_button(self) -> None:
        if not hasattr(self, "btn_pcap_pick_range"):
            return
        visible = self._pcap_period_granularity == "range" and bool(self._pcap_day_groups_raw)
        self.btn_pcap_pick_range.setVisible(visible)

    def _on_pcap_period_mode_changed(self, index: int) -> None:
        if index < 0:
            return
        mode = str(self.cmb_pcap_period_mode.itemData(index) or "day")
        if mode == self._pcap_period_granularity:
            return
        if mode == "month":
            if not month_view_available(self._pcap_day_groups_raw.keys()):
                self.cmb_pcap_period_mode.blockSignals(True)
                revert_index = self.cmb_pcap_period_mode.findData(self._pcap_period_granularity or "day")
                if revert_index >= 0:
                    self.cmb_pcap_period_mode.setCurrentIndex(revert_index)
                self.cmb_pcap_period_mode.blockSignals(False)
                self._info(
                    "Month view unavailable",
                    "Month view requires a complete calendar month (every day indexed).",
                    "Use Day view for partial imports.",
                )
                return
        if mode == "range":
            if not self.configure_pcap_period_range():
                self.cmb_pcap_period_mode.blockSignals(True)
                revert_index = self.cmb_pcap_period_mode.findData(self._pcap_period_granularity or "day")
                if revert_index >= 0:
                    self.cmb_pcap_period_mode.setCurrentIndex(revert_index)
                self.cmb_pcap_period_mode.blockSignals(False)
                return
        elif self._pcap_period_granularity == "range":
            self._pcap_period_range_start = ""
            self._pcap_period_range_end = ""
        if self._thread is not None or self._batch_thread is not None:
            self.cmb_pcap_period_mode.blockSignals(True)
            revert_index = self.cmb_pcap_period_mode.findData(self._pcap_period_granularity or "day")
            if revert_index >= 0:
                self.cmb_pcap_period_mode.setCurrentIndex(revert_index)
            self.cmb_pcap_period_mode.blockSignals(False)
            return
        self._pcap_period_granularity = mode
        self._sync_pcap_range_button()
        if not self._pcap_day_groups_raw:
            return
        self._rebuild_pcap_period_combo()
        self.load_active_period(prefer_saved=True)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        project_id = self._current_project_id()
        if project_id is None:
            return
        if self._pcap_day_groups_raw or self._thread is not None or self._batch_thread is not None:
            return
        controller = getattr(self.app, "dataset_controller", None)
        if controller is not None:
            controller.sync_pcap_periods_from_project(project_id)

    def _sync_period_selector_panel(self) -> None:
        has_periods = bool(self._pcap_day_groups_raw or self._pcap_day_groups)
        batch_total = int(getattr(self, "_pcap_batch_total", 0) or 0)
        batch_processed = int(getattr(self, "_pcap_batch_processed", 0) or 0)
        queue = list(getattr(self, "_pcap_queue", None) or [])
        has_batch = bool(queue) or (
            batch_total > 0 and (batch_processed < batch_total or self._batch_thread is not None)
        )
        if hasattr(self, "lbl_pcap_day"):
            self.lbl_pcap_day.setVisible(has_periods)
        if hasattr(self, "cmb_pcap_period_mode"):
            self.cmb_pcap_period_mode.setVisible(has_periods)
        if hasattr(self, "cmb_pcap_day"):
            self.cmb_pcap_day.setVisible(has_periods)
        if hasattr(self, "btn_pcap_pick_range"):
            self.btn_pcap_pick_range.setVisible(has_periods and self._pcap_period_granularity == "range")
        if hasattr(self, "btn_reanalyze_period"):
            self.btn_reanalyze_period.setVisible(has_periods)
        if hasattr(self, "pcap_period_row"):
            self.pcap_period_row.setVisible(has_periods)
        if hasattr(self, "batch_status_panel"):
            self.batch_status_panel.setVisible(has_batch)

    def load_active_period(self, *, prefer_saved: bool = False) -> None:
        if not self._pcap_day_groups:
            return
        if self._thread is not None or self._batch_thread is not None:
            return
        day = str(self._pcap_active_day or self.cmb_pcap_day.currentData() or "")
        if not day:
            return
        if prefer_saved and self._try_load_saved_pcap_period(day):
            return
        paths = list(self._pcap_day_groups.get(day, []))
        if paths:
            self._load_pcap_files(paths, label=f"{self._format_day_label(day)} ({len(paths):,} PCAP files)")
        elif prefer_saved:
            self._try_load_saved_pcap_period(day)

    def refresh_current_view(self) -> None:
        if self._thread is not None or self._batch_thread is not None:
            return
        if self.summary:
            self._render_loaded_summary(self.summary)
            return
        day = str(self._pcap_active_day or self.cmb_pcap_day.currentData() or "")
        if day:
            self._try_load_saved_pcap_period(day)

    def clear_project_view(self) -> None:
        """Reset PCAP page when project/dataset context is cleared."""
        if self._batch_worker is not None:
            self._batch_worker.request_stop()
        self._pcap_queue = []
        self._pcap_queue_auto_save = False
        self._pcap_queue_auto_process = False
        self.summary = None
        self._saved_source_id = None
        self._service_chart_full_rows = []
        self._activity_chart_full_rows = []
        self._all_artifacts = []
        self._batch_finish_guard = False
        self._clear_day_groups()
        self._reset_batch_status()

        if hasattr(self, "lbl_file"):
            self.lbl_file.setText("No PCAP loaded")
        if hasattr(self, "lbl_stats"):
            self._set_stats_style("HeaderStatLabel")
            self.lbl_stats.setText("")
        if hasattr(self, "lbl_load_progress"):
            self.lbl_load_progress.clear()
            self.lbl_load_progress.hide()
        if hasattr(self, "load_progress"):
            self.load_progress.hide()
            self.load_progress.setValue(0)
        if hasattr(self, "lbl_period_gaps"):
            self.lbl_period_gaps.clear()
        if hasattr(self, "lbl_limit_notice"):
            self.lbl_limit_notice.hide()
            self.lbl_limit_notice.clear()
        if hasattr(self, "btn_expand_period_gaps"):
            self.btn_expand_period_gaps.setVisible(False)
        if hasattr(self, "btn_reanalyze_period"):
            self.btn_reanalyze_period.setVisible(False)
        if hasattr(self, "pcap_period_row"):
            self.pcap_period_row.setVisible(False)
        if hasattr(self, "batch_status_panel"):
            self.batch_status_panel.setVisible(False)
        if hasattr(self, "lbl_batch_status"):
            self.lbl_batch_status.clear()

        empty_chart = "Open a PCAP file to show visible service groups."
        empty_activity = "Open a PCAP file to show hourly packet activity."
        if hasattr(self, "chart_services"):
            self.chart_services.set_rows([], empty_text=empty_chart)
        if hasattr(self, "chart_activity"):
            self.chart_activity.set_rows([], empty_text=empty_activity)
        if hasattr(self, "btn_expand_chart_services"):
            self.btn_expand_chart_services.setEnabled(False)
        if hasattr(self, "btn_expand_chart_activity"):
            self.btn_expand_chart_activity.setEnabled(False)

        self._set_investigator_text({"plain_summary": "Open a PCAP file to see a plain-language investigation view."})
        if hasattr(self, "lbl_highlights_brief"):
            self.lbl_highlights_brief.setText("Open a PCAP file to see communication highlights.")
        if hasattr(self, "lbl_overview_text"):
            self.lbl_overview_text.setText("Open a PCAP file to see a readable investigation overview.")
        if hasattr(self, "lbl_communication_count"):
            self.lbl_communication_count.setText("0 indicators")
        if hasattr(self, "lbl_communication_breakdown"):
            self.lbl_communication_breakdown.setText("Messaging/push: 0 | Possible call/media: 0 | Services: 0")
        if hasattr(self, "lbl_network_overview_count"):
            self.lbl_network_overview_count.setText("0 rows")
        if hasattr(self, "lbl_network_overview_breakdown"):
            self.lbl_network_overview_breakdown.setText("")
        if hasattr(self, "lbl_visible_metadata_count"):
            self.lbl_visible_metadata_count.setText("0 rows")
        if hasattr(self, "lbl_visible_metadata_breakdown"):
            self.lbl_visible_metadata_breakdown.setText("")
        if hasattr(self, "lbl_samples_count"):
            self.lbl_samples_count.setText("0 readable rows")
        if hasattr(self, "lbl_connections_count"):
            self.lbl_connections_count.setText("0 rows")
        if hasattr(self, "lbl_connections_breakdown"):
            self.lbl_connections_breakdown.setText("")

        for table_name in (
            "tbl_communications",
            "tbl_network_overview",
            "tbl_visible_metadata",
            "tbl_samples",
            "tbl_connections",
        ):
            table = getattr(self, table_name, None)
            if table is not None:
                self._set_table(table, [])
        if hasattr(self, "txt_communication_detail"):
            self.txt_communication_detail.clear()
        if hasattr(self, "txt_pcap_ai_summary"):
            self.txt_pcap_ai_summary.clear()

        self._set_visibility_indicators([], empty_text="Open a PCAP file to show readable vs encrypted indicators.")
        self._set_artifact_tables([])

        for button, enabled in (
            (getattr(self, "btn_open", None), True),
            (getattr(self, "btn_save_project", None), False),
            (getattr(self, "btn_export", None), False),
            (getattr(self, "btn_ai_summary", None), False),
            (getattr(self, "btn_add_notes", None), False),
            (getattr(self, "btn_export_full_dns", None), False),
            (getattr(self, "btn_export_full_tls", None), False),
        ):
            if button is not None:
                button.setEnabled(enabled)
        if hasattr(self, "btn_save_project"):
            self.btn_save_project.setText("Save Period to Project")
        if hasattr(self, "btn_ai_summary"):
            self.btn_ai_summary.setText("AI Summary")
        self._update_open_button_text()
        self._sync_save_period_button(saved=False, hide=False)
        self._sync_period_selector_panel()
        self._update_reanalyze_button_state()

    def _try_load_saved_pcap_period(self, day: str) -> bool:
        project_id = self._current_project_id()
        if project_id is None or not day:
            return False

        source = get_saved_pcap_period_source(project_id, day)
        if source is None:
            return False

        self._render_saved_period_source(source, day)
        return True

    def _render_saved_period_source(self, source, day: str) -> None:
        self.summary = None
        self._saved_source_id = int(source.id or 0) or None
        self._pcap_active_day = day
        title = str(source.file_name or source.file_path or self._format_day_label(day))
        self.lbl_file.setText(title)
        self._set_stats_style("HeaderStatLabel")
        self.lbl_stats.setText(
            f"{source.format or 'Saved period'} | Packets: {int(source.packet_count or 0):,} | "
            f"Volume: {human_bytes(int(source.wire_bytes or 0), precision=2)} | "
            f"Period: {self._format_pcap_range(source.first_seen, source.last_seen)} | "
            "Loaded from project save — use Re-analyze Period for full communications view."
        )
        plain = str(source.summary_text or "").strip() or "Saved PCAP period is available in the project profile."
        self._set_investigator_text({"plain_summary": plain})
        empty_saved = "Open Re-analyze Period to rebuild full tables from source PCAP files."
        self.lbl_highlights_brief.setText("Saved PCAP period loaded from project profile.")
        self.lbl_communication_count.setText("Saved summary")
        self.lbl_communication_breakdown.setText(empty_saved)
        self._set_table(self.tbl_communications, [])
        self.txt_communication_detail.clear()
        self.chart_services.set_rows([], empty_text=empty_saved)
        self.chart_activity.set_rows([], empty_text=empty_saved)
        self._service_chart_full_rows = []
        self._activity_chart_full_rows = []
        if hasattr(self, "btn_expand_chart_services"):
            self.btn_expand_chart_services.setEnabled(False)
        if hasattr(self, "btn_expand_chart_activity"):
            self.btn_expand_chart_activity.setEnabled(False)
        self._set_visibility_indicators([], empty_text=empty_saved)
        self.lbl_overview_text.setText(
            f"Saved PCAP period for {self._format_day_label(day)}.\n"
            f"Device IP: {source.likely_device_ip or '-'}\n"
            f"Packets: {int(source.packet_count or 0):,}\n"
            f"Volume: {human_bytes(int(source.wire_bytes or 0), precision=2)}"
        )
        self._set_table(self.tbl_network_overview, [])
        self.lbl_network_overview_count.setText("Saved period")
        self.lbl_network_overview_breakdown.setText(empty_saved)
        self._set_table(self.tbl_visible_metadata, [])
        self.lbl_visible_metadata_count.setText("Saved period")
        self.lbl_visible_metadata_breakdown.setText(empty_saved)
        self._set_table(self.tbl_samples, [])
        self.lbl_samples_count.setText("0 readable rows")
        self._set_table(self.tbl_connections, [])
        self.lbl_connections_count.setText("Saved period")
        self.lbl_connections_breakdown.setText(
            f"Device IP: {source.likely_device_ip or '-'} | Packets: {int(source.packet_count or 0):,}"
        )
        self._set_artifact_tables([])
        self.btn_export.setEnabled(False)
        if hasattr(self, "btn_export_full_dns"):
            self.btn_export_full_dns.setEnabled(False)
        if hasattr(self, "btn_export_full_tls"):
            self.btn_export_full_tls.setEnabled(False)
        self.btn_save_project.setText("Saved to Project")
        self.btn_save_project.setEnabled(False)
        self._sync_save_period_button(saved=True)
        self.btn_ai_summary.setEnabled(bool(plain))
        self.btn_add_notes.setEnabled(bool(plain))
        self._sync_period_selector_panel()
        self._update_reanalyze_button_state()

    def _clear_day_groups(self) -> None:
        self._reset_period_selector_ui(keep_raw=False)

    def _reset_period_selector_ui(self, *, keep_raw: bool = False) -> None:
        if not keep_raw:
            self._pcap_day_groups_raw = {}
        self._pcap_day_groups = {}
        if keep_raw:
            self._pcap_active_day = ""
        else:
            self._pcap_active_day = ""
        if hasattr(self, "cmb_pcap_day"):
            self.cmb_pcap_day.blockSignals(True)
            self.cmb_pcap_day.clear()
            self.cmb_pcap_day.blockSignals(False)
        if not keep_raw and hasattr(self, "cmb_pcap_period_mode"):
            self.cmb_pcap_period_mode.blockSignals(True)
            self.cmb_pcap_period_mode.setCurrentIndex(0)
            self.cmb_pcap_period_mode.blockSignals(False)
            self._pcap_period_granularity = "day"
        self._sync_period_selector_panel()
        if hasattr(self, "btn_reanalyze_period"):
            self.btn_reanalyze_period.setEnabled(bool(self._pcap_day_groups))
        self._update_period_gap_banner(list(self._pcap_day_groups_raw.keys()) if keep_raw else [])

    def _on_pcap_day_changed(self, index: int) -> None:
        if index < 0 or not self._pcap_day_groups:
            return
        if self._thread is not None or self._batch_thread is not None:
            return
        day = str(self.cmb_pcap_day.itemData(index) or "")
        if not day:
            return
        self._pcap_active_day = day
        self._pcap_queue = []
        paths = list(self._pcap_day_groups.get(day, []))
        if self._try_load_saved_pcap_period(day):
            return
        if not paths:
            self.lbl_stats.setText(f"No source PCAP files remain for {self._format_day_label(day)}.")
            return
        self._pcap_batch_total = len(paths)
        self._pcap_batch_processed = 0
        self._pcap_batch_failed = 0
        self._update_batch_status(f"{self._format_day_label(day)} aggregate")
        self._load_pcap_files(paths, label=f"{self._format_day_label(day)} ({len(paths):,} PCAP files)")

    def _format_day_label(self, day: str) -> str:
        return format_period_day_label(day)

    def _active_period_file_count(self, *, fallback: int = 0) -> int:
        day = str(self._pcap_active_day or self.cmb_pcap_day.currentData() or "")
        if day:
            count = len(self._pcap_day_groups.get(day, []) or [])
            if count:
                return count
        batch_total = int(self._pcap_batch_total or 0)
        if batch_total:
            return batch_total
        return max(0, int(fallback or 0))

    def _active_period_title(self, *, file_count: int | None = None) -> str:
        day = str(self._pcap_active_day or self.cmb_pcap_day.currentData() or "")
        count = self._active_period_file_count(fallback=int(file_count or 0)) if file_count is None else max(0, int(file_count))
        if day:
            return period_group_label(
                day,
                granularity=self._pcap_period_granularity or "day",
                file_count=max(1, count),
                kind="PCAP",
            )
        if count > 1:
            return f"{count:,} PCAP files"
        if count == 1:
            return "1 PCAP file"
        return "No PCAP loaded"

    def _hide_individual_pcap_names(self, *, file_count: int | None = None) -> bool:
        count = self._active_period_file_count(fallback=int(file_count or 0)) if file_count is None else int(file_count or 0)
        if count > 1:
            return True
        if self._pcap_period_granularity in {"month", "range"}:
            return count > 0 or int(self._pcap_batch_total or 0) > 1
        return int(self._pcap_batch_total or 0) > 1

    def _load_pcap_file(self, file_path: str):
        self._load_pcap_files([file_path], label="")

    def _close_period_load_progress(self) -> None:
        if hasattr(self, "load_progress"):
            self.load_progress.hide()
            self.load_progress.setRange(0, 100)
            self.load_progress.setValue(0)
        if hasattr(self, "lbl_load_progress"):
            self.lbl_load_progress.hide()
            self.lbl_load_progress.clear()
        self._period_load_progress = None
        self._sync_period_gap_visibility()

    def _show_period_load_progress(self, paths: list[str], *, label: str = "", total: int = 0) -> None:
        if not hasattr(self, "load_progress"):
            return
        text = label or f"Loading {len(paths):,} PCAP files for selected period..."
        bar = self.load_progress
        if total > 1:
            bar.setRange(0, max(1, total))
            bar.setValue(0)
            progress_text = f"0 / {total}"
        else:
            bar.setRange(0, 0)
            progress_text = text
        if hasattr(self, "lbl_load_progress"):
            self.lbl_load_progress.setText(progress_text)
            self.lbl_load_progress.show()
        bar.show()
        self._period_load_progress = bar
        self._sync_period_gap_visibility()

    def _update_period_load_progress(self, current: int, total: int, label: str = "", *, current_file: str = "") -> None:
        bar = getattr(self, "load_progress", None)
        if bar is None or bar.isHidden():
            return
        if total > 0:
            bar.setRange(0, max(1, total))
            bar.setValue(max(0, min(current, total)))
            progress_text = f"{current} / {total}"
            file_name = Path(str(current_file or "")).name if current_file else ""
            if file_name:
                progress_text = f"{progress_text} — {file_name}"
        elif label:
            progress_text = str(label)
        else:
            progress_text = ""
        if progress_text and hasattr(self, "lbl_load_progress"):
            self.lbl_load_progress.setText(progress_text)
            self.lbl_load_progress.show()

    def _load_pcap_files(self, file_paths: list[str], *, label: str = ""):
        if not self._ensure_project_workspace():
            return

        if self._thread is not None:
            self._info("PCAP", "PCAP analysis is already running.")
            return
        paths = [str(path) for path in file_paths if str(path or "").strip()]
        if not paths:
            return

        self.btn_open.setEnabled(False)
        self.btn_open.setText("Loading...")
        self.btn_export.setEnabled(False)
        self.btn_ai_summary.setEnabled(False)
        if hasattr(self, "btn_export_full_dns"):
            self.btn_export_full_dns.setEnabled(False)
        if hasattr(self, "btn_export_full_tls"):
            self.btn_export_full_tls.setEnabled(False)
        if hasattr(self, "btn_reanalyze_period"):
            self.btn_reanalyze_period.setEnabled(False)
        self.txt_pcap_ai_summary.clear()
        if len(paths) == 1:
            self.lbl_file.setText(paths[0])
            current_text = Path(paths[0]).name
        else:
            current_text = label or f"{len(paths):,} PCAP files"
            self.lbl_file.setText(self._active_period_title(file_count=len(paths)))
        self.lbl_stats.setText(
            "Analyzing capture..."
            if len(paths) == 1
            else f"Analyzing {len(paths):,} PCAP files for selected period..."
        )
        self._set_stats_style("PcapLoadingStatus")
        self._update_batch_status(current_text)
        show_bar = len(paths) > 1 or self._pcap_period_granularity in {"month", "range"}
        if show_bar:
            self._show_period_load_progress(paths, label=label or current_text)

        self._thread = QThread(self._thread_parent())
        worker_path: str | list[str] = paths[0] if len(paths) == 1 else paths
        self._worker = PcapWorker(worker_path, label=label)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_loaded, Qt.QueuedConnection)
        self._worker.error.connect(self._on_error, Qt.QueuedConnection)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.error.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._cleanup_thread)
        self._start_batch_faulthandler_watch()
        self._thread.start()

    def _on_loaded(self, summary: PcapSummary):
        self._close_period_load_progress()
        self._render_loaded_summary(summary)
        if self._pcap_queue_auto_save:
            saved = self._save_current_to_project(show_dialog=False, check_device=False, refresh_ui=False)
            self._mark_current_ingest("done" if saved else "failed", "" if saved else "Auto-save failed.")
            if saved:
                self._sync_save_period_button(saved=True, hide=True)
        source_count = len(getattr(summary, "source_paths", None) or [])
        if source_count > 1 and self._pcap_batch_total == source_count:
            self._pcap_batch_processed = self._pcap_batch_total
        else:
            self._pcap_batch_processed += 1
        self._update_batch_status()

    def _render_loaded_summary(self, summary: PcapSummary) -> None:
        self.summary = summary
        self._saved_source_id = None
        self.btn_export.setEnabled(True)
        if hasattr(self, "btn_export_full_dns"):
            self.btn_export_full_dns.setEnabled(True)
        if hasattr(self, "btn_export_full_tls"):
            self.btn_export_full_tls.setEnabled(True)
        source_count = len(getattr(summary, "source_paths", None) or [])
        already_saved = self._current_period_already_saved()
        if already_saved:
            self._sync_save_period_button(saved=True)
        else:
            self.btn_save_project.setEnabled(True)
            self.btn_save_project.setText("Save Period to Project")
            if not self._pcap_queue_auto_save:
                self._sync_save_period_button(visible=True)
            if source_count > 1:
                self.btn_save_project.setToolTip(
                    "Save this daily aggregate to the project profile. The source files remain indexed individually."
                )
            else:
                self.btn_save_project.setToolTip("")
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Summary")
        self.btn_add_notes.setEnabled(True)
        if source_count > 1 or self._hide_individual_pcap_names(file_count=source_count):
            self.lbl_file.setText(self._active_period_title(file_count=source_count))
        else:
            self.lbl_file.setText(summary.file_path or summary.file_name or "PCAP loaded")
        self._set_stats_style("HeaderStatLabel")
        self.lbl_stats.setText(
            f"{summary.format} | Packets: {summary.packet_count:,} | "
            f"Volume: {human_bytes(summary.wire_bytes, precision=2)} | "
            f"Period: {self._format_pcap_range(summary.first_seen, summary.last_seen)}"
        )
        if self._pcap_queue:
            self.lbl_stats.setText(
                self.lbl_stats.text()
                + f" | Folder queue: {len(self._pcap_queue)} more"
                + (" | auto-batch" if self._pcap_queue_auto_process else "")
            )
        investigator = build_investigator_view(summary)
        self._set_highlights(summary)
        self._set_investigator_text(investigator)
        self._update_limit_notice(summary)
        self._apply_investigator_charts(investigator)
        self._set_visibility_indicators(
            investigator.get("visibility_rows") or [],
            empty_text="No visibility indicators are available.",
        )
        self.lbl_overview_text.setText(self._overview_text(summary))
        self._set_network_overview_table(summary)
        self._set_evidence_tables(summary)
        self._set_artifact_tables(summary.artifacts)
        self._set_connections_table(summary)
        self._sync_period_selector_to_summary(summary)
        self._update_reanalyze_button_state()

    def _update_reanalyze_button_state(self) -> None:
        if not hasattr(self, "btn_reanalyze_period"):
            return
        busy = self._thread is not None or self._batch_thread is not None
        day = str(self._pcap_active_day or self.cmb_pcap_day.currentData() or "")
        has_day_paths = bool(self._pcap_day_groups.get(day, [])) if day else bool(self._pcap_day_groups)
        has_summary = bool(getattr(self, "summary", None))
        self.btn_reanalyze_period.setEnabled(not busy and (has_day_paths or has_summary))

    def reanalyze_current_period(self) -> None:
        if self._thread is not None or self._batch_thread is not None:
            self._info("PCAP", "PCAP analysis is already running.")
            return

        day = str(self._pcap_active_day or self.cmb_pcap_day.currentData() or "")
        paths = list(self._pcap_day_groups.get(day, []))
        if not paths and getattr(self, "summary", None):
            paths = list(getattr(self.summary, "source_paths", None) or [])
        if not paths and getattr(self, "summary", None) and self.summary.file_path:
            paths = [self.summary.file_path]

        if not paths:
            self._info("PCAP", "No PCAP period is loaded to re-analyze.")
            return

        label = ""
        if day:
            label = f"{self._format_day_label(day)} ({len(paths):,} PCAP files)"
        elif len(paths) > 1:
            label = f"{len(paths):,} PCAP files"
        if len(paths) == 1:
            self._load_pcap_files(paths, label=label)
        else:
            self._start_period_reanalyze(paths, day=day, label=label)

    def _start_period_reanalyze(self, paths: list[str], *, day: str = "", label: str = "") -> None:
        if self._thread is not None or self._batch_thread is not None:
            self._info("PCAP", "PCAP analysis is already running.")
            return

        clean_paths = [str(path) for path in paths if str(path or "").strip()]
        if not clean_paths:
            return

        self._pcap_queue = []
        self._pcap_queue_auto_save = False
        self._pcap_queue_auto_process = False
        self._pcap_batch_total = len(clean_paths)
        self._pcap_batch_processed = 0
        self._pcap_batch_failed = 0
        self._pcap_batch_current_label = ""

        self.btn_open.setEnabled(False)
        self.btn_open.setText("Loading...")
        self.btn_export.setEnabled(False)
        self.btn_ai_summary.setEnabled(False)
        if hasattr(self, "btn_export_full_dns"):
            self.btn_export_full_dns.setEnabled(False)
        if hasattr(self, "btn_export_full_tls"):
            self.btn_export_full_tls.setEnabled(False)
        if hasattr(self, "btn_reanalyze_period"):
            self.btn_reanalyze_period.setEnabled(False)
        self.btn_save_project.setEnabled(False)
        self.btn_add_notes.setEnabled(False)
        self.txt_pcap_ai_summary.clear()

        period_label = label or f"{len(clean_paths):,} PCAP files"
        self.lbl_file.setText(self._active_period_title(file_count=len(clean_paths)))
        self.lbl_stats.setText(f"Analyzing {len(clean_paths):,} PCAP files for selected period...")
        self._set_stats_style("PcapLoadingStatus")
        self._update_batch_status()
        self._show_period_load_progress(
            clean_paths,
            label=period_label,
            total=len(clean_paths),
        )
        self._start_batch_faulthandler_watch()

        day_groups = {day: clean_paths} if day else None
        self._batch_thread = QThread(self._thread_parent())
        self._batch_worker = PcapBatchWorker(
            clean_paths,
            project_id=None,
            auto_save=False,
            day_groups=day_groups,
        )
        self._batch_worker.moveToThread(self._batch_thread)
        self._batch_thread.started.connect(self._batch_worker.run)
        self._batch_worker.progress.connect(self._on_batch_progress, Qt.QueuedConnection)
        self._batch_worker.finished.connect(self._on_batch_finished, Qt.QueuedConnection)
        self._batch_worker.finished.connect(self._batch_thread.quit)
        self._batch_worker.finished.connect(self._batch_worker.deleteLater)
        self._batch_thread.finished.connect(self._cleanup_batch_thread)
        self._batch_thread.start()

    def _export_full_metadata(self, kind: str) -> None:
        if not getattr(self, "summary", None):
            self._info("PCAP export", "Open a PCAP file first.")
            return

        project = get_project(self._current_project_id()) if self._current_project_id() is not None else None
        default_name = f"pcap_{kind}_full_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        default_path = (
            str(workspace_export_path(project.base_folder, default_name, category="pcap"))
            if project and project.base_folder
            else default_name
        )

        file_path, _selected = QFileDialog.getSaveFileName(
            self,
            f"Export full {kind.upper()} metadata",
            default_path,
            "CSV files (*.csv)",
        )
        if not file_path:
            return

        try:
            if kind == "dns":
                row_count = export_pcap_dns_csv(file_path, self.summary)
                label = "DNS queries"
            elif kind == "tls":
                row_count = export_pcap_tls_csv(file_path, self.summary)
                label = "TLS SNI hosts"
            else:
                raise ValueError(f"Unsupported metadata export: {kind}")
            self._info(
                "PCAP export",
                f"Exported {row_count:,} {label}.",
                f"File:\n{file_path}",
            )
        except Exception as exc:
            self._error("PCAP export failed", str(exc))

    def _sync_period_selector_to_summary(self, summary: PcapSummary) -> None:
        if not self._pcap_day_groups or not hasattr(self, "cmb_pcap_day"):
            return
        day = resolve_period_day(
            file_paths=list(getattr(summary, "source_paths", None) or []),
            first_seen=summary.first_seen,
            last_seen=summary.last_seen,
        )
        if not day or day not in self._pcap_day_groups:
            return
        index = self.cmb_pcap_day.findData(day)
        if index < 0:
            return
        if self.cmb_pcap_day.currentIndex() == index and self._pcap_active_day == day:
            return
        self.cmb_pcap_day.blockSignals(True)
        self.cmb_pcap_day.setCurrentIndex(index)
        self.cmb_pcap_day.blockSignals(False)
        self._pcap_active_day = day
        if not self.summary:
            return
        summary = self.summary
        investigator = build_investigator_view(summary)
        self._set_highlights(summary)
        self._set_investigator_text(investigator)
        self._update_limit_notice(summary)
        self._apply_investigator_charts(investigator)
        self._set_visibility_indicators(
            investigator.get("visibility_rows") or [],
            empty_text="No visibility indicators are available.",
        )
        self.lbl_overview_text.setText(self._overview_text(summary))
        self._set_network_overview_table(summary)
        self._set_evidence_tables(summary)
        self._set_artifact_tables(summary.artifacts)
        self._set_connections_table(summary)

    def _apply_investigator_charts(self, investigator: dict[str, Any]) -> None:
        service_rows = self._service_chart_rows(investigator.get("service_rows") or [])
        activity_source = sorted(
            list(investigator.get("activity_rows") or []),
            key=lambda row: int(row.get("packets") or 0),
            reverse=True,
        )
        activity_rows = self._activity_chart_rows(activity_source)
        self._service_chart_full_rows = list(service_rows)
        self._activity_chart_full_rows = list(activity_rows)
        self.chart_services.set_rows(
            service_rows,
            empty_text="No visible service groups were identified.",
        )
        self.chart_activity.set_rows(
            activity_rows,
            empty_text="No hourly activity is available.",
        )
        preview = PROFILE_CHART_PREVIEW_ROWS
        service_total = len(service_rows)
        activity_total = len(activity_rows)
        self.btn_expand_chart_services.setEnabled(service_total > preview)
        self.btn_expand_chart_activity.setEnabled(activity_total > preview)
        if service_total > preview:
            self.btn_expand_chart_services.setToolTip(f"{service_total:,} service groups — chart shows top {preview}.")
        else:
            self.btn_expand_chart_services.setToolTip("")
        if activity_total > preview:
            self.btn_expand_chart_activity.setToolTip(f"{activity_total:,} buckets — chart shows top {preview} by packets.")
        else:
            self.btn_expand_chart_activity.setToolTip("")

    def _expand_service_chart(self) -> None:
        rows = [
            {
                "label": row.get("label"),
                "count": row.get("count"),
                "value": row.get("value"),
                "tooltip": row.get("tooltip"),
            }
            for row in self._service_chart_full_rows
        ]
        self._open_rows_dialog(
            "Visible service groups",
            [("label", "Service"), ("count", "Packets"), ("value", "Share"), ("tooltip", "Example")],
            rows,
        )

    def _expand_activity_chart(self) -> None:
        rows = [
            {
                "label": row.get("label"),
                "count": row.get("count"),
                "value": row.get("value"),
            }
            for row in self._activity_chart_full_rows
        ]
        self._open_rows_dialog(
            "Hourly activity (peak hours)",
            [("label", "Hour"), ("count", "Packets"), ("value", "Share")],
            rows,
        )

    def _service_chart_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        chart_rows = []
        for row in rows or []:
            count = int(row.get("count") or 0)
            share = row.get("share")
            try:
                share_text = f"{float(share):.1f}%"
            except Exception:
                share_text = str(share or "-")
            label = str(row.get("service") or "-")
            example = str(row.get("example") or "").strip()
            chart_rows.append({
                "label": label,
                "tooltip": f"{label} - {example}" if example else label,
                "count": count,
                "value": f"{count} / {share_text}",
            })
        return chart_rows

    def _activity_chart_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        chart_rows = []
        for row in rows or []:
            packets = int(row.get("packets") or 0)
            share = row.get("share")
            try:
                share_text = f"{float(share):.1f}%"
            except Exception:
                share_text = str(share or "-")
            chart_rows.append({
                "label": str(row.get("hour") or "-"),
                "count": packets,
                "value": f"{packets:,} / {share_text}",
            })
        return chart_rows

    def _visibility_kind(self, label: str) -> str:
        text = str(label or "").strip().lower()
        if text.startswith("encrypted"):
            return "encrypted"
        if "dns" in text:
            return "dns"
        if "http" in text:
            return "http"
        return "other"

    def _set_visibility_indicators(self, rows: list[dict[str, Any]] | None, *, empty_text: str = "") -> None:
        while self.visibility_rows_layout.count():
            item = self.visibility_rows_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
            nested = item.layout()
            if nested is not None:
                while nested.count():
                    nested_item = nested.takeAt(0)
                    nested_widget = nested_item.widget()
                    if nested_widget is not None:
                        nested_widget.deleteLater()

        if not rows:
            self.lbl_visibility_empty.setText(
                empty_text or "Open a PCAP file to show readable vs encrypted indicators."
            )
            self.lbl_visibility_empty.show()
            return

        self.lbl_visibility_empty.hide()
        for row in rows:
            label = str(row.get("label") or "-")
            count = int(row.get("count") or 0)
            share = row.get("share")
            try:
                share_text = f"{float(share):.1f}%"
            except Exception:
                share_text = str(share or "-")
            kind = self._visibility_kind(label)
            value = f"{count:,} ({share_text})"
            self.visibility_rows_layout.addWidget(
                VisibilityIndicatorRow(label, value, kind, self._open_visibility_data)
            )

    def _open_visibility_data(self, kind: str) -> None:
        summary = getattr(self, "summary", None)
        if summary is None:
            self._info("PCAP", "Open a PCAP file first.")
            return

        if kind == "encrypted":
            self._open_table_dialog("Communication indicators", self.tbl_communications)
            return

        if kind == "dns":
            rows = [
                row
                for row in self._visible_metadata_rows(summary)
                if "dns" in str(row.get("type") or "").lower()
            ]
            self._open_rows_dialog(
                "DNS metadata",
                [("type", "Type"), ("value", "Visible Value"), ("count", "Count")],
                rows,
            )
            return

        sample_columns = [
            ("time", "Time"),
            ("type", "Type"),
            ("source", "Source"),
            ("destination", "Destination"),
            ("value", "Visible Value"),
        ]
        if kind == "http":
            rows = [
                row for row in (summary.readable_samples or [])
                if str(row.get("type") or "") == "HTTP cleartext"
            ]
            self._open_rows_dialog("HTTP cleartext samples", sample_columns, rows)
            return

        rows = [
            row for row in (summary.readable_samples or [])
            if str(row.get("type") or "") != "HTTP cleartext"
        ]
        self._open_rows_dialog("Other readable samples", sample_columns, rows)

    def _visibility_chart_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        chart_rows = []
        for row in rows or []:
            count = int(row.get("count") or 0)
            share = row.get("share")
            try:
                share_text = f"{float(share):.1f}%"
            except Exception:
                share_text = str(share or "-")
            chart_rows.append({
                "label": str(row.get("label") or "-"),
                "count": count,
                "value": f"{count:,} ({share_text})",
            })
        return chart_rows

    def _visible_metadata_rows(self, summary: PcapSummary) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []

        def _append_from_counts(counts: dict[str, int] | None, *, row_type: str, key: str) -> None:
            if not counts:
                return
            for name, count in sorted(counts.items(), key=lambda item: (-item[1], item[0].lower())):
                if str(name).strip():
                    rows.append({"type": row_type, "value": name, "count": count})

        dns_items = summary.dns_queries or []
        if dns_items:
            for item in dns_items:
                rows.append({"type": "DNS query", "value": item.get("query"), "count": item.get("count")})
        else:
            _append_from_counts(summary.dns_query_counts, row_type="DNS query", key="query")

        tls_items = summary.tls_sni or []
        if tls_items:
            for item in tls_items:
                rows.append({"type": "TLS SNI", "value": item.get("host"), "count": item.get("count")})
        else:
            _append_from_counts(summary.tls_sni_counts, row_type="TLS SNI", key="host")

        http_items = summary.http_hosts or []
        if http_items:
            for item in http_items:
                rows.append({"type": "HTTP host", "value": item.get("host"), "count": item.get("count")})
        else:
            _append_from_counts(summary.http_host_counts, row_type="HTTP host", key="host")
        return rows

    def _set_evidence_tables(self, summary: PcapSummary) -> None:
        metadata_rows = self._visible_metadata_rows(summary)
        sample_rows = summary.readable_samples or []
        self._set_table(self.tbl_visible_metadata, metadata_rows)
        self._set_table(self.tbl_samples, sample_rows)

        dns_total = int(summary.total_dns_names or len(summary.dns_query_counts or {}) or 0)
        tls_total = int(summary.total_tls_sni_hosts or len(summary.tls_sni_counts or {}) or 0)
        http_total = int(summary.total_http_hosts or len(summary.http_host_counts or {}) or 0)
        self.lbl_visible_metadata_count.setText(f"{len(metadata_rows):,} metadata rows (DNS + TLS + HTTP)")
        self.lbl_visible_metadata_breakdown.setText(
            f"DNS: {dns_total:,} | TLS SNI: {tls_total:,} | HTTP hosts: {http_total:,}"
        )
        self.lbl_samples_count.setText(f"{len(sample_rows):,} readable rows")

    def _network_overview_rows(self, summary: PcapSummary) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for item in summary.protocols or []:
            rows.append({
                "section": "Protocol",
                "value": item.get("protocol"),
                "detail": f"Number: {item.get('number') or '-'}",
                "packets": item.get("packets"),
            })
        for item in summary.top_endpoints or []:
            rows.append({
                "section": "Endpoint",
                "value": item.get("ip"),
                "detail": "Top observed endpoint",
                "packets": item.get("packets"),
            })
        for item in summary.top_ports or []:
            protocol = item.get("protocol")
            port = item.get("port")
            rows.append({
                "section": "Port",
                "value": f"{format_ip_proto(protocol) if isinstance(protocol, int) else protocol}/{port}",
                "detail": "Top observed port",
                "packets": item.get("packets"),
            })
        return rows

    def _set_network_overview_table(self, summary: PcapSummary) -> None:
        rows = self._network_overview_rows(summary)
        self._set_table(self.tbl_network_overview, rows)
        self.lbl_network_overview_count.setText(f"{len(rows):,} rows")
        self.lbl_network_overview_breakdown.setText(
            f"Protocols: {len(summary.protocols or []):,} | "
            f"Endpoints: {len(summary.top_endpoints or []):,} | "
            f"Ports: {len(summary.top_ports or []):,}"
        )

    def _set_connections_table(self, summary: PcapSummary) -> None:
        rows = summary.flows or []
        self._set_table(self.tbl_connections, rows)
        payload_rows = sum(1 for row in rows if str(row.get("pcap_payload_preview") or "").strip())
        device_ip = summary.likely_device_ip or "-"
        self.lbl_connections_count.setText(f"{len(rows):,} flow summaries")
        self.lbl_connections_breakdown.setText(
            f"Device IP: {device_ip} | Visible previews: {payload_rows:,} | "
            f"Packets: {summary.packet_count:,} | Volume: {human_bytes(summary.wire_bytes, precision=2)}"
        )

    def _set_highlights(self, summary: PcapSummary) -> None:
        rows = summary.communication_rows or []
        media_like = sum(1 for row in rows if "media" in str(row.get("activity_type") or "").lower() or "call" in str(row.get("activity_type") or "").lower())
        messaging_like = sum(1 for row in rows if "messaging" in str(row.get("activity_type") or "").lower() or "push" in str(row.get("activity_type") or "").lower())
        services = []
        seen = set()
        for row in rows:
            service = str(row.get("service") or "").strip()
            if service and service not in seen:
                seen.add(service)
                services.append(service)

        lines = [
            f"Visible app/service indicators: {', '.join(services) if services else '-'}",
            f"Messaging/push-like indicators: {messaging_like}",
            f"Possible call/media indicators: {media_like}",
            "Classification is based on metadata such as host names, ports, protocol, duration and volume. It is an investigative indicator, not content proof.",
        ]
        self.lbl_highlights_brief.setText("\n".join(lines))
        self.lbl_communication_count.setText(f"{len(rows):,} indicators")
        self.lbl_communication_breakdown.setText(
            f"Messaging/push: {messaging_like:,} | "
            f"Possible call/media: {media_like:,} | "
            f"Services: {len(services):,}"
        )
        self._set_table(self.tbl_communications, rows)
        if rows:
            self.tbl_communications.selectRow(0)
        else:
            self.txt_communication_detail.clear()

    def _on_communication_selected(self, current: QModelIndex, previous: QModelIndex | None = None) -> None:
        model = self.tbl_communications.model()
        if not isinstance(model, DictTableModel) or not current.isValid():
            self.txt_communication_detail.clear()
            return
        if current.row() < 0 or current.row() >= len(model.rows):
            self.txt_communication_detail.clear()
            return

        row = model.rows[current.row()]
        self.txt_communication_detail.setPlainText(self._communication_detail_text(row))

    def _communication_detail_text(self, row: dict[str, Any]) -> str:
        lines = [
            f"Service: {row.get('service') or '-'}",
            f"Indicator: {row.get('activity_type') or '-'}",
            f"Confidence: {row.get('confidence') or '-'}",
            f"Host / signal: {row.get('host') or '-'}",
            f"Source: {row.get('source') or '-'}",
            f"Destination: {row.get('destination') or '-'}",
            f"Protocol: {row.get('protocol') or '-'}",
            f"Volume: {human_bytes(row.get('bytes'), precision=2)}",
            f"Packets: {row.get('packets') or 0}",
            f"Duration: {format_duration_compact_ms(row.get('duration_ms'))}",
            f"First seen: {self._format_pcap_time(row.get('first_seen'))}",
            f"Last seen: {self._format_pcap_time(row.get('last_seen'))}",
            "",
            "Evidence:",
            str(row.get("evidence") or "-"),
            "",
            "Interpretation limit:",
            "This is a metadata-based indicator. It does not prove message content or confirm a call by itself.",
        ]
        return "\n".join(lines)

    def _open_communications_dialog(self) -> None:
        model = self.tbl_communications.model()
        rows = list(model.rows) if isinstance(model, DictTableModel) else []
        open_communication_indicators_dialog(
            self,
            rows=rows,
            columns=self.communication_full_columns,
            fixed_widths=self.communication_full_fixed_widths,
            detail_text=self._communication_detail_text,
            on_empty=self._info,
            append_export_footer=lambda footer, table: self._append_export_footer(
                footer, title="Communication indicators", table=table
            ),
        )

    def _on_error(self, message: str):
        self._close_period_load_progress()
        if not self._pcap_queue_auto_process:
            self._error("PCAP analysis failed", message)
        self._set_stats_style("HeaderStatLabel")
        self.lbl_stats.setText("PCAP analysis failed.")
        self._pcap_batch_failed += 1
        self._pcap_batch_processed += 1
        if self._pcap_queue_auto_save:
            self._mark_current_ingest("failed", message)
        self._update_batch_status(error_text=message)

    def _batch_progress_ui_interval(self, total: int) -> float:
        count = max(0, int(total or 0))
        if count >= 1000:
            return 1.0
        if count >= 200:
            return 0.5
        if count >= 50:
            return 0.25
        return 0.15

    def _on_batch_progress(self, processed: int, total: int, failed: int, current_file: str) -> None:
        self._pcap_batch_processed = processed
        self._pcap_batch_total = total
        self._pcap_batch_failed = failed
        if current_file:
            self._pcap_batch_current_label = current_file
        now = time.monotonic()
        interval = self._batch_progress_ui_interval(total)
        if (
            processed <= 1
            or processed >= total
            or now - self._pcap_batch_last_ui_ts >= interval
        ):
            self._pcap_batch_last_ui_ts = now
            self._update_period_load_progress(processed, total, current_file=current_file)
            self._update_batch_status()

    def _on_batch_finished(self, last_summary: object, processed: int, failed: int) -> None:
        if self._batch_finish_guard:
            return
        self._batch_finish_guard = True
        try:
            self._finish_batch_ui(last_summary, processed, failed)
        finally:
            self._batch_finish_guard = False

    def _finish_batch_ui(self, last_summary: object, processed: int, failed: int) -> None:
        self._pcap_batch_processed = processed
        self._pcap_batch_failed = failed
        total = max(int(self._pcap_batch_total or 0), int(processed or 0))
        self._update_period_load_progress(processed, total)
        self._update_batch_status()
        self._pcap_queue_auto_process = False
        self._pcap_queue = []

        self.btn_open.setEnabled(True)
        self.btn_save_project.setEnabled(bool(last_summary))
        self.btn_export.setEnabled(bool(last_summary))
        self.btn_ai_summary.setEnabled(bool(last_summary))
        self.btn_add_notes.setEnabled(bool(last_summary))
        self._update_open_button_text()

        self._set_stats_style("HeaderStatLabel")
        saved_day_count = len(self._batch_analysis_day_groups()) if self._pcap_day_groups_raw else 0
        if isinstance(last_summary, PcapSummary):
            if self._pcap_queue_auto_save and saved_day_count > 1:
                self.lbl_stats.setText(
                    f"Batch complete — {processed:,} PCAP files saved across {saved_day_count:,} daily periods."
                )
                self.btn_save_project.setText("Saved to Project")
                self._sync_save_period_button(saved=True, hide=True)
                self._reset_batch_status()
                if self._pcap_active_day:
                    self._try_load_saved_pcap_period(str(self._pcap_active_day))
            else:
                self._render_loaded_summary(last_summary)
                if self._pcap_queue_auto_save:
                    self.btn_save_project.setText("Saved to Project")
                    self._sync_save_period_button(saved=True, hide=True)
                if self._pcap_day_groups:
                    self._reset_batch_status()
        else:
            self.lbl_stats.setText("PCAP batch finished, but no capture was analyzed successfully.")

        self._pcap_queue_auto_save = False
        if self._pcap_day_groups_raw and not self._pcap_day_groups:
            self._rebuild_pcap_period_combo()
        elif self._pcap_day_groups_raw:
            self._update_period_gap_banner(list(self._pcap_day_groups_raw.keys()))
        if not self._pcap_day_groups:
            self._update_batch_status()
        else:
            self._sync_period_selector_panel()
        self._sync_period_gap_visibility()
        project_id = self._current_project_id()
        QTimer.singleShot(
            0,
            lambda pid=project_id, proc=int(processed or 0), fail=int(failed or 0): self._after_batch_project_refresh(pid, proc, fail),
        )

    def _after_batch_project_refresh(self, project_id: int | None, processed: int, failed: int) -> None:
        if project_id is None or project_id != self._current_project_id():
            return
        controller = getattr(self.app, "dataset_controller", None) if self.app else None
        if controller is not None and getattr(controller, "_import_finalize_pending", False):
            if processed > 0:
                try:
                    add_activity(
                        int(project_id),
                        "pcap_batch_finished",
                        f"{processed:,} processed, {failed:,} failed",
                    )
                except Exception:
                    pass
                if hasattr(self.app, "notes_controller"):
                    try:
                        self.app.notes_controller.refresh_activity_ui_for_project(int(project_id))
                    except Exception:
                        pass
            if self._pcap_day_groups_raw:
                self._update_period_gap_banner(list(self._pcap_day_groups_raw.keys()))
                self._sync_period_gap_visibility()
            QTimer.singleShot(0, controller.complete_deferred_import_finalize)
            return
        self._refresh_project_after_batch()
        if processed > 0:
            try:
                add_activity(
                    int(project_id),
                    "pcap_batch_finished",
                    f"{processed:,} processed, {failed:,} failed",
                )
            except Exception:
                pass
            if self.app and hasattr(self.app, "notes_controller"):
                try:
                    self.app.notes_controller.refresh_activity_ui_for_project(int(project_id))
                except Exception:
                    pass

    def _cleanup_thread(self):
        self._stop_batch_faulthandler_watch()
        self._close_period_load_progress()
        self.btn_open.setEnabled(True)
        self._update_open_button_text()
        if not self._pcap_queue:
            self._pcap_queue_auto_save = False
            self._pcap_queue_auto_process = False
            self._update_batch_status()
        self._worker = None
        self._thread = None
        self._update_reanalyze_button_state()
        if self._pcap_queue_auto_process and self._pcap_queue:
            QTimer.singleShot(100, self._load_next_queued_pcap)

    def _start_batch_faulthandler_watch(self) -> None:
        import faulthandler

        from ui.crash_logging import _TeeTextIO, _open_crash_log_handles

        self._stop_batch_faulthandler_watch()
        try:
            handles = _open_crash_log_handles()
            if not handles:
                return
            tee = _TeeTextIO(handles)
            self._batch_faulthandler_cancel = faulthandler.dump_traceback_later(
                45,
                repeat=True,
                file=tee,
            )
        except Exception:
            pass

    def _stop_batch_faulthandler_watch(self) -> None:
        cancel = getattr(self, "_batch_faulthandler_cancel", None)
        self._batch_faulthandler_cancel = None
        if cancel is not None:
            try:
                cancel()
            except Exception:
                pass

    def _cleanup_batch_thread(self):
        self._stop_batch_faulthandler_watch()
        self._batch_worker = None
        self._batch_thread = None
        self._update_reanalyze_button_state()
        self._sync_period_selector_panel()
        if self._pcap_day_groups_raw:
            self._update_period_gap_banner(list(self._pcap_day_groups_raw.keys()))
        self._sync_period_gap_visibility()

    def _update_open_button_text(self) -> None:
        if self._pcap_queue:
            self.btn_open.setText(f"Open next PCAP ({len(self._pcap_queue)})")
        else:
            self.btn_open.setText("Load dataset")

    def _reset_batch_status(self) -> None:
        self._pcap_batch_total = 0
        self._pcap_batch_processed = 0
        self._pcap_batch_failed = 0
        self._pcap_batch_current_label = ""
        self._close_period_load_progress()
        self._sync_period_selector_panel()
        self._sync_period_gap_visibility()

    def _batch_context_label(self, current_file: str = "") -> str:
        text = str(current_file or self._pcap_batch_current_label or "").strip()
        if text.lower().endswith((".pcap", ".pcapng")):
            day = _iso_day_from_path(text)
            if day:
                return self._format_day_label(day)
            return ""
        if text:
            return format_period_day_label(text)
        active_day = str(self._pcap_active_day or "")
        if active_day:
            return format_period_day_label(active_day)
        return ""

    def _update_batch_status(self, current_file: str = "", error_text: str = "") -> None:
        if not hasattr(self, "batch_status_panel"):
            return

        batch_total = int(self._pcap_batch_total or 0)
        batch_processed = int(self._pcap_batch_processed or 0)
        has_batch = bool(self._pcap_queue) or (
            batch_total > 0 and (batch_processed < batch_total or self._batch_thread is not None)
        )
        if not has_batch:
            self._sync_period_selector_panel()
            return

        if self._pcap_queue_auto_process or self._batch_thread is not None:
            remaining = max(0, int(self._pcap_batch_total) - int(self._pcap_batch_processed))
        else:
            remaining = len(self._pcap_queue)
        mode = "Auto batch" if self._pcap_queue_auto_process else "Manual queue"
        if not self._hide_individual_pcap_names():
            context_day = self._batch_context_label(current_file)
            if context_day:
                mode = f"{mode} | {context_day}"
        parts = [
            f"{mode}: {self._pcap_batch_processed:,} / {self._pcap_batch_total:,} processed",
            f"{remaining:,} remaining",
        ]
        if self._pcap_batch_failed:
            parts.append(f"{self._pcap_batch_failed:,} failed")
        if error_text:
            parts.append(f"last error: {error_text[:160]}")

        self.lbl_batch_status.setText(" | ".join(parts))
        self._sync_period_selector_panel()

    def _mark_current_ingest(self, status: str, message: str = "") -> None:
        project_id = self._current_project_id()
        if project_id is None:
            return
        paths: list[str] = []
        if self.summary:
            paths.extend(str(path) for path in (getattr(self.summary, "source_paths", None) or []) if str(path or "").strip())
            if not paths and self.summary.file_path:
                paths.append(self.summary.file_path)
        if not paths:
            fallback = (self.lbl_file.text() or "").strip()
            if fallback:
                paths.append(fallback)
        for file_path in paths:
            try:
                mark_ingest_item(project_id, file_path, status, message)
            except Exception:
                pass

    def _set_table(self, table: QTableView, rows: list[dict[str, Any]]):
        set_dict_table_rows(table, rows)

    def _set_artifact_tables(self, artifacts: list[dict[str, Any]]) -> None:
        self._all_artifacts = artifacts or []
        counts: dict[str, int] = {}
        for artifact in self._all_artifacts:
            category = str(artifact.get("category") or "Other")
            counts[category] = counts.get(category, 0) + 1

        self.cmb_artifact_category.blockSignals(True)
        self.cmb_artifact_category.clear()
        self.cmb_artifact_category.addItem(f"All artifacts ({len(self._all_artifacts)})", "")
        for category, count in sorted(counts.items()):
            self.cmb_artifact_category.addItem(f"{category} ({count})", category)
        self.cmb_artifact_category.blockSignals(False)
        if counts:
            preview_lines = [
                f"{idx}. {category}  {count:,}"
                for idx, (category, count) in enumerate(
                    sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:5],
                    start=1,
                )
            ]
            preview_text = "\n".join(preview_lines)
        else:
            preview_text = "No artifact categories loaded."
        self.lbl_artifact_preview.setText(preview_text)
        self._apply_artifact_filter()

    def _apply_artifact_filter(self, *args) -> None:
        category = self.cmb_artifact_category.currentData() if hasattr(self, "cmb_artifact_category") else ""
        rows = [
            artifact
            for artifact in self._all_artifacts
            if not category or str(artifact.get("category") or "Other") == category
        ]
        self._set_table(self.tbl_artifacts, rows)
        self.lbl_artifact_count.setText(f"{len(rows)} shown")
        selected_category = self.cmb_artifact_category.currentData() if hasattr(self, "cmb_artifact_category") else ""
        label = "artifacts" if not selected_category else f"{selected_category} artifacts"
        self.lbl_artifact_total.setText(f"{len(rows):,} {label}")
        if rows:
            self.tbl_artifacts.selectRow(0)
        else:
            self.txt_artifact_detail.clear()

    def _on_artifact_selected(self, current: QModelIndex, previous: QModelIndex | None = None) -> None:
        model = self.tbl_artifacts.model()
        if not isinstance(model, DictTableModel) or not current.isValid():
            self.txt_artifact_detail.clear()
            return
        if current.row() < 0 or current.row() >= len(model.rows):
            self.txt_artifact_detail.clear()
            return

        artifact = model.rows[current.row()]
        detail_lines = [
            f"Category: {artifact.get('category') or '-'}",
            f"Type: {artifact.get('type') or '-'}",
            f"Value: {artifact.get('value') or '-'}",
            f"Count: {artifact.get('count') or 0}",
            f"Visibility: {artifact.get('visibility') or '-'}",
            "",
            f"Source: {artifact.get('source') or '-'}",
            f"Destination: {artifact.get('destination') or '-'}",
            f"First seen: {self._format_pcap_time(artifact.get('first_seen'))}",
            f"Last seen: {self._format_pcap_time(artifact.get('last_seen'))}",
            "",
            "Meaning:",
            str(artifact.get("explanation") or "-"),
        ]
        if artifact.get("sensitive"):
            detail_lines.extend([
                "",
                "Sensitive value:",
                "The value was visible in plaintext capture data and is redacted in ViaNyquist.",
            ])
        self.txt_artifact_detail.setPlainText("\n".join(detail_lines))

    def _overview_text(self, summary: PcapSummary) -> str:
        lines = [
            "What is visible:",
            f"- DNS names: {int(summary.total_dns_names or len(summary.dns_queries or [])):,}",
            f"- TLS SNI hosts: {int(summary.total_tls_sni_hosts or len(summary.tls_sni or [])):,}",
            f"- HTTP cleartext hosts: {int(summary.total_http_hosts or len(summary.http_hosts or [])):,}",
            f"- Flow summaries: {len(summary.flows or []):,}",
            f"- Readable payload samples: {len(summary.readable_samples or []):,}",
            "",
            "Important limitation:",
            "Encrypted HTTPS, QUIC and application traffic content is not readable from packet capture alone. "
            "ViaNyquist shows the observable metadata and only the payload bytes that are actually visible.",
        ]
        return "\n".join(lines)

    def _refresh_widget_style(self, widget: QWidget) -> None:
        refresh_widget_style(widget)

    def _set_stats_style(self, object_name: str) -> None:
        apply_named_style(self.lbl_stats, object_name)

    def _set_investigator_text(self, investigator: dict[str, Any]) -> None:
        summary = str(investigator.get("plain_summary") or "")
        self.lbl_plain_summary.setText(summary)

        key_points = "\n".join(f"- {point}" for point in (investigator.get("key_points") or [])[:4])
        self.lbl_key_points.setText(f"Key points:\n{key_points}" if key_points else "")
        limitations = "\n".join(f"- {item}" for item in (investigator.get("limitations") or [])[:4])
        self.lbl_limitations.setText(f"Limitations:\n{limitations}" if limitations else "")

    def generate_ai_summary(self):
        if not self.summary:
            self._info("PCAP AI", "Open a PCAP file first.")
            return
        if not hasattr(self.app, "ai_service"):
            self._error("PCAP AI", "AI service is not available.")
            return
        if self._ai_runner.is_running():
            self._info("PCAP AI", "PCAP AI summary is already running.")
            return

        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary.setText("Generating...")
        self.txt_pcap_ai_summary.setPlainText("Generating PCAP AI summary...")
        if hasattr(self, "ai_summary_tab"):
            self.tabs.setCurrentWidget(self.ai_summary_tab)

        project_name = getattr(self.app, "current_project_name", "") or ""
        period_label = self._format_day_label(self._pcap_active_day) if self._pcap_active_day else ""
        period_mode = getattr(self, "_pcap_period_granularity", "day")
        worker = AITextWorker(
            self.app.ai_service.generate_pcap_summary,
            self.summary,
            project_name,
            period_label=period_label,
            period_mode=period_mode,
        )
        self._ai_runner.start(
            worker,
            thread_parent=self._thread_parent(),
            finished_slot=self._on_ai_summary_finished,
            error_slot=self._on_ai_summary_error,
        )

    def _on_ai_summary_finished(self, result: str):
        self.txt_pcap_ai_summary.setPlainText(result)
        if hasattr(self.app, "publish_ai_output"):
            self.app.publish_ai_output("PCAP", "PCAP AI Summary", result)
        project_id = getattr(self.app, "current_project_id", None) if self.app else None
        if project_id is not None and (result or "").strip():
            try:
                add_activity(int(project_id), "ai_summary_generated", "PCAP summary")
                if self.app and hasattr(self.app, "notes_controller"):
                    self.app.notes_controller.refresh_activity_ui_for_project(int(project_id))
            except Exception:
                pass
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Summary")

    def _on_ai_summary_error(self, message: str):
        self.txt_pcap_ai_summary.setPlainText(f"AI error: {message}")
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Summary")

    def export_summary(self):
        if not self.summary:
            self._info("PCAP export", "Open a PCAP file first.")
            return

        default_name = Path(self.summary.file_name).with_suffix(".pcap-summary.html").name
        project = get_project(self._current_project_id()) if self._current_project_id() is not None else None
        default_path = (
            str(workspace_export_path(project.base_folder, default_name, category="pcap"))
            if project and project.base_folder
            else default_name
        )
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export PCAP summary",
            default_path,
            "HTML files (*.html)",
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".html"):
            file_path += ".html"

        try:
            export_pcap_summary_html(
                file_path,
                self.summary,
                project=project,
                project_name=getattr(self.app, "current_project_name", "") or "",
            )
            webbrowser.open(Path(file_path).resolve().as_uri())
        except Exception as exc:
            self._error("PCAP export failed", str(exc))

    def save_to_project(self):
        if not self.btn_save_project.isEnabled() or self._current_period_already_saved():
            return
        self._save_current_to_project(show_dialog=True, check_device=True)

    def _save_current_to_project(
        self,
        *,
        show_dialog: bool = True,
        check_device: bool = True,
        refresh_ui: bool = True,
    ) -> bool:
        if not self.summary:
            if show_dialog:
                self._info("PCAP", "Open a PCAP file first.")
            return False

        if self._current_period_already_saved():
            self._sync_save_period_button(saved=True)
            return False

        project_id = self._current_project_id()
        if project_id is None:
            if show_dialog:
                self._info(
                    "PCAP",
                    "Open an active project first.",
                    "PCAP analyses must be tied to a project before they can be used in notes or future activity profiles.",
                )
            return False
        if not self._ensure_project_workspace():
            return False

        if check_device and not self._confirm_project_device_match(project_id):
            return False

        try:
            source_paths = list(getattr(self.summary, "source_paths", None) or [])
            if not source_paths and getattr(self.summary, "file_path", ""):
                source_paths = [self.summary.file_path]
            source_count = len(source_paths)
            investigator = build_investigator_view(self.summary)
            plain = str(investigator.get("plain_summary") or "")
            period_day = resolve_period_day(
                active_day=self._pcap_active_day,
                file_paths=source_paths,
                first_seen=self.summary.first_seen,
                last_seen=self.summary.last_seen,
            )
            span = capture_span_note(self.summary.first_seen, self.summary.last_seen, period_day=period_day)
            if span:
                plain = f"{plain}\n{span}"

            if source_count > 1:
                digest = aggregate_hash_for_paths(source_paths)
                saved_path = self.summary.file_path or self.summary.file_name
                saved_name = self.summary.file_name or f"{source_count:,} PCAP files"
                source_id = save_pcap_period_summary(
                    project_id,
                    period_day=period_day,
                    file_path=saved_path,
                    file_name=saved_name,
                    file_sha256_value=digest,
                    file_size=self.summary.file_size,
                    format=self.summary.format,
                    packet_count=self.summary.packet_count,
                    wire_bytes=self.summary.wire_bytes,
                    first_seen=self.summary.first_seen,
                    last_seen=self.summary.last_seen,
                    duration_seconds=self.summary.duration_seconds,
                    likely_device_ip=self.summary.likely_device_ip,
                    summary_text=plain,
                )
            else:
                saved_path = self.summary.file_path
                saved_name = self.summary.file_name
                digest = file_sha256(saved_path)
                source_id = save_pcap_period_summary(
                    project_id,
                    period_day=period_day or resolve_period_day(file_paths=[saved_path], first_seen=self.summary.first_seen),
                    file_path=saved_path,
                    file_name=saved_name,
                    file_sha256_value=digest,
                    file_size=self.summary.file_size,
                    format=self.summary.format,
                    packet_count=self.summary.packet_count,
                    wire_bytes=self.summary.wire_bytes,
                    first_seen=self.summary.first_seen,
                    last_seen=self.summary.last_seen,
                    duration_seconds=self.summary.duration_seconds,
                    likely_device_ip=self.summary.likely_device_ip,
                    summary_text=plain,
                )
            self._mark_saved_source_paths_done(project_id, source_paths)
            bound_project_ip = self._bind_project_device_ip_if_empty(project_id)
            merge_public_ips_into_profile(
                project_id,
                collect_public_ips_from_pcap_summary(self.summary),
                source="pcap",
            )
        except Exception as exc:
            if show_dialog:
                self._error("PCAP", "Failed to save PCAP analysis to project.", str(exc))
            return False

        self._saved_source_id = source_id
        self._sync_save_period_button(saved=True, hide=not show_dialog)
        if refresh_ui:
            self._refresh_project_after_batch()
        details = [f"Source id: {source_id}"]
        if bound_project_ip:
            details.append(f"Project known IP was set to: {bound_project_ip}")
        if show_dialog:
            self._info("PCAP", "PCAP analysis saved to active project.", "\n".join(details))
        if not refresh_ui:
            self._refresh_activity()
        return True

    def _aggregate_source_hash(self, source_paths: list[str]) -> str:
        digest = hashlib.sha256()
        for raw_path in sorted(str(path) for path in source_paths if str(path or "").strip()):
            path = Path(raw_path)
            try:
                stat = path.stat()
                marker = f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}"
            except Exception:
                marker = f"{raw_path}|missing"
            digest.update(marker.encode("utf-8", errors="replace"))
            digest.update(b"\n")
        return "aggregate:" + digest.hexdigest()

    def _mark_saved_source_paths_done(self, project_id: int, source_paths: list[str]) -> None:
        paths = [Path(str(path)) for path in source_paths if str(path or "").strip()]
        rows = []
        for path in paths:
            try:
                file_size = path.stat().st_size if path.is_file() else 0
            except Exception:
                file_size = 0
            rows.append({
                "file_path": str(path),
                "file_name": path.name,
                "file_type": "pcap",
                "file_size": file_size,
                "observed_date": self._observed_date_for_source_path(path),
            })

        if not rows:
            return

        source_root = self._common_source_root(paths)
        upsert_ingest_items(project_id, source_root, rows)
        for row in rows:
            mark_ingest_item(project_id, row["file_path"], "done", "")

    def _common_source_root(self, paths: list[Path]) -> str:
        parents = [str(path.parent) for path in paths]
        if not parents:
            return ""
        try:
            return str(Path(os.path.commonpath(parents)))
        except Exception:
            return parents[0]

    def _observed_date_for_source_path(self, path: Path) -> str:
        text = str(path)
        match = re.search(r"(20\d{6})", text)
        if match:
            raw = match.group(1)
            return f"{raw[:4]}-{raw[4:6]}-{raw[6:8]}"
        first_seen = str(getattr(self.summary, "first_seen", "") or "")
        if len(first_seen) >= 10 and first_seen[4] == "-" and first_seen[7] == "-":
            return first_seen[:10]
        return ""

    def _refresh_project_after_batch(self) -> None:
        if self._project_batch_refresh_running:
            return
        project_id = self._current_project_id()
        if project_id is None:
            return
        self._project_batch_refresh_running = True
        try:
            if hasattr(self.app, "projects_ui_controller"):
                self.app.projects_ui_controller.sync_project_workspace(project_id)
                self.app.projects_ui_controller.refresh_recent_datasets(project_id)
                self.app.projects_ui_controller.refresh_case_dashboard()
            if hasattr(self.app, "refresh_activity_profile_ui"):
                self.app.refresh_activity_profile_ui()
            if self._pcap_day_groups_raw:
                self._update_period_gap_banner(list(self._pcap_day_groups_raw.keys()))
            self._sync_period_gap_visibility()
        finally:
            self._project_batch_refresh_running = False

    def add_summary_to_notes(self):
        if not self.summary:
            self._info("Notes", "Open a PCAP file first.")
            return

        project_id = self._current_project_id()
        if project_id is None:
            self._info("Notes", "Open an active project first.")
            return

        block = self._make_notes_block()
        if not block:
            return

        try:
            if hasattr(self.app, "notes_page"):
                self.app.notes_page.append_block(block)
            else:
                existing = self.app.txt_notes.toPlainText() or ""
                if existing.strip():
                    if not existing.endswith("\n"):
                        existing += "\n"
                    new_text = existing + "\n" + block
                else:
                    new_text = block
                self.app.txt_notes.setPlainText(new_text)
            self.app._notes_dirty = True
            self.app.notes_controller.flush()
            add_activity(project_id, "pcap_notes_added", self.summary.file_name)
            self._refresh_activity()
        except Exception as exc:
            self._error("Notes", "Failed to add PCAP summary to notes.", str(exc))
            return

        if hasattr(self.app, "go_to_notes"):
            self.app.go_to_notes()
        self._info("Notes", "PCAP summary added to project notes.")

    def _make_notes_block(self) -> str:
        if not self.summary:
            return ""

        investigator = build_investigator_view(self.summary)
        ts = datetime.now().strftime("%d.%m.%Y. %H:%M:%S")
        lines = [
            f"[PCAP summary added: {ts}]",
            f"File: {self.summary.file_name}",
            f"Source: {self.summary.file_path}",
            f"Device IP: {self.summary.likely_device_ip or '-'}",
            f"Capture period: {self._format_pcap_range(self.summary.first_seen, self.summary.last_seen)}",
            f"Packets: {self.summary.packet_count:,}",
            f"Volume: {human_bytes(self.summary.wire_bytes, precision=2)}",
            "",
            str(investigator.get("plain_summary") or ""),
            "",
            "Key points:",
        ]
        for point in investigator.get("key_points") or []:
            lines.append(f"- {point}")
        if self.summary.communication_rows:
            lines.extend([
                "",
                "Communication highlights:",
            ])
            for row in self.summary.communication_rows or []:
                lines.append(
                    f"- {row.get('service')}: {row.get('activity_type')} "
                    f"({row.get('confidence')} confidence) - {row.get('evidence')}"
                )
        lines.extend([
            "",
            "Artifact categories:",
        ])
        for row in self._artifact_category_counts():
            lines.append(f"- {row['category']}: {row['count']}")
        lines.extend([
            "",
            "Limitations:",
        ])
        for item in investigator.get("limitations") or []:
            lines.append(f"- {item}")
        lines.append("-" * 60)
        return "\n".join(lines) + "\n"

    def _artifact_category_counts(self) -> list[dict[str, Any]]:
        if not self.summary:
            return []
        counts: dict[str, int] = {}
        for artifact in self.summary.artifacts or []:
            category = str(artifact.get("category") or "Other")
            counts[category] = counts.get(category, 0) + 1
        return [
            {"category": category, "count": count}
            for category, count in sorted(counts.items())
        ]

    def _confirm_project_device_match(self, project_id: int) -> bool:
        return True

    def _bind_project_device_ip_if_empty(self, project_id: int) -> str:
        current_ip = (self.summary.likely_device_ip if self.summary else "").strip()
        if not current_ip:
            return ""

        project = get_project(project_id)
        if not project or (project.subject_ip or "").strip():
            return ""

        set_project_subject(
            project_id,
            first_name=project.subject_first_name,
            last_name=project.subject_last_name,
            oib=project.subject_oib,
            msisdn=project.subject_msisdn,
            imsi=project.subject_imsi,
            imei=project.subject_imei,
            ip=current_ip,
            extra_identifiers=project.subject_extra_identifiers,
        )
        return current_ip

    def _current_project_id(self) -> int | None:
        return getattr(self.app, "current_project_id", None)

    def _ensure_project_workspace(self) -> bool:
        project_id = self._current_project_id()
        if project_id is None:
            self._info(
                "PCAP",
                "Open an active project first.",
                "PCAP files must be tied to a project Workspace before analysis.",
            )
            return False

        project = get_project(project_id)
        if project and (project.base_folder or "").strip():
            return True

        self._info(
            "PCAP",
            "Set a Workspace folder for the active project first.",
            "PCAP files, exports and project references are managed through the Workspace folder.",
        )
        return False

    def _info(self, title: str, message: str, details: str = "") -> None:
        if hasattr(self.app, "_message_dialog"):
            self.app._message_dialog(title, message, details, width=520)
        else:
            QMessageBox.information(self, title, message if not details else f"{message}\n\n{details}")

    def _error(self, title: str, message: str, details: str = "") -> None:
        if hasattr(self.app, "_message_dialog"):
            self.app._message_dialog(title, message, details, width=560)
        else:
            QMessageBox.critical(self, title, message if not details else f"{message}\n\n{details}")

    def _confirm(
        self,
        title: str,
        message: str,
        details: str = "",
        ok_text: str = "OK",
        cancel_text: str = "Cancel",
    ) -> bool:
        if hasattr(self.app, "_confirm_dialog"):
            return self.app._confirm_dialog(
                title=title,
                message=message,
                details=details,
                ok_text=ok_text,
                cancel_text=cancel_text,
                width=560,
            )
        return QMessageBox.question(self, title, message) == QMessageBox.Yes

    def _refresh_activity(self) -> None:
        if hasattr(self.app, "notes_controller"):
            self.app.notes_controller.refresh_activity_ui()

    def shutdown_background_tasks(self, wait_ms: int = 5000) -> None:
        self._stop_batch_faulthandler_watch()
        if self._batch_worker is not None:
            self._batch_worker.request_stop()
        self._ai_runner.stop(wait_ms=wait_ms)
        for thread_name in ("_thread", "_batch_thread"):
            thread = getattr(self, thread_name, None)
            stop_qthread(thread, wait_ms=wait_ms)
            setattr(self, thread_name, None)
        self._worker = None
        self._batch_worker = None
