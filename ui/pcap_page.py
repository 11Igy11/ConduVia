from __future__ import annotations

from ui.pcap.analysis_handlers import PcapAnalysisMixin
from ui.pcap.export_actions import PcapExportMixin
from ui.pcap.investigator_panels import PcapInvestigatorMixin
from ui.pcap.period_ui import PcapPeriodMixin

from typing import Any

from PySide6.QtCore import QThread, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableView,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)

from core.analysis_limits import PROFILE_CHART_PREVIEW_ROWS
from ui.expand_dialogs import (
    build_dict_table,
)
from ui.buttons import make_action_button, style_action_button
from ui.dataset_header_layout import (
    DATASET_HEADER_MARGINS,
    DATASET_HEADER_SPACING,
    DATASET_PAGE_SPACING,
)
from core.limit_notices import pcap_flow_cap_notice
from core.pcap_analyzer import PcapSummary
from core.db import (
    get_project,
    set_project_subject,
)
from ui.bar_chart_widget import BarChartWidget
from ui.explore_widgets import CopyableTableView
from ui.period_selector_panel import (
    build_period_selector_row,
    make_period_day_combo,
    make_period_label,
    make_period_mode_combo,
    make_pick_range_button,
)
from ui.font_utils import apply_named_style, refresh_widget_style
from ui.thread_utils import stop_qthread
from ui.worker_runner import WorkerRunner
from ui.pcap_batch_runner import PcapBatchRunner
from ui.workers.pcap_workers import PcapWorker


class PcapPage(PcapInvestigatorMixin, PcapPeriodMixin, PcapAnalysisMixin, PcapExportMixin, QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.app = parent
        self.summary: PcapSummary | None = None
        self._thread: QThread | None = None
        self._worker: PcapWorker | None = None
        self._batch_runner = PcapBatchRunner(self._thread_parent())
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
        self._ai_runner = WorkerRunner(self._thread_parent())
        self._saved_source_id: int | None = None
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
        self._selected_communication_row: dict[str, Any] | None = None
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
        self.btn_mark_finding = make_action_button("Mark as Finding", enabled=False)
        self.btn_mark_finding.setToolTip("Save the loaded PCAP period/day as a project finding.")
        self.btn_go_to_findings = make_action_button("Go to Findings", enabled=False)
        self.btn_go_to_findings.setToolTip("Open project findings filtered to PCAP entries")
        self.btn_export = make_action_button("Export Summary", enabled=False)
        top.addWidget(self.lbl_title)
        top.addStretch()
        top.addWidget(self.btn_open)
        top.addWidget(self.btn_save_project)
        top.addWidget(self.btn_ai_summary)
        top.addWidget(self.btn_add_notes)
        top.addWidget(self.btn_mark_finding)
        top.addWidget(self.btn_go_to_findings)
        top.addWidget(self.btn_export)

        self.lbl_file = QLabel("No PCAP loaded")
        self.lbl_file.setObjectName("HeaderPathLabel")
        self.lbl_file.setWordWrap(True)
        self.lbl_stats = QLabel("")
        self.lbl_stats.setObjectName("HeaderStatLabel")
        self.lbl_stats.setWordWrap(False)

        self.lbl_pcap_day = make_period_label(header)
        self.cmb_pcap_day = make_period_day_combo(header)
        self.cmb_pcap_period_mode = make_period_mode_combo(header)
        self.btn_pcap_pick_range = make_pick_range_button(header)
        self.btn_reanalyze_period = make_action_button("Re-analyze Period", enabled=False)
        self.btn_reanalyze_period.setToolTip(
            "Re-run PCAP analysis for the selected period from source files."
        )
        self.btn_reanalyze_period.setVisible(False)

        header_bottom = QHBoxLayout()
        header_bottom.setSpacing(2)
        header_bottom.setContentsMargins(0, 0, 0, 0)
        header_bottom.addWidget(self.lbl_stats, 1)

        self.pcap_period_row = build_period_selector_row(
            header,
            period_label=self.lbl_pcap_day,
            day_combo=self.cmb_pcap_day,
            mode_combo=self.cmb_pcap_period_mode,
            pick_range_button=self.btn_pcap_pick_range,
            trailing_widgets=[self.btn_reanalyze_period],
        )

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
        self.btn_mark_finding.clicked.connect(self._mark_pcap_period_as_finding)
        self.btn_go_to_findings.clicked.connect(self._open_project_findings)
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

    def refresh_findings_link(self) -> None:
        enabled = self._current_project_id() is not None
        if hasattr(self, "btn_go_to_findings"):
            self.btn_go_to_findings.setEnabled(enabled)

    def _open_project_findings(self) -> None:
        if self.app is None:
            return
        if self._current_project_id() is None:
            self._info("Findings", "Open an active project first.")
            return
        if hasattr(self.app, "go_to_findings"):
            self.app.go_to_findings(pcap_filter=True, from_pcap=True)

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

        self.btn_expand_communications = make_action_button("Open full communication table")
        self.btn_expand_communications.clicked.connect(self._open_communications_dialog)
        self.btn_mark_communication_finding = make_action_button("Mark as Finding", enabled=False)
        self.btn_mark_communication_finding.setToolTip(
            "Save the selected communication indicator as a finding. Select a row in the full table first."
        )
        self.btn_mark_communication_finding.clicked.connect(self._mark_pcap_communication_as_finding)

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
            extra_buttons=[self.btn_mark_communication_finding],
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
        self.summary_scroll = scroll

        content = QWidget()
        content.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(14)

        self.investigator_card = QFrame()
        self.investigator_card.setObjectName("PcapInvestigatorCard")
        card_outer = QVBoxLayout(self.investigator_card)
        card_outer.setContentsMargins(14, 12, 14, 12)
        card_outer.setSpacing(8)

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

        card_outer.addWidget(self.lbl_plain_summary)
        card_outer.addWidget(self.lbl_key_points)
        card_outer.addWidget(self.lbl_limitations)

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

        layout.addWidget(self.investigator_card)
        layout.addLayout(top)
        layout.addWidget(self.visibility_panel)

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
        self.btn_export_metadata = make_action_button("Export metadata", enabled=False)
        self.btn_export_metadata.clicked.connect(self._open_metadata_export_menu)
        export_row.addWidget(self.btn_export_metadata)
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
        *,
        extra_buttons: list[QPushButton] | None = None,
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
        detail_label.setMinimumHeight(28)

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_description)
        layout.addWidget(count_label)
        layout.addWidget(detail_label)

        button_row = QHBoxLayout()
        button_row.setContentsMargins(0, 6, 0, 0)
        button_row.addStretch()
        for extra in extra_buttons or []:
            button_row.addWidget(extra)
        button_row.addWidget(button)
        layout.addLayout(button_row)
        return card






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



















    def showEvent(self, event) -> None:
        super().showEvent(event)
        project_id = self._current_project_id()
        if project_id is None:
            return
        if self._pcap_day_groups_raw or self._thread is not None or self._batch_runner.is_running():
            return
        controller = getattr(self.app, "dataset_controller", None)
        if controller is None:
            return
        if (
            getattr(controller, "_import_finalize_running", False)
            or getattr(controller, "_import_finalize_pending", False)
            or getattr(controller, "_import_plan", None)
        ):
            return
        controller.sync_pcap_periods_from_project(project_id)



    def _mark_pcap_period_as_finding(self) -> None:
        if self.app is not None and hasattr(self.app, "findings_controller"):
            self.app.findings_controller.mark_pcap_period_as_finding()

    def _mark_pcap_communication_as_finding(self) -> None:
        if self.app is not None and hasattr(self.app, "findings_controller"):
            self.app.findings_controller.mark_pcap_communication_as_finding()

    def _sync_communication_finding_button(self) -> None:
        if not hasattr(self, "btn_mark_communication_finding"):
            return
        enabled = bool(getattr(self, "_selected_communication_row", None)) and self.summary is not None
        self.btn_mark_communication_finding.setEnabled(enabled)

    def refresh_current_view(self) -> None:
        if self._thread is not None or self._batch_runner.is_running():
            return
        if self.summary:
            self._render_loaded_summary(self.summary)
            return
        day = str(self._pcap_active_day or self.cmb_pcap_day.currentData() or "")
        if day:
            self._try_load_saved_pcap_period(day)

    def clear_project_view(self) -> None:
        """Reset PCAP page when project/dataset context is cleared."""
        if self._batch_runner.worker is not None:
            self._batch_runner.request_stop()
        self._pcap_queue = []
        self._pcap_queue_auto_save = False
        self._pcap_queue_auto_process = False
        self.summary = None
        self._selected_communication_row = None
        self._sync_communication_finding_button()
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
            (getattr(self, "btn_mark_finding", None), False),
            (getattr(self, "btn_go_to_findings", None), False),
            (getattr(self, "btn_mark_communication_finding", None), False),
            (getattr(self, "btn_export_metadata", None), False),
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

































    def _refresh_widget_style(self, widget: QWidget) -> None:
        refresh_widget_style(widget)

    def _set_stats_style(self, object_name: str) -> None:
        apply_named_style(self.lbl_stats, object_name)





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
        self._batch_runner.stop(wait_ms=wait_ms)
        self._batch_runner.stop_crash_watch()
        self._ai_runner.stop(wait_ms=wait_ms)
        stop_qthread(self._thread, wait_ms=wait_ms)
        self._thread = None
        self._worker = None
