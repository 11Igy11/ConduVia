from __future__ import annotations

import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QThread, Qt, Signal
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
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableView,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QHeaderView,
)

from core.exporters.pcap_exporter import export_pcap_summary_html
from core.formatters import format_duration_compact_ms, format_pcap_datetime, human_bytes
from core.pcap_analyzer import PcapSummary, analyze_pcap, build_investigator_view
from core.protocols import format_ip_proto
from core.workspace import workspace_export_path
from core.db import (
    add_activity,
    add_pcap_source,
    file_sha256,
    get_app_settings,
    get_project,
    list_project_pcap_device_ips,
    set_project_subject,
)
from ui.activity_profile_page import BarChartWidget
from ui.explore_widgets import AITextWorker, CopyableTableView


class PcapWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, path: str):
        super().__init__()
        self.path = path

    def run(self):
        try:
            self.finished.emit(analyze_pcap(self.path))
        except Exception as exc:
            self.error.emit(str(exc))


class DictTableModel(QAbstractTableModel):
    def __init__(self, columns: list[tuple[str, str]], rows: list[dict[str, Any]] | None = None):
        super().__init__()
        self.columns = columns
        self.rows = rows or []

    def set_rows(self, rows: list[dict[str, Any]]):
        self.beginResetModel()
        self.rows = rows or []
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.columns)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.columns[section][1]
        if role == Qt.DisplayRole:
            return str(section + 1)
        return None

    def sort(self, column: int, order: Qt.SortOrder = Qt.AscendingOrder):
        if column < 0 or column >= len(self.columns):
            return
        key = self.columns[column][0]
        reverse = order == Qt.DescendingOrder
        self.layoutAboutToBeChanged.emit()
        self.rows.sort(key=lambda row: self._sort_value(key, row.get(key, "")), reverse=reverse)
        self.layoutChanged.emit()

    def _sort_value(self, key: str, value: Any):
        if value is None:
            return (1, "")
        if key in {
            "bytes",
            "bidirectional_bytes",
            "packets",
            "bidirectional_packets",
            "duration_ms",
            "bidirectional_duration_ms",
            "count",
            "share",
            "port",
            "src_port",
            "dst_port",
            "protocol",
            "protocol_number",
        }:
            try:
                return (0, float(value))
            except Exception:
                return (0, 0.0)
        if key == "confidence":
            order = {"low": 1, "medium": 2, "high": 3}
            return (0, order.get(str(value).strip().lower(), 0))
        return (0, str(value).casefold())

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role not in (Qt.DisplayRole, Qt.ToolTipRole):
            return None
        key = self.columns[index.column()][0]
        value = self.rows[index.row()].get(key, "")
        if role == Qt.ToolTipRole:
            return "" if value is None else str(value)
        if key in ("protocol", "protocol_number") and isinstance(value, int):
            return format_ip_proto(value)
        if key in ("bytes", "bidirectional_bytes"):
            return human_bytes(value, precision=2)
        if key in ("bidirectional_duration_ms", "duration_ms"):
            return format_duration_compact_ms(value)
        if key in {
            "time",
            "hour",
            "first_seen",
            "last_seen",
            "bidirectional_first_seen_ms",
            "bidirectional_last_seen_ms",
        }:
            return format_pcap_datetime(value)
        if key == "share":
            try:
                return f"{float(value):.1f}%"
            except Exception:
                return str(value)
        return "" if value is None else str(value)


class PcapPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.app = parent
        self.summary: PcapSummary | None = None
        self._thread: QThread | None = None
        self._worker: PcapWorker | None = None
        self._ai_thread: QThread | None = None
        self._ai_worker: AITextWorker | None = None
        self._saved_source_id: int | None = None
        self._all_artifacts: list[dict[str, Any]] = []
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(10)

        header = QFrame()
        header.setObjectName("ExploreHeaderCard")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(14, 14, 14, 14)
        header_layout.setSpacing(10)

        top = QHBoxLayout()
        self.lbl_title = QLabel("PCAP analysis")
        self.lbl_title.setObjectName("HeaderProjectLabel")
        self.btn_open = QPushButton("Open PCAP")
        self.btn_save_project = QPushButton("Save to Project")
        self.btn_save_project.setEnabled(False)
        self.btn_ai_summary = QPushButton("AI Summary")
        self.btn_ai_summary.setEnabled(False)
        self.btn_add_notes = QPushButton("Add to Notes")
        self.btn_add_notes.setEnabled(False)
        self.btn_export = QPushButton("Export Summary")
        self.btn_export.setEnabled(False)
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

        header_layout.addLayout(top)
        header_layout.addWidget(self.lbl_file)
        header_layout.addWidget(self.lbl_stats)
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
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

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

        self.txt_communication_detail = QTextEdit()
        self.txt_communication_detail.setReadOnly(True)
        self.txt_communication_detail.setMinimumWidth(300)
        self.txt_communication_detail.setPlaceholderText("Select a communication indicator to see the evidence used for classification.")

        self.btn_expand_communications = QPushButton("Expand table")
        self.btn_expand_communications.setFixedHeight(34)
        self.btn_expand_communications.clicked.connect(self._open_communications_dialog)

        indicators_header = QHBoxLayout()
        indicators_header.setContentsMargins(0, 0, 0, 0)
        indicators_header.setSpacing(8)
        indicators_title = QLabel("Communication indicators")
        indicators_title.setObjectName("SectionTitle")
        indicators_header.addWidget(indicators_title)
        indicators_header.addStretch()
        indicators_header.addWidget(self.btn_expand_communications)

        brief_group = self._group("Investigation brief", self.lbl_highlights_brief)
        brief_group.setMaximumHeight(145)
        table_panel = QWidget()
        table_layout = QVBoxLayout(table_panel)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.setSpacing(8)
        table_layout.addLayout(indicators_header)
        table_layout.addWidget(self.tbl_communications, 1)

        detail_group = self._group("Selected indicator evidence", self.txt_communication_detail)
        detail_group.setMinimumWidth(320)

        body = QSplitter(Qt.Horizontal)
        body.addWidget(table_panel)
        body.addWidget(detail_group)
        body.setStretchFactor(0, 5)
        body.setStretchFactor(1, 1)
        body.setCollapsible(0, False)
        body.setCollapsible(1, False)

        layout.addWidget(brief_group)
        layout.addWidget(body, 1)

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
            label_width=190,
            label_limit=38,
            max_rows=24,
        )
        self.chart_activity = BarChartWidget(
            "Activity timeline by hour",
            value_key="count",
            value_label_key="value",
            label_width=175,
            label_limit=28,
            max_rows=24,
        )
        self.chart_visibility = BarChartWidget(
            "Visible vs encrypted indicators",
            value_key="count",
            value_label_key="value",
            count_list=True,
            max_rows=6,
        )

        top = QHBoxLayout()
        top.setSpacing(10)
        self.chart_services.setMinimumHeight(260)
        self.chart_activity.setMinimumHeight(260)
        self.chart_visibility.setMinimumHeight(170)

        top.addWidget(self.chart_services, 1)
        top.addWidget(self.chart_activity, 1)

        layout.addWidget(self.investigator_card, 0)
        layout.addLayout(top, 2)
        layout.addWidget(self.chart_visibility, 1)
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
        self.btn_expand_network_overview = QPushButton("Expand")
        self.btn_expand_network_overview.setFixedHeight(32)
        self.btn_expand_network_overview.clicked.connect(
            lambda: self._open_table_dialog("Network overview", self.tbl_network_overview)
        )
        network_panel = QWidget()
        network_layout = QVBoxLayout(network_panel)
        network_layout.setContentsMargins(0, 0, 0, 0)
        network_layout.setSpacing(8)
        network_header = QHBoxLayout()
        network_header.addStretch()
        network_header.addWidget(self.btn_expand_network_overview)
        network_layout.addLayout(network_header)
        network_layout.addWidget(self.tbl_network_overview, 1)

        layout.addWidget(self.overview_card)
        layout.addWidget(self._group("Network overview", network_panel), 1)
        layout.addStretch()

        scroll.setWidget(content)
        page_layout.addWidget(scroll, 1)
        return page

    def _build_evidence_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

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

        self.btn_expand_metadata = QPushButton("Expand")
        self.btn_expand_metadata.setFixedHeight(32)
        self.btn_expand_metadata.clicked.connect(
            lambda: self._open_table_dialog("Visible metadata", self.tbl_visible_metadata)
        )
        metadata_panel = QWidget()
        metadata_layout = QVBoxLayout(metadata_panel)
        metadata_layout.setContentsMargins(0, 0, 0, 0)
        metadata_layout.setSpacing(8)
        metadata_header = QHBoxLayout()
        metadata_header.addStretch()
        metadata_header.addWidget(self.btn_expand_metadata)
        metadata_layout.addLayout(metadata_header)
        metadata_layout.addWidget(self.tbl_visible_metadata, 1)

        samples_panel = QWidget()
        samples_layout = QVBoxLayout(samples_panel)
        samples_layout.setContentsMargins(0, 0, 0, 0)
        samples_layout.setSpacing(8)

        self.btn_expand_samples = QPushButton("Expand")
        self.btn_expand_samples.setFixedHeight(32)
        self.btn_expand_samples.clicked.connect(
            lambda: self._open_table_dialog("Readable payload / metadata samples", self.tbl_samples)
        )
        samples_header = QHBoxLayout()
        samples_header.addStretch()
        samples_header.addWidget(self.btn_expand_samples)
        samples_layout.addLayout(samples_header)

        samples_hint = QLabel(
            "Visible values are extracted from DNS names, TLS SNI, HTTP host/header data and plaintext payload previews. "
            "Treat them as observable network evidence, not as decrypted message content."
        )
        samples_hint.setObjectName("MutedLabel")
        samples_hint.setWordWrap(True)
        samples_hint.setTextInteractionFlags(Qt.TextSelectableByMouse)
        samples_layout.addWidget(samples_hint)
        samples_layout.addWidget(self.tbl_samples, 1)

        layout.addWidget(self._group("Visible metadata", metadata_panel), 0)
        layout.addWidget(self._group("Readable payload / metadata samples", samples_panel), 1)
        return page

    def _build_artifacts_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        controls = QHBoxLayout()
        controls.setSpacing(10)
        controls.addWidget(QLabel("Category"))
        self.cmb_artifact_category = QComboBox()
        self.cmb_artifact_category.setMinimumWidth(240)
        self.cmb_artifact_category.currentIndexChanged.connect(self._apply_artifact_filter)
        self.lbl_artifact_count = QLabel("")
        self.lbl_artifact_count.setObjectName("MutedLabel")
        self.btn_expand_artifacts = QPushButton("Expand")
        self.btn_expand_artifacts.setFixedHeight(32)
        self.btn_expand_artifacts.clicked.connect(
            lambda: self._open_table_dialog("Extracted artifacts", self.tbl_artifacts)
        )
        controls.addWidget(self.cmb_artifact_category)
        controls.addWidget(self.lbl_artifact_count)
        controls.addStretch()
        controls.addWidget(self.btn_expand_artifacts)
        layout.addLayout(controls)

        columns = [
            ("category", "Category"),
            ("type", "Type"),
            ("value", "Value"),
            ("count", "Count"),
            ("visibility", "Visibility"),
            ("first_seen", "First Seen"),
            ("last_seen", "Last Seen"),
        ]

        self.tbl_artifacts = self._table(
            columns,
            fixed_widths={0: 150, 1: 180, 2: 360, 3: 80, 4: 150, 5: 170, 6: 170},
            stretch_columns=[],
        )
        self.tbl_artifacts.setMinimumHeight(360)
        self.tbl_artifacts.selectionModel().currentRowChanged.connect(self._on_artifact_selected)

        self.txt_artifact_detail = QTextEdit()
        self.txt_artifact_detail.setReadOnly(True)
        self.txt_artifact_detail.setMinimumHeight(150)
        self.txt_artifact_detail.setPlaceholderText("Select an artifact to see source, destination and explanation.")

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self._group("Extracted artifacts", self.tbl_artifacts))
        splitter.addWidget(self._group("Artifact details", self.txt_artifact_detail))
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        layout.addWidget(splitter, 1)
        return page

    def _build_connections_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        header = QHBoxLayout()
        title = QLabel("Connections")
        title.setObjectName("SectionTitle")
        self.btn_expand_connections = QPushButton("Expand")
        self.btn_expand_connections.setFixedHeight(32)
        self.btn_expand_connections.clicked.connect(
            lambda: self._open_table_dialog("Connections", self.tbl_connections)
        )
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self.btn_expand_connections)
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
        layout.addLayout(header)
        layout.addWidget(self.tbl_connections)
        return page

    def _table(
        self,
        columns: list[tuple[str, str]],
        *,
        stretch_last: bool = False,
        fixed_widths: dict[int, int] | None = None,
        stretch_columns: list[int] | None = None,
    ) -> CopyableTableView:
        table = CopyableTableView(self.app)
        table.setModel(DictTableModel(columns))
        table.setSortingEnabled(True)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        table.setEditTriggers(QTableView.NoEditTriggers)
        table.setWordWrap(False)
        table.verticalHeader().setVisible(False)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        table.setMinimumHeight(210)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(stretch_last)
        fixed_widths = fixed_widths or {}
        for idx, width in fixed_widths.items():
            if 0 <= idx < len(columns):
                table.setColumnWidth(idx, width)
        for idx in stretch_columns or []:
            if 0 <= idx < len(columns):
                header.setSectionResizeMode(idx, QHeaderView.Stretch)
        return table

    def _group(self, title: str, widget: QWidget) -> QGroupBox:
        group = QGroupBox(title)
        layout = QVBoxLayout(group)
        layout.addWidget(widget)
        return group

    def _dialog_size(self, preferred_width: int, preferred_height: int) -> tuple[int, int]:
        screen = QApplication.primaryScreen()
        if screen is None:
            return preferred_width, preferred_height
        available = screen.availableGeometry()
        width = min(preferred_width, max(760, available.width() - 120))
        height = min(preferred_height, max(520, available.height() - 120))
        return width, height

    def _open_table_dialog(self, title: str, source_table: QTableView) -> None:
        source_model = source_table.model()
        if not isinstance(source_model, DictTableModel) or not source_model.rows:
            QMessageBox.information(self, title, "No rows are loaded.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.resize(*self._dialog_size(1180, 720))

        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        hint = QLabel("Expanded table view. Sort columns, select rows, or right-click to copy values.")
        hint.setObjectName("MutedLabel")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        fixed_widths = {
            idx: max(110, min(420, source_table.columnWidth(idx)))
            for idx in range(source_model.columnCount())
        }
        table = self._table(source_model.columns, fixed_widths=fixed_widths, stretch_columns=[])
        table.setMinimumHeight(520)
        table.verticalHeader().setDefaultSectionSize(max(34, source_table.verticalHeader().defaultSectionSize()))
        self._set_table(table, list(source_model.rows))
        layout.addWidget(table, 1)

        footer = QHBoxLayout()
        footer.addStretch()
        btn_close = QPushButton("Close")
        btn_close.setFixedHeight(34)
        btn_close.clicked.connect(dlg.accept)
        footer.addWidget(btn_close)
        layout.addLayout(footer)

        dlg.exec()

    def _format_pcap_time(self, value: Any) -> str:
        text = format_pcap_datetime(value)
        return text or "-"

    def _format_pcap_range(self, start: Any, end: Any) -> str:
        return f"{self._format_pcap_time(start)} - {self._format_pcap_time(end)}"

    def open_pcap_dialog(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP file",
            "",
            "Capture files (*.pcap *.pcapng);;All files (*.*)",
        )
        if file_path:
            self.load_pcap(file_path)

    def load_pcap(self, file_path: str):
        if self._thread is not None:
            QMessageBox.information(self, "PCAP", "PCAP analysis is already running.")
            return

        self.btn_open.setEnabled(False)
        self.btn_open.setText("Loading...")
        self.btn_export.setEnabled(False)
        self.btn_ai_summary.setEnabled(False)
        self.txt_pcap_ai_summary.clear()
        self.lbl_file.setText(file_path)
        self.lbl_stats.setText("Analyzing capture...")

        self._thread = QThread()
        self._worker = PcapWorker(file_path)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_loaded, Qt.QueuedConnection)
        self._worker.error.connect(self._on_error, Qt.QueuedConnection)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.error.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()

    def _on_loaded(self, summary: PcapSummary):
        self.summary = summary
        self._saved_source_id = None
        self.btn_export.setEnabled(True)
        self.btn_save_project.setEnabled(True)
        self.btn_save_project.setText("Save to Project")
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Summary")
        self.btn_add_notes.setEnabled(True)
        self.lbl_file.setText(summary.file_path)
        self.lbl_stats.setText(
            f"{summary.format} | Packets: {summary.packet_count:,} | "
            f"Volume: {human_bytes(summary.wire_bytes, precision=2)} | "
            f"Period: {self._format_pcap_range(summary.first_seen, summary.last_seen)}"
        )
        investigator = build_investigator_view(summary)
        self._set_highlights(summary)
        self._set_investigator_text(investigator)
        self.chart_services.set_rows(
            self._service_chart_rows(investigator["service_rows"]),
            empty_text="No visible service groups were identified.",
        )
        self.chart_activity.set_rows(
            self._activity_chart_rows(investigator["activity_rows"]),
            empty_text="No hourly activity timeline is available.",
        )
        self.chart_visibility.set_rows(
            self._visibility_chart_rows(investigator["visibility_rows"]),
            empty_text="No visibility indicators are available.",
        )
        self.lbl_overview_text.setText(self._overview_text(summary))
        self._set_table(self.tbl_network_overview, self._network_overview_rows(summary))
        self._set_table(self.tbl_visible_metadata, self._visible_metadata_rows(summary))
        self._set_table(self.tbl_samples, summary.readable_samples)
        self._set_artifact_tables(summary.artifacts)
        self._set_table(self.tbl_connections, summary.flows)

    def refresh_current_view(self) -> None:
        if not self.summary:
            return
        summary = self.summary
        investigator = build_investigator_view(summary)
        self._set_highlights(summary)
        self._set_investigator_text(investigator)
        self.chart_services.set_rows(
            self._service_chart_rows(investigator["service_rows"]),
            empty_text="No visible service groups were identified.",
        )
        self.chart_activity.set_rows(
            self._activity_chart_rows(investigator["activity_rows"]),
            empty_text="No hourly activity timeline is available.",
        )
        self.chart_visibility.set_rows(
            self._visibility_chart_rows(investigator["visibility_rows"]),
            empty_text="No visibility indicators are available.",
        )
        self.lbl_overview_text.setText(self._overview_text(summary))
        self._set_table(self.tbl_network_overview, self._network_overview_rows(summary))
        self._set_table(self.tbl_visible_metadata, self._visible_metadata_rows(summary))
        self._set_table(self.tbl_samples, summary.readable_samples)
        self._set_artifact_tables(summary.artifacts)
        self._set_table(self.tbl_connections, summary.flows)

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
                "label": f"{label} - {example}" if example else label,
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
        for item in summary.dns_queries or []:
            rows.append({"type": "DNS query", "value": item.get("query"), "count": item.get("count")})
        for item in summary.tls_sni or []:
            rows.append({"type": "TLS SNI", "value": item.get("host"), "count": item.get("count")})
        for item in summary.http_hosts or []:
            rows.append({"type": "HTTP host", "value": item.get("host"), "count": item.get("count")})
        return rows

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
            f"Visible app/service indicators: {', '.join(services[:8]) if services else '-'}",
            f"Messaging/push-like indicators: {messaging_like}",
            f"Possible call/media indicators: {media_like}",
            "Classification is based on metadata such as host names, ports, protocol, duration and volume. It is an investigative indicator, not content proof.",
        ]
        self.lbl_highlights_brief.setText("\n".join(lines))
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
        if not isinstance(model, DictTableModel) or not model.rows:
            QMessageBox.information(self, "Communication indicators", "No communication indicators are loaded.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Communication indicators")
        dlg.resize(*self._dialog_size(1180, 720))

        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        hint = QLabel("Metadata-based communication indicators. Sort columns, select rows, or right-click to copy values.")
        hint.setObjectName("MutedLabel")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        table = self._table(
            self.communication_full_columns,
            fixed_widths=self.communication_full_fixed_widths,
            stretch_columns=[3],
        )
        table.setMinimumWidth(980)
        table.verticalHeader().setDefaultSectionSize(42)
        self._set_table(table, list(model.rows))

        detail = QTextEdit()
        detail.setReadOnly(True)
        detail.setMinimumWidth(320)
        detail.setPlaceholderText("Select a communication indicator to see the evidence used for classification.")

        def update_detail(current: QModelIndex, previous: QModelIndex | None = None) -> None:
            table_model = table.model()
            if not isinstance(table_model, DictTableModel) or not current.isValid():
                detail.clear()
                return
            if current.row() < 0 or current.row() >= len(table_model.rows):
                detail.clear()
                return
            detail.setPlainText(self._communication_detail_text(table_model.rows[current.row()]))

        table.selectionModel().currentRowChanged.connect(update_detail)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(table)
        splitter.addWidget(self._group("Selected indicator evidence", detail))
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 1)
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        layout.addWidget(splitter, 1)
        table.selectRow(0)

        footer = QHBoxLayout()
        footer.addStretch()
        btn_close = QPushButton("Close")
        btn_close.setFixedHeight(34)
        btn_close.clicked.connect(dlg.accept)
        footer.addWidget(btn_close)
        layout.addLayout(footer)

        dlg.exec()

    def _on_error(self, message: str):
        QMessageBox.critical(self, "PCAP analysis failed", message)
        self.lbl_stats.setText("PCAP analysis failed.")

    def _cleanup_thread(self):
        self.btn_open.setEnabled(True)
        self.btn_open.setText("Open PCAP")
        self._worker = None
        self._thread = None

    def _set_table(self, table: QTableView, rows: list[dict[str, Any]]):
        model = table.model()
        if isinstance(model, DictTableModel):
            model.set_rows(rows)
            section = table.horizontalHeader().sortIndicatorSection()
            order = table.horizontalHeader().sortIndicatorOrder()
            if table.isSortingEnabled() and section >= 0:
                model.sort(section, order)

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
            "PCAP Investigation Overview",
            "",
            f"File: {summary.file_name}",
            f"Format: {summary.format}",
            f"Packets: {summary.packet_count:,}",
            f"Traffic volume: {human_bytes(summary.wire_bytes, precision=2)}",
            f"Capture period: {self._format_pcap_range(summary.first_seen, summary.last_seen)}",
            f"Device IP: {summary.likely_device_ip or '-'}",
            "",
            "What is visible:",
            f"- DNS queries: {len(summary.dns_queries)} unique visible names",
            f"- TLS SNI hosts: {len(summary.tls_sni)} unique visible host names",
            f"- HTTP cleartext hosts: {len(summary.http_hosts)} unique hosts",
            f"- Readable payload samples: {len(summary.readable_samples)}",
            "",
            "Important limitation:",
            "Encrypted HTTPS, QUIC and application traffic content is not readable from packet capture alone. "
            "ViaNyquist shows the observable metadata and only the payload bytes that are actually visible.",
        ]
        return "\n".join(lines)

    def _set_investigator_text(self, investigator: dict[str, Any]) -> None:
        summary = str(investigator.get("plain_summary") or "")
        self.lbl_plain_summary.setText(summary)

        key_points = "\n".join(f"- {point}" for point in (investigator.get("key_points") or [])[:4])
        self.lbl_key_points.setText(f"Key points:\n{key_points}" if key_points else "")
        limitations = "\n".join(f"- {item}" for item in (investigator.get("limitations") or [])[:2])
        self.lbl_limitations.setText(f"Limitations:\n{limitations}" if limitations else "")

    def generate_ai_summary(self):
        if not self.summary:
            self._info("PCAP AI", "Open a PCAP file first.")
            return
        if not hasattr(self.app, "ai_service"):
            self._error("PCAP AI", "AI service is not available.")
            return
        if self._ai_thread is not None:
            self._info("PCAP AI", "PCAP AI summary is already running.")
            return

        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary.setText("Generating...")
        self.txt_pcap_ai_summary.setPlainText("Generating PCAP AI summary...")
        if hasattr(self, "ai_summary_tab"):
            self.tabs.setCurrentWidget(self.ai_summary_tab)

        project_name = getattr(self.app, "current_project_name", "") or ""
        self._ai_thread = QThread()
        self._ai_worker = AITextWorker(
            self.app.ai_service.generate_pcap_summary,
            self.summary,
            project_name,
        )
        self._ai_worker.moveToThread(self._ai_thread)
        self._ai_thread.started.connect(self._ai_worker.run)
        self._ai_worker.finished.connect(self._on_ai_summary_finished, Qt.QueuedConnection)
        self._ai_worker.error.connect(self._on_ai_summary_error, Qt.QueuedConnection)
        self._ai_worker.finished.connect(self._ai_thread.quit)
        self._ai_worker.error.connect(self._ai_thread.quit)
        self._ai_thread.finished.connect(self._cleanup_ai_thread)
        self._ai_thread.start()

    def _on_ai_summary_finished(self, result: str):
        self.txt_pcap_ai_summary.setPlainText(result)
        if hasattr(self.app, "publish_ai_output"):
            self.app.publish_ai_output("PCAP", "PCAP AI Summary", result)
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Summary")

    def _on_ai_summary_error(self, message: str):
        self.txt_pcap_ai_summary.setPlainText(f"AI error: {message}")
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Summary")

    def _cleanup_ai_thread(self):
        if self._ai_worker is not None:
            self._ai_worker.deleteLater()
            self._ai_worker = None
        if self._ai_thread is not None:
            self._ai_thread.deleteLater()
            self._ai_thread = None

    def export_summary(self):
        if not self.summary:
            QMessageBox.information(self, "PCAP export", "Open a PCAP file first.")
            return

        default_name = Path(self.summary.file_name).with_suffix(".pcap-summary.html").name
        project = get_project(self._current_project_id()) if self._current_project_id() is not None else None
        default_path = (
            str(workspace_export_path(project.base_folder, default_name))
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
                report_language=get_app_settings().get("output_language", "hr"),
            )
            webbrowser.open(Path(file_path).resolve().as_uri())
        except Exception as exc:
            QMessageBox.critical(self, "PCAP export failed", str(exc))

    def save_to_project(self):
        if not self.summary:
            self._info("PCAP", "Open a PCAP file first.")
            return

        project_id = self._current_project_id()
        if project_id is None:
            self._info(
                "PCAP",
                "Open an active project first.",
                "PCAP analyses must be tied to a project before they can be used in notes or future activity profiles.",
            )
            return

        if not self._confirm_project_device_match(project_id):
            return

        try:
            digest = file_sha256(self.summary.file_path)
            investigator = build_investigator_view(self.summary)
            source_id = add_pcap_source(
                project_id,
                file_path=self.summary.file_path,
                file_name=self.summary.file_name,
                file_sha256_value=digest,
                file_size=self.summary.file_size,
                format=self.summary.format,
                packet_count=self.summary.packet_count,
                wire_bytes=self.summary.wire_bytes,
                first_seen=self.summary.first_seen,
                last_seen=self.summary.last_seen,
                duration_seconds=self.summary.duration_seconds,
                likely_device_ip=self.summary.likely_device_ip,
                summary_text=str(investigator.get("plain_summary") or ""),
            )
            bound_project_ip = self._bind_project_device_ip_if_empty(project_id)
        except Exception as exc:
            self._error("PCAP", "Failed to save PCAP analysis to project.", str(exc))
            return

        self._saved_source_id = source_id
        self.btn_save_project.setText("Saved to Project")
        if hasattr(self.app, "projects_ui_controller"):
            self.app.projects_ui_controller.sync_project_workspace(project_id)
        details = [f"Source id: {source_id}"]
        if bound_project_ip:
            details.append(f"Project known IP was set to: {bound_project_ip}")
        self._info("PCAP", "PCAP analysis saved to active project.", "\n".join(details))
        self._refresh_activity()

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
            existing = self.app.txt_notes.toPlainText() or ""
            if existing.strip():
                if not existing.endswith("\n"):
                    existing += "\n"
                new_text = existing + "\n" + block
            else:
                new_text = block

            self.app.txt_notes.setPlainText(new_text)
            self.app._notes_dirty = True
            self.app._flush_notes()
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
            for row in self.summary.communication_rows[:8]:
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
        current_ip = (self.summary.likely_device_ip if self.summary else "").strip()
        if not current_ip:
            return self._confirm(
                "PCAP",
                "Device IP could not be determined.",
                "The PCAP can still be saved, but ViaNyquist cannot compare it with previous PCAP sources in this project.",
                ok_text="Save anyway",
                cancel_text="Cancel",
            )

        project = get_project(project_id)
        project_ip = (project.subject_ip if project else "").strip()
        if project_ip and project_ip.casefold() != current_ip.casefold():
            ok = self._confirm(
                "PCAP project IP mismatch",
                "This PCAP likely describes a different device IP than the active project.",
                (
                    f"Project known IP: {project_ip}\n"
                    f"Current PCAP device IP: {current_ip}\n\n"
                    "Save only if this capture belongs to the same target/project or if the known project IP should be reviewed."
                ),
                ok_text="Save anyway",
                cancel_text="Cancel",
            )
            if not ok:
                return False

        previous_ips = [ip for ip in list_project_pcap_device_ips(project_id) if ip and ip != current_ip]
        if not previous_ips:
            return True

        return self._confirm(
            "PCAP device mismatch",
            "This PCAP appears to describe a different device IP than previous PCAP sources in this project.",
            (
                f"Current device IP: {current_ip}\n"
                f"Previous project PCAP device IPs: {', '.join(previous_ips[:8])}\n\n"
                "Save only if this capture belongs to the same target/project."
            ),
            ok_text="Save anyway",
            cancel_text="Cancel",
        )

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
        if hasattr(self.app, "refresh_activity_ui"):
            self.app.refresh_activity_ui()
