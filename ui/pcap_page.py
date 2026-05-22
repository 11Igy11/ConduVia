from __future__ import annotations

import hashlib
import os
import re
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QThread, QTimer, Qt, Signal
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

from core.exporters.listing_exporter import export_listing_csv, export_listing_excel
from core.exporters.pcap_exporter import export_pcap_summary_html
from core.exporters.table_exporter import export_table_html
from core.formatters import format_duration_compact_ms, format_pcap_datetime, human_bytes
from core.evidence_policy import format_period_day_label, period_combo_label
from core.pcap_analyzer import PcapSummary, analyze_pcap, analyze_pcap_files, build_investigator_view
from core.pcap_period import aggregate_hash_for_paths, capture_span_note, resolve_period_day
from core.protocols import format_ip_proto
from core.workspace import workspace_export_path
from core.db import (
    add_activity,
    add_pcap_source,
    file_sha256,
    save_pcap_period_summary,
    get_app_settings,
    get_project,
    list_project_pcap_device_ips,
    mark_ingest_item,
    set_project_subject,
    upsert_ingest_items,
)
from ui.activity_profile_page import BarChartWidget
from ui.explore_widgets import AITextWorker, CopyableTableView


class PcapWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, path: str | list[str], *, label: str = ""):
        super().__init__()
        self.path = path
        self.label = label

    def run(self):
        try:
            if isinstance(self.path, list):
                self.finished.emit(analyze_pcap_files(self.path, label=self.label))
            else:
                self.finished.emit(analyze_pcap(self.path))
        except Exception as exc:
            self.error.emit(str(exc))


class PcapBatchWorker(QObject):
    progress = Signal(int, int, int, str)
    finished = Signal(object, int, int)

    def __init__(
        self,
        paths: list[str],
        *,
        project_id: int | None = None,
        auto_save: bool = False,
        day_groups: dict[str, list[str]] | None = None,
    ):
        super().__init__()
        self.paths = [str(path) for path in paths if str(path or "").strip()]
        self.project_id = project_id
        self.auto_save = bool(auto_save)
        self.day_groups = {
            str(day): [str(path) for path in day_paths if str(path or "").strip()]
            for day, day_paths in (day_groups or {}).items()
            if str(day or "").strip() and day != "undated"
        }
        self.stop_requested = False

    def request_stop(self) -> None:
        self.stop_requested = True

    def run(self) -> None:
        processed = 0
        failed = 0
        last_summary = None

        jobs: list[tuple[str, list[str]]] = []
        if self.day_groups:
            for day, day_paths in sorted(self.day_groups.items(), key=lambda pair: pair[0]):
                jobs.append((day, day_paths))
        else:
            jobs.append(("", self.paths))

        total = sum(len(paths) for _day, paths in jobs)

        for period_day, day_paths in jobs:
            if self.stop_requested:
                break
            if not day_paths:
                continue

            if len(day_paths) > 1 or period_day:
                self.progress.emit(processed, total, failed, f"{format_period_day_label(period_day) or 'batch'}")
                try:
                    label = (
                        f"{format_period_day_label(period_day)} ({len(day_paths):,} PCAP files)"
                        if period_day
                        else f"{len(day_paths):,} PCAP files"
                    )
                    summary = analyze_pcap_files(day_paths, label=label)
                    last_summary = summary
                    if self.auto_save and self.project_id is not None:
                        self._save_period_summary(summary, period_day, day_paths)
                    processed += len(day_paths)
                except Exception as exc:
                    failed += len(day_paths)
                    processed += len(day_paths)
                    if self.project_id is not None:
                        for path in day_paths:
                            try:
                                mark_ingest_item(self.project_id, path, "failed", str(exc))
                            except Exception:
                                pass
                self.progress.emit(processed, total, failed, Path(day_paths[-1]).name)
                continue

            for path in day_paths:
                if self.stop_requested:
                    break

                self.progress.emit(processed, total, failed, Path(path).name)
                try:
                    summary = analyze_pcap(path)
                    last_summary = summary
                    if self.auto_save and self.project_id is not None:
                        self._save_file_summary(summary, path)
                    processed += 1
                    self.progress.emit(processed, total, failed, Path(path).name)
                except Exception as exc:
                    failed += 1
                    processed += 1
                    if self.project_id is not None:
                        try:
                            mark_ingest_item(self.project_id, path, "failed", str(exc))
                        except Exception:
                            pass
                    self.progress.emit(processed, total, failed, Path(path).name)

        self.finished.emit(last_summary, processed, failed)

    def _save_period_summary(self, summary: PcapSummary, period_day: str, source_paths: list[str]) -> None:
        day = resolve_period_day(
            active_day=period_day,
            file_paths=source_paths,
            first_seen=summary.first_seen,
            last_seen=summary.last_seen,
        )
        digest = aggregate_hash_for_paths(source_paths)
        investigator = build_investigator_view(summary)
        plain = str(investigator.get("plain_summary") or "")
        span = capture_span_note(summary.first_seen, summary.last_seen, period_day=day)
        if span:
            plain = f"{plain}\n{span}"
        save_pcap_period_summary(
            self.project_id,
            period_day=day,
            file_path=summary.file_path or summary.file_name,
            file_sha256_value=digest,
            file_size=summary.file_size,
            file_name=summary.file_name,
            format=summary.format,
            packet_count=summary.packet_count,
            wire_bytes=summary.wire_bytes,
            first_seen=summary.first_seen,
            last_seen=summary.last_seen,
            duration_seconds=summary.duration_seconds,
            likely_device_ip=summary.likely_device_ip,
            summary_text=plain,
        )
        self._mark_paths_done(source_paths)

    def _save_file_summary(self, summary: PcapSummary, source_path: str) -> None:
        digest = file_sha256(source_path)
        day = resolve_period_day(
            file_paths=[source_path],
            first_seen=summary.first_seen,
            last_seen=summary.last_seen,
        )
        investigator = build_investigator_view(summary)
        add_pcap_source(
            self.project_id,
            file_path=source_path,
            file_name=summary.file_name,
            file_sha256_value=digest,
            file_size=summary.file_size,
            format=summary.format,
            packet_count=summary.packet_count,
            wire_bytes=summary.wire_bytes,
            first_seen=summary.first_seen,
            last_seen=summary.last_seen,
            duration_seconds=summary.duration_seconds,
            likely_device_ip=summary.likely_device_ip,
            summary_text=str(investigator.get("plain_summary") or ""),
            period_day=day,
        )
        mark_ingest_item(self.project_id, source_path, "done", "")

    def _mark_paths_done(self, source_paths: list[str]) -> None:
        for path in source_paths:
            mark_ingest_item(self.project_id, str(path), "done", "")


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
        self._batch_thread: QThread | None = None
        self._batch_worker: PcapBatchWorker | None = None
        self._ai_thread: QThread | None = None
        self._ai_worker: AITextWorker | None = None
        self._saved_source_id: int | None = None
        self._pcap_queue: list[str] = []
        self._pcap_queue_auto_save = False
        self._pcap_queue_auto_process = False
        self._pcap_batch_total = 0
        self._pcap_batch_processed = 0
        self._pcap_batch_failed = 0
        self._pcap_batch_stop_after_current = False
        self._pcap_day_groups: dict[str, list[str]] = {}
        self._pcap_active_day = ""
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
        self.btn_save_project = QPushButton("Save Period to Project")
        self.btn_save_all_periods = QPushButton("Save All Periods")
        self.btn_save_all_periods.setEnabled(False)
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
        top.addWidget(self.btn_save_all_periods)
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

        self.batch_status_panel = QFrame()
        self.batch_status_panel.setObjectName("InlinePanel")
        batch_layout = QHBoxLayout(self.batch_status_panel)
        batch_layout.setContentsMargins(10, 8, 10, 8)
        batch_layout.setSpacing(10)
        self.lbl_batch_status = QLabel("")
        self.lbl_batch_status.setObjectName("MutedLabel")
        self.lbl_pcap_day = QLabel("Period:")
        self.lbl_pcap_day.setObjectName("MutedLabel")
        self.cmb_pcap_day = QComboBox()
        self.cmb_pcap_day.setMinimumWidth(230)
        self.lbl_pcap_day.setVisible(False)
        self.cmb_pcap_day.setVisible(False)
        self.btn_stop_batch = QPushButton("Stop after current")
        self.btn_stop_batch.setFixedHeight(32)
        batch_layout.addWidget(self.lbl_pcap_day)
        batch_layout.addWidget(self.cmb_pcap_day)
        batch_layout.addWidget(self.lbl_batch_status, 1)
        batch_layout.addWidget(self.btn_stop_batch)
        self.batch_status_panel.setVisible(False)
        header_layout.addWidget(self.batch_status_panel)
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
        self.btn_save_all_periods.clicked.connect(self.save_all_periods_to_project)
        self.btn_ai_summary.clicked.connect(self.generate_ai_summary)
        self.btn_add_notes.clicked.connect(self.add_summary_to_notes)
        self.btn_export.clicked.connect(self.export_summary)
        self.btn_stop_batch.clicked.connect(self.stop_after_current_batch)
        self.cmb_pcap_day.currentIndexChanged.connect(self._on_pcap_day_changed)

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
        layout.setContentsMargins(14, 14, 14, 14)
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
        self.btn_expand_communications.setFixedHeight(38)
        self.btn_expand_communications.clicked.connect(self._open_communications_dialog)

        brief_group = self._group("Investigation brief", self.lbl_highlights_brief)
        brief_group.setMaximumHeight(145)

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
        layout.addStretch()

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
        self.chart_services.set_rows([], empty_text="Open a PCAP file to show visible service groups.")
        self.chart_activity.set_rows([], empty_text="Open a PCAP file to show hourly packet activity.")
        self.chart_visibility.set_rows([], empty_text="Open a PCAP file to show readable vs encrypted indicators.")

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
        self.tbl_network_overview.hide()
        self.btn_expand_network_overview = QPushButton("Open full network table")
        self.btn_expand_network_overview.setFixedHeight(38)
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
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
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

        self.btn_expand_metadata = QPushButton("Open full metadata table")
        self.btn_expand_metadata.setFixedHeight(38)
        self.btn_expand_metadata.clicked.connect(
            lambda: self._open_table_dialog("Visible metadata", self.tbl_visible_metadata)
        )

        self.btn_expand_samples = QPushButton("Open full samples table")
        self.btn_expand_samples.setFixedHeight(38)
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

        workflow_hint = QLabel(
            "Use the full table view for investigation work: sorting, copying values and reading wide columns. "
            "The embedded Evidence page is intentionally a compact overview."
        )
        workflow_hint.setObjectName("MutedLabel")
        workflow_hint.setWordWrap(True)
        workflow_hint.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(workflow_hint)
        layout.addStretch()
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
        layout = QVBoxLayout(card)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(10)

        lbl_title = QLabel(title)
        lbl_title.setObjectName("SectionTitle")
        lbl_title.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lbl_description = QLabel(description)
        lbl_description.setObjectName("MutedLabel")
        lbl_description.setWordWrap(True)
        lbl_description.setTextInteractionFlags(Qt.TextSelectableByMouse)

        layout.addWidget(lbl_title)
        layout.addWidget(lbl_description)
        layout.addWidget(count_label)
        layout.addWidget(detail_label)
        layout.addStretch()
        layout.addWidget(button, 0, Qt.AlignRight)
        return card

    def _build_artifacts_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(14)

        controls = QHBoxLayout()
        controls.setSpacing(10)
        controls.addWidget(QLabel("Category"))
        self.cmb_artifact_category = QComboBox()
        self.cmb_artifact_category.setMinimumWidth(240)
        self.cmb_artifact_category.currentIndexChanged.connect(self._apply_artifact_filter)
        self.lbl_artifact_count = QLabel("")
        self.lbl_artifact_count.setObjectName("MutedLabel")
        self.btn_expand_artifacts = QPushButton("Open full artifacts table")
        self.btn_expand_artifacts.setFixedHeight(38)
        self.btn_expand_artifacts.clicked.connect(
            lambda: self._open_table_dialog("Extracted artifacts", self.tbl_artifacts)
        )
        controls.addWidget(self.cmb_artifact_category)
        controls.addWidget(self.lbl_artifact_count)
        controls.addStretch()
        controls.addWidget(self.btn_expand_artifacts)

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
        self.lbl_artifact_breakdown = QLabel("No artifact categories loaded.")
        self.lbl_artifact_breakdown.setObjectName("MutedLabel")
        self.lbl_artifact_breakdown.setWordWrap(True)
        self.lbl_artifact_breakdown.setTextInteractionFlags(Qt.TextSelectableByMouse)

        layout.addLayout(controls)
        layout.addWidget(
            self._evidence_launcher_card(
                "Extracted artifacts",
                "Visible web, local network, credential and Windows/enterprise indicators extracted from readable capture data.",
                self.lbl_artifact_total,
                self.lbl_artifact_breakdown,
                self.btn_expand_artifacts,
            ),
            0,
        )
        layout.addStretch()
        return page

    def _build_connections_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(14)

        self.btn_expand_connections = QPushButton("Open full connections table")
        self.btn_expand_connections.setFixedHeight(38)
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
            idx: self._expanded_column_width(source_model.columns[idx], source_table.columnWidth(idx))
            for idx in range(source_model.columnCount())
        }
        table = self._table(source_model.columns, fixed_widths=fixed_widths, stretch_columns=[])
        table.setMinimumHeight(520)
        table.verticalHeader().setDefaultSectionSize(max(34, source_table.verticalHeader().defaultSectionSize()))
        self._set_table(table, list(source_model.rows))
        layout.addWidget(table, 1)

        footer = QHBoxLayout()
        footer.addWidget(self._export_button("Export CSV", title, table, "csv"))
        footer.addWidget(self._export_button("Export Excel", title, table, "xlsx"))
        footer.addWidget(self._export_button("Export HTML", title, table, "html"))
        footer.addStretch()
        btn_close = QPushButton("Close")
        btn_close.setFixedHeight(34)
        btn_close.clicked.connect(dlg.accept)
        footer.addWidget(btn_close)
        layout.addLayout(footer)

        dlg.exec()

    def _export_button(self, text: str, title: str, table: QTableView, export_format: str) -> QPushButton:
        button = QPushButton(text)
        button.setFixedHeight(34)
        button.clicked.connect(lambda: self._export_table_dialog(title, table, export_format))
        return button

    def _table_export_data(self, table: QTableView) -> tuple[list[str], list[list[str]]]:
        model = table.model()
        if not isinstance(model, DictTableModel):
            return [], []

        headers = [title for _, title in model.columns]
        rows = [
            ["" if row.get(key) is None else str(row.get(key)) for key, _ in model.columns]
            for row in model.rows
        ]
        return headers, rows

    def _table_export_default_path(self, title: str, suffix: str) -> str:
        safe_title = "".join(ch if ch.isalnum() else "_" for ch in (title or "pcap_table").lower())
        safe_title = "_".join(part for part in safe_title.split("_") if part) or "pcap_table"
        base_name = f"{safe_title}.{suffix}"
        project = get_project(self._current_project_id()) if self._current_project_id() is not None else None
        if project and project.base_folder:
            return str(workspace_export_path(project.base_folder, base_name, category="pcap"))
        return base_name

    def _export_table_dialog(self, title: str, table: QTableView, export_format: str) -> None:
        headers, rows = self._table_export_data(table)
        if not headers or not rows:
            QMessageBox.information(self, "Export table", "No rows are loaded.")
            return

        filters = {
            "csv": "CSV files (*.csv)",
            "xlsx": "Excel files (*.xlsx)",
            "html": "HTML files (*.html)",
        }
        suffix = "xlsx" if export_format == "xlsx" else export_format
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {title}",
            self._table_export_default_path(title, suffix),
            filters.get(export_format, "All files (*.*)"),
        )
        if not file_path:
            return

        try:
            if export_format == "csv":
                export_listing_csv(file_path, headers, rows)
            elif export_format == "xlsx":
                export_listing_excel(file_path, headers, rows)
            elif export_format == "html":
                self._write_table_html(file_path, title, headers, rows)
            else:
                raise ValueError(f"Unsupported export format: {export_format}")
        except Exception as exc:
            QMessageBox.critical(self, "Export table failed", str(exc))
            return

        QMessageBox.information(self, "Export table", f"Exported:\n{file_path}")

    def _write_table_html(self, file_path: str, title: str, headers: list[str], rows: list[list[str]]) -> None:
        export_table_html(file_path, title, headers, rows)

    def _expanded_column_width(self, column: tuple[str, str], current_width: int) -> int:
        key, title = column
        name = f"{key} {title}".lower()
        preferred = 140
        if "time" in name or "seen" in name:
            preferred = 190
        if "source" in name or "destination" in name or "endpoint" in name:
            preferred = 210
        if "host" in name or "signal" in name or "query" in name:
            preferred = 300
        if "value" in name or "evidence" in name or "detail" in name:
            preferred = 380
        if "packet" in name or "count" in name or "port" in name:
            preferred = 120
        return max(preferred, max(110, min(440, current_width)))

    def _format_pcap_time(self, value: Any) -> str:
        text = format_pcap_datetime(value)
        return text or "-"

    def _format_pcap_range(self, start: Any, end: Any) -> str:
        return f"{self._format_pcap_time(start)} - {self._format_pcap_time(end)}"

    def open_pcap_dialog(self):
        if not self._ensure_project_workspace():
            return

        if self._pcap_queue and self._thread is None:
            self._load_next_queued_pcap()
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
    ) -> None:
        paths = [str(path) for path in (file_paths or []) if str(path or "").strip()]
        if not paths:
            return

        grouped_day = False
        if day_groups:
            paths = self._set_day_groups(day_groups) or paths
            grouped_day = bool(self._pcap_day_groups)
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
        self._pcap_batch_stop_after_current = False
        if grouped_day and len(paths) > 1:
            label = f"{self._format_day_label(self._pcap_active_day)} ({len(paths):,} PCAP files)"
            self._update_batch_status(label)
            self._load_pcap_files(paths, label=label)
        else:
            self._update_batch_status(Path(paths[0]).name)
            self._load_pcap_file(paths[0])

    def _start_auto_pcap_batch(self, paths: list[str], *, auto_save: bool) -> None:
        if self._thread is not None or self._batch_thread is not None:
            QMessageBox.information(self, "PCAP", "PCAP analysis is already running.")
            return

        project_id = self._current_project_id()
        self._pcap_queue = []
        self._pcap_queue_auto_save = bool(auto_save)
        self._pcap_queue_auto_process = True
        self._pcap_batch_total = len(paths)
        self._pcap_batch_processed = 0
        self._pcap_batch_failed = 0
        self._pcap_batch_stop_after_current = False

        self.btn_open.setEnabled(False)
        self.btn_open.setText("Loading...")
        self.btn_export.setEnabled(False)
        self.btn_ai_summary.setEnabled(False)
        self.btn_save_project.setEnabled(False)
        self.btn_add_notes.setEnabled(False)
        self.lbl_file.setText(Path(paths[0]).name)
        self.lbl_stats.setText("Auto analyzing PCAP batch...")
        self.lbl_stats.setObjectName("PcapLoadingStatus")
        self._refresh_widget_style(self.lbl_stats)
        self._update_batch_status(Path(paths[0]).name)

        self._batch_thread = QThread()
        self._batch_worker = PcapBatchWorker(
            paths,
            project_id=project_id,
            auto_save=auto_save,
            day_groups=self._pcap_day_groups or None,
        )
        self._batch_worker.moveToThread(self._batch_thread)
        self._batch_thread.started.connect(self._batch_worker.run)
        self._batch_worker.progress.connect(self._on_batch_progress, Qt.QueuedConnection)
        self._batch_worker.finished.connect(self._on_batch_finished, Qt.QueuedConnection)
        self._batch_worker.finished.connect(self._batch_thread.quit)
        self._batch_worker.finished.connect(self._batch_worker.deleteLater)
        self._batch_thread.finished.connect(self._batch_thread.deleteLater)
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

    def _set_day_groups(self, day_groups: dict[str, list[str]]) -> list[str]:
        cleaned = {
            str(day): [str(path) for path in paths if str(path or "").strip()]
            for day, paths in (day_groups or {}).items()
        }
        cleaned = {day: paths for day, paths in cleaned.items() if paths}
        self._pcap_day_groups = dict(sorted(cleaned.items(), key=lambda pair: (pair[0] == "undated", pair[0])))
        if not self._pcap_day_groups:
            self._clear_day_groups()
            return []

        self.cmb_pcap_day.blockSignals(True)
        self.cmb_pcap_day.clear()
        for day, paths in self._pcap_day_groups.items():
            self.cmb_pcap_day.addItem(period_combo_label(day, len(paths), kind="PCAP"), day)
        self.cmb_pcap_day.blockSignals(False)
        self.lbl_pcap_day.setVisible(True)
        self.cmb_pcap_day.setVisible(True)
        if hasattr(self, "btn_save_all_periods"):
            self.btn_save_all_periods.setEnabled(True)
        self._pcap_active_day = self.cmb_pcap_day.currentData() or next(iter(self._pcap_day_groups))
        return list(self._pcap_day_groups.get(self._pcap_active_day, []))

    def _clear_day_groups(self) -> None:
        self._pcap_day_groups = {}
        self._pcap_active_day = ""
        if hasattr(self, "cmb_pcap_day"):
            self.cmb_pcap_day.blockSignals(True)
            self.cmb_pcap_day.clear()
            self.cmb_pcap_day.blockSignals(False)
            self.cmb_pcap_day.setVisible(False)
        if hasattr(self, "lbl_pcap_day"):
            self.lbl_pcap_day.setVisible(False)
        if hasattr(self, "btn_save_all_periods"):
            self.btn_save_all_periods.setEnabled(False)

    def _on_pcap_day_changed(self, index: int) -> None:
        if index < 0 or not self._pcap_day_groups:
            return
        if self._thread is not None or self._batch_thread is not None:
            return
        day = str(self.cmb_pcap_day.itemData(index) or "")
        paths = list(self._pcap_day_groups.get(day, []))
        if not paths:
            return
        self._pcap_active_day = day
        self._pcap_queue = []
        self._pcap_batch_total = len(paths)
        self._pcap_batch_processed = 0
        self._pcap_batch_failed = 0
        self._pcap_batch_stop_after_current = False
        self._update_batch_status(f"{self._format_day_label(day)} aggregate")
        self._load_pcap_files(paths, label=f"{self._format_day_label(day)} ({len(paths):,} PCAP files)")

    def _format_day_label(self, day: str) -> str:
        return format_period_day_label(day)

    def _load_pcap_file(self, file_path: str):
        self._load_pcap_files([file_path], label="")

    def _load_pcap_files(self, file_paths: list[str], *, label: str = ""):
        if not self._ensure_project_workspace():
            return

        if self._thread is not None:
            QMessageBox.information(self, "PCAP", "PCAP analysis is already running.")
            return
        paths = [str(path) for path in file_paths if str(path or "").strip()]
        if not paths:
            return

        self.btn_open.setEnabled(False)
        self.btn_open.setText("Loading...")
        self.btn_export.setEnabled(False)
        self.btn_ai_summary.setEnabled(False)
        self.txt_pcap_ai_summary.clear()
        if len(paths) == 1:
            self.lbl_file.setText(paths[0])
            current_text = Path(paths[0]).name
        else:
            self.lbl_file.setText(label or f"{len(paths):,} PCAP files")
            current_text = label or f"{len(paths):,} PCAP files"
        self.lbl_stats.setText("Analyzing capture..." if len(paths) == 1 else f"Analyzing {len(paths):,} PCAP files for selected day...")
        self.lbl_stats.setObjectName("PcapLoadingStatus")
        self._refresh_widget_style(self.lbl_stats)
        self._update_batch_status(current_text)

        self._thread = QThread()
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
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()

    def _on_loaded(self, summary: PcapSummary):
        self._render_loaded_summary(summary)
        if self._pcap_queue_auto_save:
            saved = self._save_current_to_project(show_dialog=False, check_device=False, refresh_ui=False)
            self._mark_current_ingest("done" if saved else "failed", "" if saved else "Auto-save failed.")
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
        source_count = len(getattr(summary, "source_paths", None) or [])
        self.btn_save_project.setEnabled(True)
        if source_count > 1:
            self.btn_save_project.setText("Save Period to Project")
            self.btn_save_all_periods.setEnabled(bool(self._pcap_day_groups))
            self.btn_save_project.setToolTip(
                "Save this daily aggregate to the project profile. The source files remain indexed individually."
            )
        else:
            self.btn_save_project.setText("Save Period to Project")
            self.btn_save_project.setToolTip("")
            self.btn_save_all_periods.setEnabled(bool(self._pcap_day_groups))
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Summary")
        self.btn_add_notes.setEnabled(True)
        if source_count > 1:
            self.lbl_file.setText(f"{summary.file_name} | Aggregated from {source_count:,} PCAP files")
        else:
            self.lbl_file.setText(summary.file_path)
        self.lbl_stats.setObjectName("HeaderStatLabel")
        self._refresh_widget_style(self.lbl_stats)
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
        self._set_network_overview_table(summary)
        self._set_evidence_tables(summary)
        self._set_artifact_tables(summary.artifacts)
        self._set_connections_table(summary)

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
        self._set_network_overview_table(summary)
        self._set_evidence_tables(summary)
        self._set_artifact_tables(summary.artifacts)
        self._set_connections_table(summary)

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

    def _set_evidence_tables(self, summary: PcapSummary) -> None:
        metadata_rows = self._visible_metadata_rows(summary)
        sample_rows = summary.readable_samples or []
        self._set_table(self.tbl_visible_metadata, metadata_rows)
        self._set_table(self.tbl_samples, sample_rows)

        self.lbl_visible_metadata_count.setText(f"{len(metadata_rows):,} visible rows")
        self.lbl_visible_metadata_breakdown.setText(
            f"DNS: {len(summary.dns_queries or []):,} | "
            f"TLS SNI: {len(summary.tls_sni or []):,} | "
            f"HTTP hosts: {len(summary.http_hosts or []):,}"
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
        self.lbl_connections_count.setText(f"{len(rows):,} connections")
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
            f"Visible app/service indicators: {', '.join(services[:8]) if services else '-'}",
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
        footer.addWidget(self._export_button("Export CSV", "Communication indicators", table, "csv"))
        footer.addWidget(self._export_button("Export Excel", "Communication indicators", table, "xlsx"))
        footer.addWidget(self._export_button("Export HTML", "Communication indicators", table, "html"))
        footer.addStretch()
        btn_close = QPushButton("Close")
        btn_close.setFixedHeight(34)
        btn_close.clicked.connect(dlg.accept)
        footer.addWidget(btn_close)
        layout.addLayout(footer)

        dlg.exec()

    def _on_error(self, message: str):
        if not self._pcap_queue_auto_process:
            QMessageBox.critical(self, "PCAP analysis failed", message)
        self.lbl_stats.setObjectName("HeaderStatLabel")
        self._refresh_widget_style(self.lbl_stats)
        self.lbl_stats.setText("PCAP analysis failed.")
        self._pcap_batch_failed += 1
        self._pcap_batch_processed += 1
        if self._pcap_queue_auto_save:
            self._mark_current_ingest("failed", message)
        self._update_batch_status(error_text=message)

    def _on_batch_progress(self, processed: int, total: int, failed: int, current_file: str) -> None:
        self._pcap_batch_processed = processed
        self._pcap_batch_total = total
        self._pcap_batch_failed = failed
        if current_file:
            self.lbl_file.setText(current_file)
        self._update_batch_status(current_file)

    def _on_batch_finished(self, last_summary: object, processed: int, failed: int) -> None:
        self._pcap_batch_processed = processed
        self._pcap_batch_failed = failed
        self._pcap_queue_auto_process = False
        self._pcap_queue = []

        self.btn_open.setEnabled(True)
        self.btn_save_project.setEnabled(bool(last_summary))
        self.btn_export.setEnabled(bool(last_summary))
        self.btn_ai_summary.setEnabled(bool(last_summary))
        self.btn_add_notes.setEnabled(bool(last_summary))
        self._update_open_button_text()

        self.lbl_stats.setObjectName("HeaderStatLabel")
        self._refresh_widget_style(self.lbl_stats)
        if isinstance(last_summary, PcapSummary):
            self._render_loaded_summary(last_summary)
            if self._pcap_queue_auto_save:
                self.btn_save_project.setText("Saved to Project")
        else:
            self.lbl_stats.setText("PCAP batch finished, but no capture was analyzed successfully.")

        self._pcap_queue_auto_save = False
        self._pcap_batch_stop_after_current = False
        self._update_batch_status()
        self._refresh_project_after_batch()

    def _cleanup_thread(self):
        self.btn_open.setEnabled(True)
        self._update_open_button_text()
        if not self._pcap_queue:
            self._pcap_queue_auto_save = False
            self._pcap_queue_auto_process = False
            self._pcap_batch_stop_after_current = False
            self._update_batch_status()
        self._worker = None
        self._thread = None
        if self._pcap_batch_stop_after_current:
            self._pcap_queue_auto_process = False
            self._update_open_button_text()
            self._update_batch_status()
            return
        if self._pcap_queue_auto_process and self._pcap_queue:
            QTimer.singleShot(100, self._load_next_queued_pcap)

    def _cleanup_batch_thread(self):
        self._batch_worker = None
        self._batch_thread = None

    def _update_open_button_text(self) -> None:
        if self._pcap_queue:
            self.btn_open.setText(f"Open next PCAP ({len(self._pcap_queue)})")
        else:
            self.btn_open.setText("Open PCAP")

    def stop_after_current_batch(self) -> None:
        if self._batch_worker is not None:
            self._pcap_batch_stop_after_current = True
            self._batch_worker.request_stop()
            self.btn_stop_batch.setEnabled(False)
            self.btn_stop_batch.setText("Stopping...")
            self._update_batch_status()
            return

        if not self._pcap_queue:
            self._reset_batch_status()
            return
        self._pcap_batch_stop_after_current = True
        self._pcap_queue_auto_process = False
        self.btn_stop_batch.setEnabled(False)
        self.btn_stop_batch.setText("Stopping...")
        self._update_batch_status()

    def _reset_batch_status(self) -> None:
        self._pcap_batch_total = 0
        self._pcap_batch_processed = 0
        self._pcap_batch_failed = 0
        self._pcap_batch_stop_after_current = False
        if hasattr(self, "batch_status_panel"):
            self.batch_status_panel.setVisible(False)
        if hasattr(self, "btn_stop_batch"):
            self.btn_stop_batch.setEnabled(True)
            self.btn_stop_batch.setText("Stop after current")

    def _update_batch_status(self, current_file: str = "", error_text: str = "") -> None:
        if not hasattr(self, "batch_status_panel"):
            return

        has_batch = self._pcap_batch_total > 1 or bool(self._pcap_queue)
        if not has_batch:
            self.batch_status_panel.setVisible(False)
            return

        remaining = len(self._pcap_queue)
        mode = "Auto batch" if self._pcap_queue_auto_process else "Manual queue"
        if self._pcap_active_day:
            mode = f"{mode} | {self._format_day_label(self._pcap_active_day)}"
        parts = [
            f"{mode}: {self._pcap_batch_processed:,} / {self._pcap_batch_total:,} processed",
            f"{remaining:,} remaining",
        ]
        if self._pcap_batch_failed:
            parts.append(f"{self._pcap_batch_failed:,} failed")
        if current_file:
            parts.append(f"current: {current_file}")
        if self._pcap_batch_stop_after_current:
            parts.append("will stop after current file")
        if error_text:
            parts.append(f"last error: {error_text[:160]}")

        self.lbl_batch_status.setText(" | ".join(parts))
        self.btn_stop_batch.setVisible(self._pcap_queue_auto_process or self._pcap_batch_stop_after_current)
        self.btn_stop_batch.setEnabled(self._pcap_queue_auto_process and bool(self._pcap_queue))
        if not self._pcap_batch_stop_after_current:
            self.btn_stop_batch.setText("Stop after current")
        self.batch_status_panel.setVisible(True)

    def _mark_current_ingest(self, status: str, message: str = "") -> None:
        project_id = self._current_project_id()
        file_path = self.summary.file_path if self.summary else self.lbl_file.text()
        if project_id is None or not file_path:
            return
        try:
            mark_ingest_item(project_id, file_path, status, message)
        except Exception:
            pass

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
        if counts:
            top_categories = ", ".join(f"{category}: {count:,}" for category, count in sorted(counts.items())[:6])
        else:
            top_categories = "No artifact categories loaded."
        self.lbl_artifact_breakdown.setText(top_categories)
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

    def _refresh_widget_style(self, widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

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
                report_language=get_app_settings().get("output_language", "hr"),
            )
            webbrowser.open(Path(file_path).resolve().as_uri())
        except Exception as exc:
            QMessageBox.critical(self, "PCAP export failed", str(exc))

    def save_all_periods_to_project(self) -> None:
        if not self._pcap_day_groups:
            self._info("PCAP", "No period groups are loaded.", "Import a folder with a calendar date range first.")
            return
        if self._thread is not None or self._batch_thread is not None:
            self._info("PCAP", "PCAP analysis is already running.")
            return
        if not self._ensure_project_workspace():
            return

        project_id = self._current_project_id()
        if project_id is None:
            self._info("PCAP", "Open an active project first.")
            return

        total_files = sum(len(paths) for paths in self._pcap_day_groups.values())
        if not self.app._confirm_dialog(
            title="Save all PCAP periods",
            message=f"Analyze and save {len(self._pcap_day_groups):,} daily periods to the project?",
            details=(
                f"Total PCAP files: {total_files:,}\n"
                "Each calendar day is saved once to the project profile, matching the JSON period workflow."
            ),
            ok_text="Save all",
            cancel_text="Cancel",
            width=620,
        ):
            return

        all_paths = [path for paths in self._pcap_day_groups.values() for path in paths]
        self._start_auto_pcap_batch(all_paths, auto_save=True)

    def save_to_project(self):
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
        except Exception as exc:
            if show_dialog:
                self._error("PCAP", "Failed to save PCAP analysis to project.", str(exc))
            return False

        self._saved_source_id = source_id
        self.btn_save_project.setText("Saved to Project")
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
        project_id = self._current_project_id()
        if project_id is None:
            return
        if hasattr(self.app, "projects_ui_controller"):
            self.app.projects_ui_controller.sync_project_workspace(project_id)
            self.app.projects_ui_controller.refresh_recent_datasets(project_id)
            self.app.projects_ui_controller.refresh_case_dashboard(project_id)
        if hasattr(self.app, "refresh_activity_profile_ui"):
            self.app.refresh_activity_profile_ui()
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
        if hasattr(self.app, "refresh_activity_ui"):
            self.app.refresh_activity_ui()
