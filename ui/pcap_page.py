from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import Any

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QThread, Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
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
from core.formatters import format_duration_compact_ms, human_bytes
from core.pcap_analyzer import PcapSummary, analyze_pcap, build_investigator_view
from core.protocols import format_ip_proto


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

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        key = self.columns[index.column()][0]
        value = self.rows[index.row()].get(key, "")
        if key in ("protocol", "protocol_number") and isinstance(value, int):
            return format_ip_proto(value)
        if key in ("bytes", "bidirectional_bytes"):
            return human_bytes(value, precision=2)
        if key == "bidirectional_duration_ms":
            return format_duration_compact_ms(value)
        if key == "share":
            try:
                return f"{float(value):.1f}%"
            except Exception:
                return str(value)
        return "" if value is None else str(value)


class PcapPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.summary: PcapSummary | None = None
        self._thread: QThread | None = None
        self._worker: PcapWorker | None = None
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
        self.btn_export = QPushButton("Export Summary")
        self.btn_export.setEnabled(False)
        top.addWidget(self.lbl_title)
        top.addStretch()
        top.addWidget(self.btn_open)
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
        self.tabs.addTab(self._build_investigator_tab(), "Investigator View")
        self.tabs.addTab(self._build_overview_tab(), "Overview")
        self.tabs.addTab(self._build_evidence_tab(), "Evidence")
        self.tabs.addTab(self._build_connections_tab(), "Connections")
        root.addWidget(self.tabs, 1)

        self.btn_open.clicked.connect(self.open_pcap_dialog)
        self.btn_export.clicked.connect(self.export_summary)

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
        self.investigator_card.setMinimumHeight(220)
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

        self.tbl_services = self._table([
            ("service", "Service group"),
            ("count", "Signals"),
            ("share", "Share"),
            ("example", "Example"),
        ], fixed_widths={1: 88, 2: 78}, stretch_columns=[0, 3])
        self.tbl_visibility = self._table([
            ("label", "Visibility"),
            ("count", "Signals"),
            ("share", "Share"),
        ], fixed_widths={1: 88, 2: 78}, stretch_columns=[0])
        self.tbl_activity = self._table([
            ("hour", "Hour"),
            ("packets", "Packets"),
            ("share", "Share"),
        ], fixed_widths={0: 170, 1: 110, 2: 78}, stretch_columns=[])

        top = QHBoxLayout()
        top.setSpacing(10)
        self.grp_services = self._group("Visible service groups", self.tbl_services)
        self.grp_visibility = self._group("Visible vs encrypted indicators", self.tbl_visibility)
        self.grp_activity = self._group("Activity timeline by hour", self.tbl_activity)

        self.grp_services.setMinimumHeight(260)
        self.grp_visibility.setMinimumHeight(260)
        self.grp_activity.setMinimumHeight(280)

        top.addWidget(self.grp_services, 3)
        top.addWidget(self.grp_visibility, 2)

        layout.addWidget(self.investigator_card, 0)
        layout.addLayout(top, 2)
        layout.addWidget(self.grp_activity, 2)
        layout.addStretch()

        scroll.setWidget(content)
        page_layout.addWidget(scroll, 1)
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

        grid = QGridLayout()
        grid.setSpacing(10)
        self.tbl_protocols = self._table([("protocol", "Protocol"), ("number", "Number"), ("packets", "Packets")], stretch_columns=[0])
        self.tbl_endpoints = self._table([("ip", "Endpoint IP"), ("packets", "Packets")], stretch_columns=[0])
        self.tbl_ports = self._table([("protocol", "Protocol"), ("port", "Port"), ("packets", "Packets")], stretch_columns=[0])
        grp_protocols = self._group("Protocols", self.tbl_protocols)
        grp_endpoints = self._group("Top endpoints", self.tbl_endpoints)
        grp_ports = self._group("Top ports", self.tbl_ports)
        grp_protocols.setMinimumHeight(250)
        grp_endpoints.setMinimumHeight(250)
        grp_ports.setMinimumHeight(300)

        grid.addWidget(grp_protocols, 0, 0)
        grid.addWidget(grp_endpoints, 0, 1)
        grid.addWidget(grp_ports, 1, 0, 1, 2)

        layout.addWidget(self.overview_card)
        layout.addLayout(grid)
        layout.addStretch()

        scroll.setWidget(content)
        page_layout.addWidget(scroll, 1)
        return page

    def _build_evidence_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)

        self.tbl_dns = self._table([("query", "DNS Query"), ("count", "Count")], fixed_widths={1: 90}, stretch_columns=[0])
        self.tbl_sni = self._table([("host", "TLS SNI Host"), ("count", "Count")], fixed_widths={1: 90}, stretch_columns=[0])
        self.tbl_http = self._table([("host", "HTTP Host"), ("count", "Count")], fixed_widths={1: 90}, stretch_columns=[0])
        self.tbl_samples = self._table([
            ("time", "Time"),
            ("type", "Type"),
            ("source", "Source"),
            ("destination", "Destination"),
            ("value", "Visible Value"),
        ], fixed_widths={0: 178, 1: 130, 2: 190, 3: 190}, stretch_columns=[4])

        top = QSplitter(Qt.Horizontal)
        top.addWidget(self._group("DNS queries", self.tbl_dns))
        top.addWidget(self._group("TLS SNI hosts", self.tbl_sni))
        top.addWidget(self._group("HTTP hosts", self.tbl_http))

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(top)
        splitter.addWidget(self._group("Readable evidence samples", self.tbl_samples))
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)
        return page

    def _build_connections_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)
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
        ], stretch_columns=[11])
        layout.addWidget(self.tbl_connections)
        return page

    def _table(
        self,
        columns: list[tuple[str, str]],
        *,
        stretch_last: bool = False,
        fixed_widths: dict[int, int] | None = None,
        stretch_columns: list[int] | None = None,
    ) -> QTableView:
        table = QTableView()
        table.setModel(DictTableModel(columns))
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
        self.btn_export.setEnabled(True)
        self.lbl_file.setText(summary.file_path)
        self.lbl_stats.setText(
            f"{summary.format} | Packets: {summary.packet_count:,} | "
            f"Volume: {human_bytes(summary.wire_bytes, precision=2)} | "
            f"Period: {summary.first_seen or '-'} - {summary.last_seen or '-'}"
        )
        investigator = build_investigator_view(summary)
        self._set_investigator_text(investigator)
        self._set_table(self.tbl_services, investigator["service_rows"])
        self._set_table(self.tbl_visibility, investigator["visibility_rows"])
        self._set_table(self.tbl_activity, investigator["activity_rows"])
        self.lbl_overview_text.setText(self._overview_text(summary))
        self._set_table(self.tbl_protocols, summary.protocols)
        self._set_table(self.tbl_endpoints, summary.top_endpoints)
        self._set_table(self.tbl_ports, summary.top_ports)
        self._set_table(self.tbl_dns, summary.dns_queries)
        self._set_table(self.tbl_sni, summary.tls_sni)
        self._set_table(self.tbl_http, summary.http_hosts)
        self._set_table(self.tbl_samples, summary.readable_samples)
        self._set_table(self.tbl_connections, summary.flows)

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

    def _overview_text(self, summary: PcapSummary) -> str:
        lines = [
            "PCAP Investigation Overview",
            "",
            f"File: {summary.file_name}",
            f"Format: {summary.format}",
            f"Packets: {summary.packet_count:,}",
            f"Traffic volume: {human_bytes(summary.wire_bytes, precision=2)}",
            f"Capture period: {summary.first_seen or '-'} - {summary.last_seen or '-'}",
            f"Likely device IP: {summary.likely_device_ip or '-'}",
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

    def export_summary(self):
        if not self.summary:
            QMessageBox.information(self, "PCAP export", "Open a PCAP file first.")
            return

        default_name = Path(self.summary.file_name).with_suffix(".pcap-summary.html").name
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export PCAP summary",
            default_name,
            "HTML files (*.html)",
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".html"):
            file_path += ".html"

        try:
            export_pcap_summary_html(file_path, self.summary)
            webbrowser.open(Path(file_path).resolve().as_uri())
        except Exception as exc:
            QMessageBox.critical(self, "PCAP export failed", str(exc))
