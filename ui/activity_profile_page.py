from __future__ import annotations

from typing import Any

from PySide6.QtCore import QThread, Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.project_profile import build_project_activity_profile
from ui.explore_widgets import AITextWorker


def _compact_range(first_seen: str, last_seen: str) -> str:
    first_seen = (first_seen or "").strip()
    last_seen = (last_seen or "").strip()
    if not first_seen or not last_seen:
        return "-"
    first_date, first_time = _split_timestamp(first_seen)
    last_date, last_time = _split_timestamp(last_seen)
    if first_date == last_date:
        return f"{first_date}\n{first_time} - {last_time}"
    return f"{first_date} {first_time}\n{last_date} {last_time}"


def _split_timestamp(value: str) -> tuple[str, str]:
    parts = value.split(" ", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return value, ""


def _short_label(value: str, limit: int) -> str:
    value = (value or "").strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."


class ActivityProfilePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.app = parent
        self.profile: dict[str, Any] | None = None
        self.project_name = ""
        self._ai_thread: QThread | None = None
        self._ai_worker: AITextWorker | None = None
        self._build_ui()
        self.clear()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(12)

        header = QFrame()
        header.setObjectName("ExploreHeaderCard")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(14, 14, 14, 14)
        header_layout.setSpacing(8)

        title_row = QHBoxLayout()
        self.lbl_title = QLabel("Activity Profile")
        self.lbl_title.setObjectName("HeaderProjectLabel")
        self.btn_ai_summary = QPushButton("AI Case Summary")
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary.clicked.connect(self.generate_ai_summary)
        title_row.addWidget(self.lbl_title)
        title_row.addStretch()
        title_row.addWidget(self.btn_ai_summary)

        self.lbl_subtitle = QLabel("Open a project to build a device/user activity profile from datasets, PCAP sources, findings and notes.")
        self.lbl_subtitle.setWordWrap(True)
        self.lbl_subtitle.setObjectName("Muted")

        header_layout.addLayout(title_row)
        header_layout.addWidget(self.lbl_subtitle)
        root.addWidget(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        scroll_layout = QVBoxLayout(content)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(12)

        evidence_title = QLabel("Evidence Overview")
        evidence_title.setObjectName("SectionTitle")
        scroll_layout.addWidget(evidence_title)

        self.metric_cards: list[QLabel] = []
        metric_grid = QGridLayout()
        metric_grid.setSpacing(10)
        for title in ("Datasets", "PCAP Sources", "Findings", "Device IPs", "PCAP Volume", "Capture Range"):
            card = QLabel(f"{title}\n0")
            card.setObjectName("ProfileMetric")
            card.setAlignment(Qt.AlignCenter)
            card.setMinimumHeight(74)
            card.setWordWrap(True)
            self.metric_cards.append(card)
            idx = len(self.metric_cards) - 1
            metric_grid.addWidget(card, idx // 3, idx % 3)
        scroll_layout.addLayout(metric_grid)

        self.evidence_chart = BarChartWidget("Evidence sources")
        self.device_ip_chart = BarChartWidget("PCAP device IP distribution")
        self.activity_chart = BarChartWidget("Activity event types")

        chart_grid = QGridLayout()
        chart_grid.setSpacing(12)
        chart_grid.addWidget(self.evidence_chart, 0, 0)
        chart_grid.addWidget(self.device_ip_chart, 0, 1)
        chart_grid.addWidget(self.activity_chart, 1, 0, 1, 2)
        chart_grid.setColumnStretch(0, 1)
        chart_grid.setColumnStretch(1, 1)
        scroll_layout.addLayout(chart_grid)

        self.txt_ai_summary = QTextEdit()
        self.txt_ai_summary.setReadOnly(True)
        self.txt_ai_summary.setMinimumHeight(220)
        self.txt_ai_summary.setPlaceholderText("Generate an AI case summary grounded in the current activity profile.")
        scroll_layout.addWidget(self._section("AI Case Summary", self.txt_ai_summary))

        self.txt_summary = QTextEdit()
        self.txt_summary.setReadOnly(True)
        self.txt_summary.setMinimumHeight(190)
        self.txt_summary.setPlaceholderText("Project profile summary will appear here.")

        self.txt_next = QTextEdit()
        self.txt_next.setReadOnly(True)
        self.txt_next.setMinimumHeight(190)
        self.txt_next.setPlaceholderText("Review guidance will appear here.")

        top = QSplitter(Qt.Horizontal)
        top.addWidget(self._section("Profile Summary", self.txt_summary))
        top.addWidget(self._section("Next Review", self.txt_next))
        top.setStretchFactor(0, 1)
        top.setStretchFactor(1, 1)

        self.lst_timeline = QListWidget()
        self.lst_timeline.setMinimumHeight(260)

        body = QSplitter(Qt.Vertical)
        body.addWidget(top)
        body.addWidget(self._section("Timeline", self.lst_timeline))
        body.setStretchFactor(0, 2)
        body.setStretchFactor(1, 1)
        scroll_layout.addWidget(body)
        scroll_layout.addStretch()
        scroll.setWidget(content)
        root.addWidget(scroll, 1)

    def refresh(self, project_id: int | None, project_name: str = ""):
        if project_id is None:
            self.clear()
            return

        profile = build_project_activity_profile(project_id)
        self.profile = profile
        self.project_name = project_name or ""
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Case Summary")
        self.lbl_title.setText(f"Activity Profile: {project_name or 'Project'}")
        self.lbl_subtitle.setText("Profile built from saved datasets, PCAP sources, findings and project activity.")
        self._set_metrics(profile.get("metrics") or [])
        self._set_overview(profile)
        self.evidence_chart.set_rows(profile.get("evidence_counts") or [])
        self.device_ip_chart.set_rows(profile.get("pcap_device_ip_rows") or [], empty_text="No saved PCAP device IPs yet.")
        self.activity_chart.set_rows(profile.get("activity_type_rows") or [], empty_text="No activity events yet.")

        summary_lines = list(profile.get("summary_lines") or [])
        self.txt_summary.setPlainText("\n".join(summary_lines))

        recommendation_lines = list(profile.get("recommendation_lines") or [])
        self.txt_next.setPlainText("\n".join(recommendation_lines))

        self.lst_timeline.clear()
        timeline = list(profile.get("timeline_lines") or [])
        if not timeline:
            self.lst_timeline.addItem(QListWidgetItem("(no project activity yet)"))
        else:
            for line in timeline:
                self.lst_timeline.addItem(QListWidgetItem(line.removeprefix("- ")))

    def clear(self):
        self.lbl_title.setText("Activity Profile")
        self.lbl_subtitle.setText("Open a project to build a device/user activity profile from datasets, PCAP sources, findings and notes.")
        self.profile = None
        self.project_name = ""
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary.setText("AI Case Summary")
        self._set_metrics([])
        self.evidence_chart.set_rows([])
        self.device_ip_chart.set_rows([], empty_text="No saved PCAP device IPs yet.")
        self.activity_chart.set_rows([], empty_text="No activity events yet.")
        self.txt_summary.clear()
        self.txt_next.clear()
        self.txt_ai_summary.clear()
        self.lst_timeline.clear()
        self.lst_timeline.addItem(QListWidgetItem("(no active project)"))

    def generate_ai_summary(self):
        if not self.profile:
            self.txt_ai_summary.setPlainText("Open an active project first.")
            return
        if not self.app or not hasattr(self.app, "ai_service"):
            self.txt_ai_summary.setPlainText("AI service is not available.")
            return
        if self._ai_thread is not None:
            return

        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary.setText("Generating...")
        self.txt_ai_summary.setPlainText("Generating activity profile summary...")

        self._ai_thread = QThread()
        self._ai_worker = AITextWorker(
            self.app.ai_service.generate_activity_profile_summary,
            dict(self.profile),
            self.project_name,
        )
        self._ai_worker.moveToThread(self._ai_thread)
        self._ai_thread.started.connect(self._ai_worker.run)
        self._ai_worker.finished.connect(self._on_ai_finished, Qt.QueuedConnection)
        self._ai_worker.error.connect(self._on_ai_error, Qt.QueuedConnection)
        self._ai_worker.finished.connect(self._ai_thread.quit)
        self._ai_worker.error.connect(self._ai_thread.quit)
        self._ai_thread.finished.connect(self._cleanup_ai_thread)
        self._ai_thread.start()

    def _on_ai_finished(self, result: str):
        self.txt_ai_summary.setPlainText(result)
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Case Summary")

    def _on_ai_error(self, message: str):
        self.txt_ai_summary.setPlainText(f"AI error: {message}")
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Case Summary")

    def _cleanup_ai_thread(self):
        if self._ai_worker is not None:
            self._ai_worker.deleteLater()
            self._ai_worker = None
        if self._ai_thread is not None:
            self._ai_thread.deleteLater()
            self._ai_thread = None

    def _set_metrics(self, metrics: list[dict[str, Any]]):
        defaults = [
            {"label": "Datasets", "value": 0, "detail": "loaded"},
            {"label": "PCAP Sources", "value": 0, "detail": "saved"},
            {"label": "Findings", "value": 0, "detail": "saved"},
            {"label": "Device IPs", "value": 0, "detail": "from PCAP"},
            {"label": "PCAP Volume", "value": "0 B", "detail": "0 packets"},
            {"label": "Capture Range", "value": "-", "detail": "from saved PCAP"},
        ]
        values = metrics or defaults
        for widget, metric in zip(self.metric_cards, values):
            widget.setText(f"{metric.get('label')}\n{metric.get('value')}")
            widget.setToolTip(str(metric.get("detail") or ""))

    def _set_overview(self, profile: dict[str, Any]):
        updates = {
            4: {
                "label": "PCAP Volume",
                "value": profile.get("total_pcap_bytes_label", "0 B"),
                "detail": f"{int(profile.get('total_pcap_packets') or 0):,} packets",
            },
            5: {
                "label": "Capture Range",
                "value": _compact_range((profile.get("capture_range") or {}).get("first_seen", ""), (profile.get("capture_range") or {}).get("last_seen", "")),
                "detail": "Observed PCAP capture period",
            },
        }
        for idx, metric in updates.items():
            if idx < len(self.metric_cards):
                self.metric_cards[idx].setText(f"{metric['label']}\n{metric['value']}")
                self.metric_cards[idx].setToolTip(metric["detail"])

    def _section(self, title: str, widget: QWidget, row_span: int = 1, col_span: int = 1) -> QWidget:
        box = QFrame()
        box.setObjectName("Card")
        layout = QVBoxLayout(box)
        layout.setContentsMargins(12, 10, 12, 12)
        layout.setSpacing(8)
        label = QLabel(title)
        label.setObjectName("SectionTitle")
        layout.addWidget(label)
        layout.addWidget(widget, 1)
        return box


class BarChartWidget(QFrame):
    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.title = title
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(12, 10, 12, 12)
        self.layout.setSpacing(8)

        title_label = QLabel(title)
        title_label.setObjectName("SectionTitle")
        self.layout.addWidget(title_label)

        self.rows = QVBoxLayout()
        self.rows.setSpacing(6)
        self.layout.addLayout(self.rows, 1)
        self.setMinimumHeight(180)

    def set_rows(self, rows: list[dict[str, Any]], *, empty_text: str = "No data yet.") -> None:
        self._clear_rows()
        if not rows:
            empty = QLabel(empty_text)
            empty.setObjectName("Muted")
            empty.setWordWrap(True)
            self.rows.addWidget(empty)
            self.rows.addStretch()
            return

        max_count = max(int(row.get("count") or 0) for row in rows) or 1
        for row in rows[:8]:
            label = str(row.get("label") or "-")
            count = int(row.get("count") or 0)
            pct = int(round((count / max_count) * 100)) if max_count else 0

            line = QHBoxLayout()
            line.setSpacing(8)
            name = QLabel(_short_label(label, 28))
            name.setMinimumWidth(120)
            name.setToolTip(label)
            value = QLabel(str(count))
            value.setMinimumWidth(40)
            value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setValue(pct)
            bar.setTextVisible(False)
            bar.setMinimumHeight(16)
            line.addWidget(name)
            line.addWidget(bar, 1)
            line.addWidget(value)
            self.rows.addLayout(line)

        self.rows.addStretch()

    def _clear_rows(self) -> None:
        while self.rows.count():
            item = self.rows.takeAt(0)
            child = item.widget()
            if child is not None:
                child.deleteLater()
            nested = item.layout()
            if nested is not None:
                while nested.count():
                    nested_item = nested.takeAt(0)
                    nested_child = nested_item.widget()
                    if nested_child is not None:
                        nested_child.deleteLater()
