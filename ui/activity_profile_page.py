from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import Any

from PySide6.QtCore import QThread, Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.behavior_profile import build_flow_behavior_profile
from core.db import get_app_settings, get_project
from core.exporters.profile_exporter import export_activity_profile_html
from core.project_datasets import load_project_dataset_flows
from core.project_profile import build_project_activity_profile
from core.timeutils import parse_timestamp
from core.workspace import workspace_export_path
from ui.explore_widgets import AITextWorker


def _compact_range(first_seen: str, last_seen: str) -> str:
    first_seen = (first_seen or "").strip()
    last_seen = (last_seen or "").strip()
    if not first_seen or not last_seen:
        return "-"
    first_date, first_time = _split_timestamp(_format_profile_timestamp(first_seen))
    last_date, last_time = _split_timestamp(_format_profile_timestamp(last_seen))
    if first_date == last_date:
        return f"{first_date}\n{first_time} - {last_time}"
    return f"{first_date} {first_time}\n{last_date} {last_time}"


def _format_profile_timestamp(value: str) -> str:
    dt = parse_timestamp(value)
    if dt is None:
        return value
    time_value = dt.strftime("%H:%M:%S.%f")[:-3]
    return f"{dt.strftime('%d/%m/%Y')} {time_value}"


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
        self._behavior_cache_key = ""
        self._behavior_cache_flows: list[dict[str, Any]] = []
        self._project_dataset_info: dict[str, Any] = {}
        self._ai_thread: QThread | None = None
        self._ai_worker: AITextWorker | None = None
        self._build_ui()
        self.clear()

    def invalidate_project_cache(self) -> None:
        self._behavior_cache_key = ""
        self._behavior_cache_flows = []
        self._project_dataset_info = {}

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
        self.btn_ai_summary = QPushButton("AI Profile Summary")
        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary.clicked.connect(self.generate_ai_summary)
        self.btn_add_ai_to_notes = QPushButton("Add to Notes")
        self.btn_add_ai_to_notes.setEnabled(False)
        self.btn_add_ai_to_notes.clicked.connect(self.add_ai_summary_to_notes)
        self.btn_export = QPushButton("Export Profile")
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self.export_profile)
        title_row.addWidget(self.lbl_title)
        title_row.addStretch()
        title_row.addWidget(self.btn_ai_summary)
        title_row.addWidget(self.btn_add_ai_to_notes)
        title_row.addWidget(self.btn_export)

        self.lbl_subtitle = QLabel("Open a project to build a device/user activity profile from JSON datasets, PCAP sources, findings and notes.")
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
        for title in ("JSON Datasets", "PCAP Sources", "Findings", "Device IPs", "PCAP Volume", "Capture Range"):
            card = QLabel(f"{title}\n0")
            card.setObjectName("ProfileMetric")
            card.setAlignment(Qt.AlignCenter)
            card.setMinimumHeight(74)
            card.setWordWrap(True)
            self.metric_cards.append(card)
            idx = len(self.metric_cards) - 1
            metric_grid.addWidget(card, idx // 3, idx % 3)
        scroll_layout.addLayout(metric_grid)

        self.evidence_chart = BarChartWidget("Evidence sources", count_list=True)
        self.device_ip_chart = BarChartWidget("PCAP device IP distribution", count_list=True)
        self.activity_chart = BarChartWidget("Activity event types", count_list=True, max_rows=6)

        chart_grid = QGridLayout()
        chart_grid.setSpacing(12)
        chart_grid.addWidget(self.device_ip_chart, 0, 0)
        chart_grid.addWidget(self.activity_chart, 0, 1)
        chart_grid.setColumnStretch(0, 1)
        chart_grid.setColumnStretch(1, 1)
        scroll_layout.addLayout(chart_grid)

        behavior_title = QLabel("Behavior Insights")
        behavior_title.setObjectName("SectionTitle")
        scroll_layout.addWidget(behavior_title)

        self.service_chart = BarChartWidget("Service groups by volume", value_key="bytes", value_label_key="bytes_label")
        self.domain_chart = BarChartWidget(
            "Observed domains by volume",
            value_key="bytes",
            value_label_key="bytes_label",
            label_limit=120,
            stacked_labels=True,
            max_rows=12,
        )
        self.hour_chart = BarChartWidget("Activity by hour", value_key="count", max_rows=24)
        self.txt_routine = QTextEdit()
        self.txt_routine.setReadOnly(True)
        self.txt_routine.setMinimumHeight(150)
        self.txt_routine.setPlaceholderText("Load a dataset to see active and quiet periods.")

        behavior_grid = QGridLayout()
        behavior_grid.setSpacing(12)
        behavior_grid.addWidget(self.service_chart, 0, 0)
        behavior_grid.addWidget(self.domain_chart, 0, 1)
        behavior_grid.addWidget(self.hour_chart, 1, 0)
        behavior_grid.addWidget(self._section("Activity rhythm", self.txt_routine), 1, 1)
        behavior_grid.setColumnStretch(0, 1)
        behavior_grid.setColumnStretch(1, 1)
        scroll_layout.addLayout(behavior_grid)

        self.txt_ai_summary = QTextEdit()
        self.txt_ai_summary.setReadOnly(True)
        self.txt_ai_summary.setMinimumHeight(220)
        self.txt_ai_summary.setPlaceholderText("Generate an AI profile summary grounded in the current activity profile.")
        ai_section = QWidget()
        ai_layout = QVBoxLayout(ai_section)
        ai_layout.setContentsMargins(0, 0, 0, 0)
        ai_layout.setSpacing(8)

        ai_layout.addWidget(self.txt_ai_summary, 1)
        scroll_layout.addWidget(self._section("AI Profile Summary", ai_section))

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

        scroll_layout.addWidget(top)
        scroll_layout.addStretch()
        scroll.setWidget(content)
        root.addWidget(scroll, 1)

    def refresh(self, project_id: int | None, project_name: str = ""):
        if project_id is None:
            self.clear()
            return

        if project_id != getattr(self, "_profile_project_id", None):
            self.invalidate_project_cache()
        self._profile_project_id = project_id
        profile = build_project_activity_profile(project_id)
        self.profile = profile
        self.project_name = project_name or ""
        self.btn_ai_summary.setEnabled(True)
        self.btn_export.setEnabled(True)
        self.btn_ai_summary.setText("AI Profile Summary")
        self.lbl_title.setText(f"Activity Profile: {project_name or 'Project'}")
        self.lbl_subtitle.setText("Profile built from saved JSON datasets, PCAP sources, findings and project activity.")
        self._set_metrics(profile.get("metrics") or [])
        self._set_overview(profile)
        self.evidence_chart.set_rows(profile.get("evidence_counts") or [])
        self.device_ip_chart.set_rows(profile.get("pcap_device_ip_rows") or [], empty_text="No saved PCAP device IPs yet.")
        self.activity_chart.set_rows(profile.get("activity_type_rows") or [], empty_text="No activity events yet.")
        self._set_behavior_profile()

        summary_lines = list(profile.get("summary_lines") or [])
        self.txt_summary.setPlainText("\n".join(summary_lines))

        recommendation_lines = list(profile.get("recommendation_lines") or [])
        self.txt_next.setPlainText("\n".join(recommendation_lines))

    def clear(self):
        self.lbl_title.setText("Activity Profile")
        self.lbl_subtitle.setText("Open a project to build a device/user activity profile from JSON datasets, PCAP sources, findings and notes.")
        self.profile = None
        self.project_name = ""
        self._profile_project_id = None
        self._behavior_cache_key = ""
        self._behavior_cache_flows = []
        self._project_dataset_info = {}
        self.btn_ai_summary.setEnabled(False)
        self.btn_add_ai_to_notes.setEnabled(False)
        self.btn_export.setEnabled(False)
        self.btn_ai_summary.setText("AI Profile Summary")
        self._set_metrics([])
        self.evidence_chart.set_rows([])
        self.device_ip_chart.set_rows([], empty_text="No saved PCAP device IPs yet.")
        self.activity_chart.set_rows([], empty_text="No activity events yet.")
        self.service_chart.set_rows([], empty_text="No saved project dataset is available for service groups.")
        self.domain_chart.set_rows([], empty_text="No saved project dataset is available for observed domains.")
        self.hour_chart.set_rows([], empty_text="No saved project dataset is available for hourly activity.")
        self.txt_routine.clear()
        self.txt_summary.clear()
        self.txt_next.clear()
        self.txt_ai_summary.clear()

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

    def export_profile(self):
        if not self.profile:
            return

        default_name = f"{self.project_name or 'activity-profile'}-activity-profile.html"
        project = self._current_project()
        default_path = (
            str(workspace_export_path(project.base_folder, default_name, category="profile"))
            if project and project.base_folder
            else default_name
        )
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export activity profile",
            default_path,
            "HTML files (*.html)",
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".html"):
            file_path += ".html"

        try:
            export_activity_profile_html(
                file_path,
                profile=self.profile,
                project_name=self.project_name,
                project=project,
                report_language=get_app_settings().get("output_language", "hr"),
            )
            webbrowser.open(Path(file_path).resolve().as_uri())
        except Exception as exc:
            if hasattr(self.app, "_message_dialog"):
                self.app._message_dialog(
                    "Activity Profile export",
                    "Failed to export activity profile.",
                    str(exc),
                    width=560,
                )

    def _on_ai_finished(self, result: str):
        self.txt_ai_summary.setPlainText(result)
        self.btn_add_ai_to_notes.setEnabled(bool((result or "").strip()))
        if self.app and hasattr(self.app, "publish_ai_output"):
            self.app.publish_ai_output("Profile", "AI Profile Summary", result)
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Profile Summary")

    def _current_project(self):
        project_id = getattr(self.app, "current_project_id", None) if self.app else None
        if project_id is None:
            return None
        return get_project(project_id)

    def _on_ai_error(self, message: str):
        self.txt_ai_summary.setPlainText(f"AI error: {message}")
        self.btn_add_ai_to_notes.setEnabled(False)
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Profile Summary")

    def add_ai_summary_to_notes(self):
        text = (self.txt_ai_summary.toPlainText() or "").strip()
        if not text:
            return
        if self.app and hasattr(self.app, "add_ai_text_to_notes"):
            self.app.add_ai_text_to_notes(text)

    def _cleanup_ai_thread(self):
        if self._ai_worker is not None:
            self._ai_worker.deleteLater()
            self._ai_worker = None
        if self._ai_thread is not None:
            self._ai_thread.deleteLater()
            self._ai_thread = None

    def _set_metrics(self, metrics: list[dict[str, Any]]):
        defaults = [
            {"label": "JSON Datasets", "value": 0, "detail": "loaded"},
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

    def _set_behavior_profile(self):
        behavior = build_flow_behavior_profile(self._current_flows())
        behavior["project_dataset_info"] = dict(self._project_dataset_info or {})
        if self.profile is not None:
            self.profile["behavior_profile"] = behavior
        if not behavior.get("flow_count"):
            self.service_chart.set_rows([], empty_text="No saved project dataset is available for service groups.")
            self.domain_chart.set_rows([], empty_text="No saved project dataset is available for observed domains.")
            self.hour_chart.set_rows([], empty_text="No saved project dataset is available for hourly activity.")
            self._set_behavior_routine_text(behavior)
            return

        self.service_chart.set_rows(
            behavior.get("service_rows") or [],
            empty_text="No visible service groups found in the loaded dataset.",
        )
        self.domain_chart.set_rows(
            behavior.get("domain_rows") or [],
            empty_text="No visible hostnames found in the loaded dataset.",
        )
        self.hour_chart.set_rows(
            behavior.get("hour_rows") or [],
            empty_text="No timestamps found in the loaded dataset.",
        )
        self._set_behavior_routine_text(behavior)

    def _current_flows(self) -> list[dict[str, Any]]:
        if self.app and getattr(self.app, "current_project_id", None) is not None:
            return self._project_dataset_flows()

        if not self.app or not hasattr(self.app, "flow_controller"):
            return self._project_dataset_flows()

        controller = self.app.flow_controller
        flows: list[dict[str, Any]] = []
        if hasattr(controller, "get_all"):
            flows = list(controller.get_all() or [])
        if not flows and hasattr(controller, "get_loaded"):
            flows = list(controller.get_loaded() or [])
        if flows:
            return flows
        return self._project_dataset_flows()

    def _project_dataset_flows(self) -> list[dict[str, Any]]:
        project_id = getattr(self.app, "current_project_id", None) if self.app else None
        if project_id is None:
            return []

        dataset_info = load_project_dataset_flows(project_id)
        cache_key = str(dataset_info.get("cache_key") or "")

        if cache_key == self._behavior_cache_key:
            self._project_dataset_info = dataset_info
            return self._behavior_cache_flows

        flows = list(dataset_info.get("flows") or [])
        self._behavior_cache_key = cache_key
        self._behavior_cache_flows = flows
        self._project_dataset_info = dataset_info
        return flows

    def _set_behavior_routine_text(self, behavior: dict[str, Any]) -> None:
        lines: list[str] = []
        info = self._project_dataset_info or {}
        if info:
            loaded_files = int(info.get("loaded_json_file_count") or 0)
            file_count = int(info.get("json_file_count") or 0)
            lines.append(
                "Project JSON files included: "
                f"{loaded_files} / {file_count}; "
                f"flow records: {int(info.get('flow_count') or 0):,}."
            )
            source_count = int(info.get("source_count") or 0)
            if source_count != file_count:
                lines.append(
                    "Saved dataset sources: "
                    f"{int(info.get('loaded_source_count') or 0)} / {source_count}."
                )
            missing = int(len(info.get("missing_rows") or []))
            if missing:
                lines.append(f"Dataset paths needing review: {missing}.")
            lines.append("")
        elif not behavior.get("flow_count"):
            lines.append("No project dataset is available for behavioral indicators.")
            lines.append("")

        lines.extend(str(line) for line in (behavior.get("routine_lines") or []))
        self.txt_routine.setPlainText("\n".join(lines))

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
    def __init__(
        self,
        title: str,
        parent=None,
        *,
        value_key: str = "count",
        value_label_key: str | None = None,
        label_limit: int = 28,
        label_width: int = 120,
        max_rows: int = 8,
        stacked_labels: bool = False,
        compact_single_counts: bool = False,
        count_list: bool = False,
    ):
        super().__init__(parent)
        self.setObjectName("Card")
        self.title = title
        self.value_key = value_key
        self.value_label_key = value_label_key
        self.label_limit = label_limit
        self.label_width = label_width
        self.max_rows = max_rows
        self.stacked_labels = stacked_labels
        self.compact_single_counts = compact_single_counts
        self.count_list = count_list
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(12, 10, 12, 12)
        self.layout.setSpacing(8)
        self.layout.setAlignment(Qt.AlignTop)

        title_label = QLabel(title)
        title_label.setObjectName("SectionTitle")
        title_label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self.layout.addWidget(title_label)

        self.rows = QVBoxLayout()
        self.rows.setSpacing(6)
        self.rows.setAlignment(Qt.AlignTop)
        self.layout.addLayout(self.rows, 1)
        self.setMinimumHeight(180)

    def set_rows(self, rows: list[dict[str, Any]], *, empty_text: str = "No data yet.") -> None:
        self._clear_rows()
        if not rows:
            empty = QLabel(empty_text)
            empty.setObjectName("Muted")
            empty.setWordWrap(True)
            empty.setAlignment(Qt.AlignLeft | Qt.AlignTop)
            self.rows.addWidget(empty)
            self.rows.addStretch(1)
            return

        max_count = max(int(row.get(self.value_key) or 0) for row in rows) or 1
        use_compact_counts = self.compact_single_counts and self.value_key == "count" and max_count <= 1
        for row in rows[: self.max_rows]:
            label = str(row.get("label") or "-")
            count = int(row.get(self.value_key) or 0)
            display_value = str(row.get(self.value_label_key) or count) if self.value_label_key else str(count)
            pct = int(round((count / max_count) * 100)) if max_count else 0

            if self.count_list:
                self._add_count_row(label, display_value)
                continue

            if self.stacked_labels:
                self._add_stacked_row(label, display_value, pct)
                continue

            line = QHBoxLayout()
            line.setSpacing(8)
            name = QLabel(_short_label(label, self.label_limit))
            name.setMinimumWidth(self.label_width)
            name.setToolTip(str(row.get("tooltip") or label))
            value = QLabel(display_value)
            value.setMinimumWidth(72)
            value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            line.addWidget(name)
            if not use_compact_counts:
                bar = QProgressBar()
                bar.setRange(0, 100)
                bar.setValue(pct)
                bar.setTextVisible(False)
                bar.setMinimumHeight(16)
                line.addWidget(bar, 1)
            else:
                line.addStretch(1)
            line.addWidget(value)
            self.rows.addLayout(line)

        self.rows.addStretch()

    def _add_count_row(self, label: str, display_value: str) -> None:
        row = QFrame()
        row.setObjectName("ProfileCountRow")
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(10, 7, 10, 7)
        row_layout.setSpacing(8)

        name = QLabel(label)
        name.setWordWrap(True)
        name.setToolTip(label)
        value = QLabel(display_value)
        value.setObjectName("ProfileCountBadge")
        value.setAlignment(Qt.AlignCenter)
        value.setMinimumWidth(44)

        row_layout.addWidget(name, 1)
        row_layout.addWidget(value)
        self.rows.addWidget(row)

    def _add_stacked_row(self, label: str, display_value: str, pct: int) -> None:
        label_row = QHBoxLayout()
        label_row.setSpacing(8)
        name = QLabel(label)
        name.setWordWrap(True)
        name.setToolTip(label)
        value = QLabel(display_value)
        value.setMinimumWidth(72)
        value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        label_row.addWidget(name, 1)
        label_row.addWidget(value)
        self.rows.addLayout(label_row)

        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(pct)
        bar.setTextVisible(False)
        bar.setMinimumHeight(14)
        self.rows.addWidget(bar)

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
