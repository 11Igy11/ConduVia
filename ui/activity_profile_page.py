from __future__ import annotations

import webbrowser
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.analysis_limits import (
    PROFILE_CHART_PREVIEW_ROWS,
)
from core.behavior_profile import build_flow_behavior_profile
from core.limit_notices import profile_skipped_json_notice
from core.db import get_project, get_project_behavior_profile
from core.exporters.profile_exporter import export_activity_profile_html
from core.project_datasets import count_project_json_datasets, load_project_dataset_flows
from core.project_profile import build_project_activity_profile
from core.timeutils import parse_timestamp
from core.workspace import workspace_export_path
from ui.bar_chart_widget import BarChartWidget
from ui.buttons import make_action_button
from ui.explore_widgets import AITextWorker
from ui.project_rows_dialog import open_project_rows_dialog
from ui.worker_runner import WorkerRunner


def _build_evidence_metric_cell(title: str) -> dict[str, QLabel | QWidget]:
    cell = QWidget()
    cell.setObjectName("ProfileEvidenceCell")
    cell.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

    layout = QVBoxLayout(cell)
    layout.setContentsMargins(10, 6, 10, 6)
    layout.setSpacing(2)

    title_label = QLabel(title)
    title_label.setObjectName("ProfileEvidenceMetricTitle")
    title_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

    body_label = QLabel("—")
    body_label.setObjectName("ProfileEvidenceMetricBody")
    body_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
    body_label.setWordWrap(True)

    layout.addWidget(title_label)
    layout.addWidget(body_label)
    return {"cell": cell, "title": title_label, "body": body_label}


def _metric_body_text(metric: dict[str, Any]) -> str:
    lines = metric.get("lines")
    if lines:
        return " · ".join(str(line) for line in lines)
    return str(metric.get("value", "-"))


def _apply_metric_card(card: dict[str, QLabel | QWidget], metric: dict[str, Any]) -> None:
    card["title"].setText(str(metric.get("label") or ""))
    card["body"].setText(_metric_body_text(metric))
    card["cell"].setToolTip(str(metric.get("detail") or ""))


def _compact_range(first_seen: str, last_seen: str) -> str:
    first_seen = (first_seen or "").strip()
    last_seen = (last_seen or "").strip()
    if not first_seen or not last_seen:
        return "-"
    first_date, first_time = _split_timestamp(_format_profile_timestamp(first_seen))
    last_date, last_time = _split_timestamp(_format_profile_timestamp(last_seen))
    if first_date == last_date:
        return f"{first_date} {first_time} – {last_time}"
    return f"{first_date} {first_time} → {last_date} {last_time}"


def _format_profile_timestamp(value: str) -> str:
    dt = parse_timestamp(value)
    if dt is None:
        return value
    time_value = dt.strftime("%H:%M:%S.%f")[:-3]
    return f"{dt.strftime('%d.%m.%Y')} {time_value}"


def _split_timestamp(value: str) -> tuple[str, str]:
    parts = value.split(" ", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return value, ""


def _top_volume_day_rows(rows: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    cleaned = list(rows or [])
    cleaned.sort(
        key=lambda row: int(row.get("count") or max(int(row.get("json_bytes") or 0), int(row.get("pcap_bytes") or 0))),
        reverse=True,
    )
    return cleaned


def _sort_profile_expand_rows(key: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned = list(rows)
    if key == "period_comparison_rows":
        cleaned.sort(
            key=lambda row: max(int(row.get("json_bytes") or 0), int(row.get("pcap_bytes") or 0)),
            reverse=True,
        )
    elif key in {"pcap_day_rows", "json_day_rows"}:
        cleaned.sort(key=lambda row: int(row.get("count") or 0), reverse=True)
    elif key == "pcap_device_ip_rows":
        cleaned.sort(key=lambda row: int(row.get("packets") or row.get("count") or 0), reverse=True)
    elif key == "pcap_period_coverage":
        cleaned.sort(key=lambda row: str(row.get("date") or row.get("label") or ""))
    return cleaned


def _sort_behavior_expand_rows(key: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned = list(rows)
    if key in {"service_rows", "domain_rows"}:
        cleaned.sort(key=lambda row: int(row.get("bytes") or row.get("count") or 0), reverse=True)
    return cleaned


class ActivityProfilePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.app = parent
        self.profile: dict[str, Any] | None = None
        self.project_name = ""
        self._behavior_cache_key = ""
        self._behavior_cache_flows: list[dict[str, Any]] = []
        self._project_dataset_info: dict[str, Any] = {}
        self._ai_runner = WorkerRunner(self)
        self._logged_repository_hit_key = ""
        self._last_ai_summary = ""
        self._build_ui()
        self.clear()

    def invalidate_project_cache(self) -> None:
        self._behavior_cache_key = ""
        self._behavior_cache_flows = []
        self._project_dataset_info = {}
        controller = getattr(self.app, "dataset_controller", None) if self.app else None
        if not (controller and controller.behavior_index_running()):
            self._behavior_index_requested_project_id = None
        self._pending_hit_record_ids: list[int] = []
        self._pending_hit_search = ""
        self._logged_repository_hit_key = ""

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(12)

        header = QFrame()
        header.setObjectName("ExploreHeaderCard")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(10, 6, 10, 6)
        header_layout.setSpacing(4)

        title_row = QHBoxLayout()
        self.lbl_title = QLabel("Activity Profile")
        self.lbl_title.setObjectName("HeaderProjectLabel")
        self.btn_ai_summary = make_action_button("AI Profile Summary", enabled=False)
        self.btn_ai_summary.clicked.connect(self.generate_ai_summary)
        self.btn_add_ai_to_notes = make_action_button("Add to Notes", enabled=False)
        self.btn_add_ai_to_notes.clicked.connect(self.add_profile_to_notes)
        self.btn_export = make_action_button("Export Profile", enabled=False)
        self.btn_export.clicked.connect(self.export_profile)
        title_row.addWidget(self.lbl_title)
        title_row.addStretch()
        title_row.addWidget(self.btn_ai_summary)
        title_row.addWidget(self.btn_add_ai_to_notes)
        title_row.addWidget(self.btn_export)

        self.lbl_subtitle = QLabel("Open a project to build a device/user activity profile from JSON datasets, PCAP sources, findings and notes.")
        self.lbl_subtitle.setWordWrap(True)
        self.lbl_subtitle.setObjectName("Muted")

        self.lbl_readiness = QLabel("")
        self.lbl_readiness.setWordWrap(True)
        self.lbl_readiness.setObjectName("ProfileReadiness")
        self.lbl_readiness.hide()

        header_layout.addLayout(title_row)
        header_layout.addWidget(self.lbl_subtitle)
        header_layout.addWidget(self.lbl_readiness)

        self.lbl_limit_notice = QLabel("")
        self.lbl_limit_notice.setObjectName("AnalysisLimitNotice")
        self.lbl_limit_notice.setWordWrap(True)
        self.lbl_limit_notice.hide()
        header_layout.addWidget(self.lbl_limit_notice)

        self.lbl_profile_hit = QLabel("")
        self.lbl_profile_hit.setObjectName("HitBanner")
        self.lbl_profile_hit.setWordWrap(True)
        self.lbl_profile_hit.hide()
        self.lbl_profile_hit.installEventFilter(self)
        header_layout.addWidget(self.lbl_profile_hit)

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

        self.metric_cards: list[dict[str, QLabel | QWidget]] = []
        evidence_panel = QFrame()
        evidence_panel.setObjectName("ProfileEvidencePanel")
        evidence_panel.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        metric_grid = QGridLayout(evidence_panel)
        metric_grid.setContentsMargins(4, 4, 4, 4)
        metric_grid.setHorizontalSpacing(0)
        metric_grid.setVerticalSpacing(0)
        for col in range(3):
            metric_grid.setColumnStretch(col, 1)

        titles = ("JSON", "PCAP", "Findings", "Device IPs", "PCAP Volume", "Capture Range")
        for idx, title in enumerate(titles):
            card = _build_evidence_metric_cell(title)
            self.metric_cards.append(card)
            grid_row = 0 if idx < 3 else 2
            metric_grid.addWidget(card["cell"], grid_row, idx % 3)

        divider = QFrame()
        divider.setObjectName("ProfileEvidenceDivider")
        divider.setFixedHeight(1)
        metric_grid.addWidget(divider, 1, 0, 1, 3)
        scroll_layout.addWidget(evidence_panel)

        self.txt_summary = QTextEdit()
        self.txt_summary.setReadOnly(True)
        self.txt_summary.setMinimumHeight(160)
        self.txt_summary.setPlaceholderText("Project profile summary will appear here.")
        self.txt_routine = QTextEdit()
        self.txt_routine.setReadOnly(True)
        self.txt_routine.setMinimumHeight(160)
        self.txt_routine.setPlaceholderText("Load a dataset to see active and quiet periods.")

        overview_row = QGridLayout()
        overview_row.setSpacing(12)
        overview_row.addWidget(self._section("Profile Summary", self.txt_summary), 0, 0)
        overview_row.addWidget(self._section("Activity rhythm", self.txt_routine), 0, 1)
        overview_row.setColumnStretch(0, 1)
        overview_row.setColumnStretch(1, 1)
        scroll_layout.addLayout(overview_row)

        self.evidence_chart = BarChartWidget(
            "Evidence sources",
            count_list=True,
            value_label_key="badge_label",
        )
        self.device_ip_chart = BarChartWidget(
            "PCAP device IP distribution",
            count_list=True,
            max_rows=PROFILE_CHART_PREVIEW_ROWS,
            value_label_key="badge_label",
        )
        self.activity_chart = BarChartWidget("Activity event types", count_list=True, max_rows=0)

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

        behavior_scope = QLabel("All saved project evidence (not filtered by Explore period).")
        behavior_scope.setObjectName("Muted")
        behavior_scope.setWordWrap(True)
        scroll_layout.addWidget(behavior_scope)

        self.service_chart = BarChartWidget(
            "Service groups by volume",
            value_key="bytes",
            value_label_key="bytes_label",
            max_rows=PROFILE_CHART_PREVIEW_ROWS,
        )
        self.domain_chart = BarChartWidget(
            "Observed domains by volume",
            value_key="bytes",
            value_label_key="bytes_label",
            label_limit=120,
            stacked_labels=True,
            max_rows=PROFILE_CHART_PREVIEW_ROWS,
        )
        self.day_chart = BarChartWidget(
            "JSON activity by day (top by volume)",
            value_key="count",
            value_label_key="detail",
            label_width=110,
            max_rows=PROFILE_CHART_PREVIEW_ROWS,
        )
        self.pcap_day_chart = BarChartWidget(
            "PCAP volume by day (top by volume)",
            value_key="count",
            value_label_key="detail",
            label_width=110,
            max_rows=PROFILE_CHART_PREVIEW_ROWS,
        )
        self.period_compare_chart = BarChartWidget(
            "JSON vs PCAP by day (top by volume)",
            value_key="count",
            value_label_key="detail",
            label_width=110,
            max_rows=PROFILE_CHART_PREVIEW_ROWS,
            stacked_labels=True,
            label_limit=80,
        )
        self.service_chart.configure_expand_table(
            lambda: self._expand_behavior_rows("service_rows", "Service groups by volume")
        )
        self.domain_chart.configure_expand_table(
            lambda: self._expand_behavior_rows("domain_rows", "Observed domains by volume")
        )
        self.day_chart.configure_expand_table(
            lambda: self._expand_profile_rows("json_day_rows", "JSON activity by day")
        )
        self.pcap_day_chart.configure_expand_table(
            lambda: self._expand_profile_rows("pcap_day_rows", "PCAP volume by day")
        )
        self.period_compare_chart.configure_expand_table(
            lambda: self._expand_profile_rows("period_comparison_rows", "JSON vs PCAP by day")
        )
        self.device_ip_chart.configure_expand_table(
            lambda: self._expand_profile_rows("pcap_device_ip_rows", "PCAP device IP distribution")
        )
        self.pcap_coverage_chart = BarChartWidget(
            "PCAP period coverage",
            value_key="saved",
            value_label_key="detail",
            label_width=110,
            max_rows=PROFILE_CHART_PREVIEW_ROWS,
            count_list=True,
        )
        self.pcap_coverage_chart.configure_expand_table(
            lambda: self._expand_profile_rows("pcap_period_coverage", "PCAP period coverage")
        )
        self.hour_chart = BarChartWidget(
            "Activity by hour (all saved project evidence)",
            value_key="count",
            max_rows=0,
        )

        behavior_grid = QGridLayout()
        behavior_grid.setSpacing(12)
        behavior_grid.addWidget(self.service_chart, 0, 0)
        behavior_grid.addWidget(self.domain_chart, 0, 1)
        behavior_grid.addWidget(self.day_chart, 1, 0)
        behavior_grid.addWidget(self.pcap_day_chart, 1, 1)
        behavior_grid.addWidget(self.period_compare_chart, 2, 0, 1, 2)
        behavior_grid.addWidget(self.pcap_coverage_chart, 3, 0)
        behavior_grid.addWidget(self.hour_chart, 3, 1)
        behavior_grid.setColumnStretch(0, 1)
        behavior_grid.setColumnStretch(1, 1)
        scroll_layout.addLayout(behavior_grid)

        scroll_layout.addStretch()
        scroll.setWidget(content)
        root.addWidget(scroll, 1)

    def refresh(self, project_id: int | None, project_name: str = "", *, quick: bool = False):
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
        self.device_ip_chart.set_rows(
            profile.get("pcap_device_ip_rows") or [],
            empty_text="No saved PCAP device IPs yet.",
            footer_text=(
                f"{len(profile.get('pcap_device_ip_rows') or [])} unique device IPs across "
                f"{int(profile.get('pcap_day_count') or 0)} PCAP periods. "
                "Badge shows packet volume, not IP count."
            ) if profile.get("pcap_device_ip_rows") else "",
        )
        self.activity_chart.set_rows(profile.get("activity_type_rows") or [], empty_text="No activity events yet.")
        self._set_behavior_profile()
        self._set_pcap_period_coverage(profile.get("pcap_period_coverage") or [])
        self._update_profile_expand_buttons(profile)

        summary_lines = list(profile.get("summary_lines") or [])
        self.txt_summary.setPlainText("\n".join(summary_lines))
        self._sync_add_to_notes_button()

        self._update_readiness(profile.get("readiness") or {})
        if not quick:
            self._update_hit_banner(project_id)

    def _update_readiness(self, readiness: dict) -> None:
        banner = getattr(self, "lbl_readiness", None)
        if banner is None:
            return
        label = str(readiness.get("label") or "").strip()
        detail = str(readiness.get("detail") or "").strip()
        state = str(readiness.get("state") or "").strip()
        if not label:
            banner.hide()
            banner.clear()
            return
        text = label if not detail else f"{label}\n{detail}"
        banner.setText(text)
        banner.setProperty("readinessState", state)
        banner.show()

    def _update_limit_notice(self, behavior: dict[str, Any] | None = None) -> None:
        banner = getattr(self, "lbl_limit_notice", None)
        if banner is None:
            return
        behavior = behavior or {}
        info = behavior.get("project_dataset_info") or self._project_dataset_info or {}
        skipped = int(info.get("skipped_json_file_count") or behavior.get("skipped_json_file_count") or 0)
        loaded = int(info.get("loaded_json_file_count") or behavior.get("loaded_json_file_count") or 0)
        indexed_count = int(info.get("json_file_count") or behavior.get("json_file_count") or 0)
        text = profile_skipped_json_notice(
            skipped_count=skipped,
            loaded_count=loaded,
            indexed_file_count=indexed_count,
        )
        if text:
            banner.setText(text)
            banner.show()
        else:
            banner.hide()
            banner.clear()

    def _update_hit_banner(self, project_id: int | None) -> None:
        banner = getattr(self, "lbl_profile_hit", None)
        if banner is None:
            return
        self._pending_hit_record_ids = []
        self._pending_hit_search = ""
        if project_id is None:
            banner.hide()
            banner.clear()
            banner.setCursor(Qt.ArrowCursor)
            return
        from core.leaks.search import find_repository_hits, normalize_hit_kind
        from core.osint.snapshot import build_osint_snapshot

        try:
            snapshot = build_osint_snapshot(int(project_id))
        except Exception:
            banner.hide()
            banner.clear()
            banner.setCursor(Qt.ArrowCursor)
            return

        seen: set[str] = set()
        hits: list[str] = []
        all_record_ids: list[int] = []
        first_search = ""
        for row in snapshot.get("identifiers") or []:
            kind = str(row.get("kind") or "").strip()
            value = str(row.get("value") or "").strip()
            if not value or value in seen:
                continue
            if kind.upper() in {"IP", "DOMAIN"}:
                continue
            if normalize_hit_kind(kind, value) is None and "@" not in value and not any(ch.isdigit() for ch in value):
                continue
            seen.add(value)
            total, summary, record_ids = find_repository_hits(value, kind=kind)
            if total:
                label = kind or "Identifier"
                hits.append(f"{label} {value} → {total} in {summary}")
                for record_id in record_ids or []:
                    if record_id not in all_record_ids:
                        all_record_ids.append(record_id)
                if not first_search:
                    first_search = value
        if hits:
            self._pending_hit_record_ids = all_record_ids
            self._pending_hit_search = first_search
            banner.setText(
                "\u2714  Repository hits: " + "; ".join(hits) + "  (click to open)"
            )
            banner.setCursor(Qt.PointingHandCursor)
            banner.setMinimumHeight(32)
            banner.show()
            hit_key = f"{project_id}:{first_search}:{len(all_record_ids)}"
            if hit_key != getattr(self, "_logged_repository_hit_key", ""):
                self._logged_repository_hit_key = hit_key
                try:
                    from core.db import add_activity

                    add_activity(
                        int(project_id),
                        "repository_hit",
                        "; ".join(hits[:3]),
                    )
                    if self.app and hasattr(self.app, "notes_controller"):
                        self.app.notes_controller.refresh_activity_ui_for_project(int(project_id))
                except Exception:
                    pass
        else:
            banner.hide()
            banner.clear()
            banner.setCursor(Qt.ArrowCursor)

    def eventFilter(self, obj, event) -> bool:
        banner = getattr(self, "lbl_profile_hit", None)
        if obj is banner and event.type() == QEvent.Type.MouseButtonRelease:
            if event.button() == Qt.MouseButton.LeftButton and self._pending_hit_search:
                self._open_hit_in_repository()
                return True
        return super().eventFilter(obj, event)

    def _open_hit_in_repository(self) -> None:
        if not self._pending_hit_search or not self.app:
            return
        if hasattr(self.app, "open_leaks_viewer"):
            self.app.open_leaks_viewer(
                search_text=self._pending_hit_search,
                record_ids=self._pending_hit_record_ids,
            )

    def clear(self):
        self.lbl_title.setText("Activity Profile")
        self.lbl_subtitle.setText("Open a project to build a device/user activity profile from JSON datasets, PCAP sources, findings and notes.")
        if hasattr(self, "lbl_readiness"):
            self.lbl_readiness.hide()
            self.lbl_readiness.clear()
        if hasattr(self, "lbl_limit_notice"):
            self.lbl_limit_notice.hide()
            self.lbl_limit_notice.clear()
        if hasattr(self, "lbl_profile_hit"):
            self.lbl_profile_hit.hide()
            self.lbl_profile_hit.clear()
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
        self.day_chart.set_rows([], empty_text="No saved JSON activity is available by day.")
        self.pcap_day_chart.set_rows([], empty_text="No saved PCAP activity is available by day.")
        self.period_compare_chart.set_rows([], empty_text="Load JSON and save PCAP periods to compare daily volume.")
        self.pcap_coverage_chart.set_rows([], empty_text="No indexed PCAP periods for this project.")
        self.hour_chart.set_rows([], empty_text="No saved project dataset is available for hourly activity.")
        self.txt_routine.clear()
        self.txt_summary.clear()
        self._last_ai_summary = ""

    def generate_ai_summary(self):
        if not self.profile:
            if self.app and hasattr(self.app, "_message_dialog"):
                self.app._message_dialog("Activity Profile", "Open an active project first.", width=440)
            return
        if not self.app or not hasattr(self.app, "ai_service"):
            if self.app and hasattr(self.app, "_message_dialog"):
                self.app._message_dialog("Activity Profile", "AI service is not available.", width=440)
            return
        if self._ai_runner.is_running():
            return

        self.btn_ai_summary.setEnabled(False)
        self.btn_ai_summary.setText("Generating...")
        self._last_ai_summary = ""

        worker = AITextWorker(
            self.app.ai_service.generate_activity_profile_summary,
            dict(self.profile),
            self.project_name,
        )
        self._ai_runner.start(
            worker,
            thread_parent=self.app,
            finished_slot=self._on_ai_finished,
            error_slot=self._on_ai_error,
        )

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
        self._last_ai_summary = (result or "").strip()
        if self.app and hasattr(self.app, "publish_ai_output"):
            self.app.publish_ai_output("Profile", "AI Profile Summary", result)
        project_id = getattr(self.app, "current_project_id", None) if self.app else None
        if project_id is not None and (result or "").strip():
            try:
                from core.db import add_activity

                add_activity(int(project_id), "ai_summary_generated", "Profile summary")
                if self.app and hasattr(self.app, "notes_controller"):
                    self.app.notes_controller.refresh_activity_ui_for_project(int(project_id))
            except Exception:
                pass
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Profile Summary")

    def _current_project(self):
        project_id = getattr(self.app, "current_project_id", None) if self.app else None
        if project_id is None:
            return None
        return get_project(project_id)

    def _on_ai_error(self, message: str):
        self._last_ai_summary = ""
        if self.app and hasattr(self.app, "_message_dialog"):
            self.app._message_dialog("Activity Profile", "AI summary failed.", message, width=560)
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Profile Summary")

    def add_profile_to_notes(self) -> None:
        summary = (self.txt_summary.toPlainText() or "").strip()
        rhythm = (self.txt_routine.toPlainText() or "").strip()
        if not summary and not rhythm:
            return
        if not self.app or self.app.current_project_id is None:
            if hasattr(self.app, "_message_dialog"):
                self.app._message_dialog("Notes", "Open an active project first.", width=420)
            return

        sections: list[str] = []
        if summary:
            sections.append(f"Profile Summary\n{summary}")
        if rhythm:
            sections.append(f"Activity rhythm\n{rhythm}")
        body = "\n\n".join(sections)

        from datetime import datetime

        from ui.notes_format import format_notes_html_block

        ts = datetime.now().strftime("%d.%m.%Y. %H:%M:%S")
        block = format_notes_html_block(
            source=f"Profile · {ts}",
            title="Activity Profile",
            body=body,
        )
        if not block:
            return
        self.app.notes_page.append_block(block)
        self.app._notes_dirty = True
        if hasattr(self.app, "notes_controller"):
            self.app.notes_controller.flush()
        self.app.go_to_notes()

    def _sync_add_to_notes_button(self) -> None:
        has_summary = bool((self.txt_summary.toPlainText() or "").strip())
        has_rhythm = bool((self.txt_routine.toPlainText() or "").strip())
        self.btn_add_ai_to_notes.setEnabled(has_summary or has_rhythm)

    def shutdown_background_tasks(self, wait_ms: int = 5000) -> None:
        self._ai_runner.stop(wait_ms=wait_ms)

    def _set_metrics(self, metrics: list[dict[str, Any]]):
        defaults = [
            {"label": "JSON", "lines": ["0 files", "0 indexed days", "0 flow days"], "detail": "loaded"},
            {"label": "PCAP", "lines": ["0 indexed files", "0 indexed days", "0 saved days"], "detail": "saved"},
            {"label": "Findings", "value": 0, "detail": "saved"},
            {"label": "Device IPs", "value": 0, "detail": "from PCAP"},
            {"label": "PCAP Volume", "value": "0 B", "detail": "0 packets"},
            {"label": "Capture Range", "value": "-", "detail": "from saved PCAP"},
        ]
        values = metrics or defaults
        for card, metric in zip(self.metric_cards, values):
            _apply_metric_card(card, metric)

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
                "detail": "Earliest first packet to latest last packet across all saved daily periods",
            },
        }
        for idx, metric in updates.items():
            if idx < len(self.metric_cards):
                _apply_metric_card(self.metric_cards[idx], metric)

    def _set_pcap_period_coverage(self, rows: list[dict[str, Any]]) -> None:
        chart_rows = []
        for row in rows:
            saved = str(row.get("status") or "") == "Saved to project"
            chart_rows.append({
                "label": str(row.get("label") or "-"),
                "saved": 1 if saved else 0,
                "detail": f"{row.get('detail') or ''} | {row.get('status') or 'Unknown'}",
            })
        self.pcap_coverage_chart.set_rows(
            chart_rows,
            empty_text="Import a PCAP folder with a calendar period to see indexed days.",
        )

    def _apply_saved_day_charts(self) -> None:
        profile = self.profile or {}
        self.day_chart.set_rows(
            _top_volume_day_rows(profile.get("json_day_rows") or []),
            empty_text="No saved JSON activity is available by day.",
        )
        self.pcap_day_chart.set_rows(
            _top_volume_day_rows(profile.get("pcap_day_rows") or []),
            empty_text="No saved PCAP activity is available by day.",
        )
        self.period_compare_chart.set_rows(
            _top_volume_day_rows(profile.get("period_comparison_rows") or []),
            empty_text="Load JSON and save PCAP periods to compare daily volume.",
        )
        self._update_profile_expand_buttons(profile)

    def _set_behavior_profile(self):
        self._apply_saved_day_charts()
        project_id = getattr(self.app, "current_project_id", None) if self.app else None
        indexed = get_project_behavior_profile(project_id) if project_id is not None else {}
        if indexed.get("flow_count"):
            saved_json_count = int(indexed.get("json_file_count") or 0)
            loaded_json_count = int(indexed.get("loaded_json_file_count") or 0)
            skipped_json_count = int(indexed.get("skipped_json_file_count") or 0)
            behavior = indexed
            self._project_dataset_info = {
                "json_file_count": saved_json_count,
                "loaded_json_file_count": loaded_json_count,
                "skipped_json_file_count": skipped_json_count,
                "flow_count": int(indexed.get("flow_count") or 0),
                "source_count": saved_json_count,
                "loaded_source_count": loaded_json_count,
                "missing_rows": [],
            }
        elif indexed.get("json_file_count"):
            saved_json_count = int(indexed.get("json_file_count") or 0)
            loaded_json_count = int(indexed.get("loaded_json_file_count") or 0)
            skipped_json_count = int(indexed.get("skipped_json_file_count") or 0)
            behavior = {
                "flow_count": 0,
                "routine_lines": [
                    f"Project JSON sources indexed: {saved_json_count:,}.",
                    "Behavior charts are being rebuilt from the saved project evidence.",
                    "Refresh Profile after indexing finishes if the charts are still empty.",
                ],
            }
            self._project_dataset_info = {
                "json_file_count": saved_json_count,
                "loaded_json_file_count": loaded_json_count,
                "skipped_json_file_count": skipped_json_count,
                "flow_count": int(indexed.get("flow_count") or 0),
                "source_count": saved_json_count,
                "loaded_source_count": loaded_json_count,
                "missing_rows": [],
            }
        else:
            saved_json_count = 0
            if project_id is not None:
                try:
                    saved_json_count = count_project_json_datasets(project_id, limit=50000)
                except Exception:
                    saved_json_count = int((self.profile or {}).get("dataset_count") or 0)

            if project_id is not None and saved_json_count:
                self._project_dataset_info = {
                    "json_file_count": saved_json_count,
                    "loaded_json_file_count": 0,
                    "skipped_json_file_count": 0,
                    "flow_count": 0,
                    "source_count": saved_json_count,
                    "loaded_source_count": 0,
                    "missing_rows": [],
                }
                behavior = {
                    "flow_count": 0,
                    "routine_lines": [
                        f"Project JSON sources indexed: {saved_json_count:,}.",
                        "Behavior charts are being prepared from the saved project evidence.",
                        "Refresh Profile after indexing finishes if the charts are still empty.",
                    ],
                }
            else:
                flows = self._current_flows()
                behavior = build_flow_behavior_profile(flows)
        behavior["project_dataset_info"] = dict(self._project_dataset_info or {})
        if self.profile is not None:
            self.profile["behavior_profile"] = behavior
        if not behavior.get("flow_count"):
            self.service_chart.set_rows([], empty_text="No saved project dataset is available for service groups.")
            self.domain_chart.set_rows([], empty_text="No saved project dataset is available for observed domains.")
            self.hour_chart.set_rows([], empty_text="No saved project dataset is available for hourly activity.")
            self._set_behavior_routine_text(behavior)
            self._update_limit_notice(behavior)
            return

        service_rows = behavior.get("service_rows") or []
        domain_rows = behavior.get("domain_rows") or []
        self.service_chart.set_rows(
            service_rows,
            empty_text="No visible service groups found in the loaded dataset.",
        )
        if len(service_rows) > PROFILE_CHART_PREVIEW_ROWS:
            self.service_chart.setToolTip(f"{len(service_rows):,} service groups indexed. Chart shows top {PROFILE_CHART_PREVIEW_ROWS} by volume.")
        self.domain_chart.set_rows(
            domain_rows,
            empty_text="No visible hostnames found in the loaded dataset.",
        )
        if len(domain_rows) > PROFILE_CHART_PREVIEW_ROWS:
            self.domain_chart.setToolTip(f"{len(domain_rows):,} domains indexed. Chart shows top {PROFILE_CHART_PREVIEW_ROWS} by volume.")
        self.day_chart.set_rows(
            _top_volume_day_rows((self.profile or {}).get("json_day_rows") or behavior.get("day_rows") or []),
            empty_text="No saved JSON activity is available by day.",
        )
        self.pcap_day_chart.set_rows(
            _top_volume_day_rows((self.profile or {}).get("pcap_day_rows") or []),
            empty_text="No saved PCAP activity is available by day.",
        )
        self.hour_chart.set_rows(
            behavior.get("hour_rows") or [],
            empty_text="No timestamps found in saved project evidence.",
            footer_text="Project-wide aggregate — not filtered by Explore period or month selection.",
        )
        self._set_behavior_routine_text(behavior)
        self._update_limit_notice(behavior)
        self._update_profile_expand_buttons(self.profile)

    def _update_profile_expand_buttons(self, profile: dict[str, Any] | None = None) -> None:
        profile = profile or self.profile or {}
        behavior = self._current_behavior_profile()
        thresholds = {
            self.day_chart: len(profile.get("json_day_rows") or []),
            self.pcap_day_chart: len(profile.get("pcap_day_rows") or []),
            self.period_compare_chart: len(profile.get("period_comparison_rows") or []),
            self.device_ip_chart: len(profile.get("pcap_device_ip_rows") or []),
            self.pcap_coverage_chart: len(profile.get("pcap_period_coverage") or []),
            self.service_chart: len(behavior.get("service_rows") or []),
            self.domain_chart: len(behavior.get("domain_rows") or []),
        }
        preview_limit = PROFILE_CHART_PREVIEW_ROWS
        for chart, count in thresholds.items():
            chart.set_expand_enabled(
                count > preview_limit,
                tooltip=(
                    f"{count:,} rows available — embedded chart shows top {preview_limit}."
                    if count > preview_limit
                    else ""
                ),
            )

    def _current_behavior_profile(self) -> dict[str, Any]:
        project_id = getattr(self.app, "current_project_id", None) if self.app else None
        if project_id is None:
            return {}
        indexed = get_project_behavior_profile(project_id)
        if indexed.get("flow_count"):
            return indexed
        flows = self._current_flows()
        if not flows:
            return indexed
        return build_flow_behavior_profile(flows)

    def _expand_behavior_rows(self, key: str, title: str) -> None:
        behavior = self._current_behavior_profile()
        rows = _sort_behavior_expand_rows(key, list(behavior.get(key) or []))
        if not rows:
            return
        if key == "service_rows":
            columns = [("label", "Service"), ("bytes_label", "Volume"), ("count", "Flows"), ("example", "Example")]
        else:
            columns = [("label", "Domain"), ("bytes_label", "Volume"), ("count", "Flows"), ("share", "Share")]
        open_project_rows_dialog(self.app, title, columns, rows)

    def _expand_profile_rows(self, key: str, title: str) -> None:
        profile = self.profile or {}
        rows = _sort_profile_expand_rows(key, list(profile.get(key) or []))
        if not rows:
            return
        if key == "period_comparison_rows":
            columns = [
                ("label", "Day"),
                ("json_mb_label", "JSON"),
                ("pcap_mb_label", "PCAP"),
                ("delta_pct", "Δ vol %"),
                ("status", "Status"),
                ("detail", "Detail"),
            ]
        elif key == "pcap_day_rows":
            columns = [("label", "Day"), ("count", "Packets"), ("bytes_label", "Volume"), ("detail", "Detail")]
        elif key == "pcap_device_ip_rows":
            columns = [
                ("label", "IP"),
                ("badge_label", "Packets"),
                ("periods", "Periods"),
                ("detail", "Detail"),
            ]
        elif key == "pcap_period_coverage":
            columns = [("label", "Day"), ("count", "Files"), ("status", "Status"), ("detail", "Detail")]
        else:
            columns = [("label", "Day"), ("count", "Flows"), ("detail", "Detail")]
        open_project_rows_dialog(self.app, title, columns, rows)

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
            skipped_files = int(info.get("skipped_json_file_count") or 0)
            if skipped_files:
                lines.append(f"Additional selected JSON files indexed but not loaded into behavior charts: {skipped_files:,}.")
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
        self._sync_add_to_notes_button()

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
