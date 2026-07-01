from __future__ import annotations

from pathlib import Path

from core.evidence_policy import format_period_day_label
from core.formatters import human_bytes
from core.pcap_analyzer import PcapSummary
from core.pcap_period import _iso_day_from_path, resolve_period_day
from core.period_gaps import (
    calendar_days_between,
    format_period_gap_summary,
    missing_period_days,
    normalize_period_day,
    summarize_partial_months,
)
from core.period_groups import is_range_period_key, month_key, period_group_label
from core.period_selector import (
    PeriodSelectorState,
    build_period_combo_entries,
    month_view_available,
    rebuild_period_selector,
)
from core.project_evidence import get_saved_pcap_period_source
from ui.expand_dialogs import open_missing_period_days_dialog
from ui.period_selector_panel import sync_period_selector_panel, sync_pick_range_button
from ui.workers.pcap_workers import PcapBatchWorker


class PcapPeriodMixin:
    """PCAP period selector, gap banner, saved-period load, and load progress UI."""

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

    def _apply_full_project_period_index(self) -> None:
        """Show every indexed PCAP day after reloading ingest (not only the last import window)."""
        needs_reset = (
            self._pcap_period_granularity != "day"
            or bool(self._pcap_period_range_start)
            or bool(self._pcap_period_range_end)
        )
        if needs_reset:
            self._pcap_period_granularity = "day"
            self._pcap_period_range_start = ""
            self._pcap_period_range_end = ""
            if hasattr(self, "cmb_pcap_period_mode"):
                self.cmb_pcap_period_mode.blockSignals(True)
                day_index = self.cmb_pcap_period_mode.findData("day")
                if day_index >= 0:
                    self.cmb_pcap_period_mode.setCurrentIndex(day_index)
                self.cmb_pcap_period_mode.blockSignals(False)
            self._sync_pcap_range_button()
            if self._pcap_day_groups_raw:
                self._rebuild_pcap_period_combo()
                return
        if self._pcap_day_groups_raw:
            self._update_period_gap_banner(list(self._pcap_day_groups_raw.keys()))
        self._sync_period_gap_visibility()

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
        sync_pick_range_button(
            getattr(self, "btn_pcap_pick_range", None),
            granularity=self._pcap_period_granularity,
            has_periods=bool(self._pcap_day_groups_raw),
        )

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
        if self._thread is not None or self._batch_runner.is_running():
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

    def _sync_period_selector_panel(self) -> None:
        has_periods = bool(self._pcap_day_groups_raw or self._pcap_day_groups)
        batch_total = int(getattr(self, "_pcap_batch_total", 0) or 0)
        batch_processed = int(getattr(self, "_pcap_batch_processed", 0) or 0)
        queue = list(getattr(self, "_pcap_queue", None) or [])
        has_batch = bool(queue) or (
            batch_total > 0 and (batch_processed < batch_total or self._batch_runner.is_running())
        )
        sync_period_selector_panel(
            has_periods=has_periods,
            granularity=self._pcap_period_granularity,
            period_label=getattr(self, "lbl_pcap_day", None),
            day_combo=getattr(self, "cmb_pcap_day", None),
            mode_combo=getattr(self, "cmb_pcap_period_mode", None),
            pick_range_button=getattr(self, "btn_pcap_pick_range", None),
            period_row=getattr(self, "pcap_period_row", None),
            trailing_widgets={
                self.btn_reanalyze_period: has_periods,
            } if hasattr(self, "btn_reanalyze_period") else None,
        )
        if hasattr(self, "batch_status_panel"):
            self.batch_status_panel.setVisible(has_batch)

    def load_active_period(self, *, prefer_saved: bool = False) -> None:
        if not self._pcap_day_groups:
            return
        if self._thread is not None or self._batch_runner.is_running():
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
        if hasattr(self, "btn_mark_finding"):
            self.btn_mark_finding.setEnabled(bool(plain))
        self._schedule_investigator_layout_refresh()
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
        if self._thread is not None or self._batch_runner.is_running():
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
        controller = getattr(self.app, "dataset_controller", None) if self.app else None
        if controller is not None and controller.import_session_active():
            controller.route_pcap_batch_progress(0, total or len(paths), current_file=label)
            return
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
        controller = getattr(self.app, "dataset_controller", None) if self.app else None
        if controller is not None and controller.import_session_active():
            controller.route_pcap_batch_progress(
                current,
                total,
                current_file=current_file or label,
            )
            return
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

    def _update_reanalyze_button_state(self) -> None:
        if not hasattr(self, "btn_reanalyze_period"):
            return
        busy = self._thread is not None or self._batch_runner.is_running()
        day = str(self._pcap_active_day or self.cmb_pcap_day.currentData() or "")
        has_day_paths = bool(self._pcap_day_groups.get(day, [])) if day else bool(self._pcap_day_groups)
        has_summary = bool(getattr(self, "summary", None))
        self.btn_reanalyze_period.setEnabled(not busy and (has_day_paths or has_summary))

    def reanalyze_current_period(self) -> None:
        if self._thread is not None or self._batch_runner.is_running():
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
        if self._thread is not None or self._batch_runner.is_running():
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
        if hasattr(self, "btn_mark_finding"):
            self.btn_mark_finding.setEnabled(False)
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

        day_groups = {day: clean_paths} if day else None
        worker = PcapBatchWorker(
            clean_paths,
            project_id=None,
            auto_save=False,
            day_groups=day_groups,
        )
        started = self._batch_runner.start(
            worker,
            thread_parent=self._thread_parent(),
            progress_slot=self._on_batch_progress,
            finished_slot=self._on_batch_finished,
            cleanup_slot=self._cleanup_batch_thread,
        )
        if not started:
            self._info("PCAP", "PCAP batch analysis is already running.")
            self.btn_open.setEnabled(True)
            self._update_open_button_text()
            self._close_period_load_progress()
            self._update_reanalyze_button_state()
            self._update_batch_status()

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
