from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import QObject, QThread, QTimer, Qt
from PySide6.QtWidgets import QFileDialog

from core.db import add_activity, mark_ingest_item
from core.formatters import human_bytes
from core.pcap_analyzer import PcapSummary, build_investigator_view
from core.pcap_batch import batch_progress_ui_interval, format_batch_status_text
from ui.explore_widgets import AITextWorker
from ui.workers.pcap_workers import PcapBatchWorker, PcapWorker


class PcapAnalysisMixin:
    """PCAP load queue, worker threads, batch handlers, and AI summary."""

    def open_pcap_dialog(self):
        if self._pcap_queue and self._thread is None and not self._batch_runner.is_running():
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

        if grouped_day:
            active_day = str(getattr(self, "_pcap_active_day", "") or "")
            active_paths = self._active_pcap_period_paths(active_day) if active_day else []
            if active_paths:
                paths = active_paths

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

    def batch_is_running(self) -> bool:
        if self._thread is not None:
            return True
        return self._batch_runner.is_running()

    def _start_auto_pcap_batch(self, paths: list[str], *, auto_save: bool) -> None:
        if self._thread is not None or self._batch_runner.is_running():
            self._info("PCAP", "PCAP analysis is already running.")
            return

        project_id = self._current_project_id()
        self._pcap_queue = []
        self._pcap_queue_auto_save = bool(auto_save)
        self._pcap_queue_auto_process = True
        batch_day_groups = self._batch_analysis_day_groups()
        if not batch_day_groups and self._pcap_day_groups_raw:
            batch_day_groups = self._raw_daily_day_groups()
        batch_periods = len(batch_day_groups) if batch_day_groups else 0
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
        if hasattr(self, "btn_mark_finding"):
            self.btn_mark_finding.setEnabled(False)
        if batch_periods > 1:
            self.lbl_file.setText(f"Selected import window ({self._pcap_batch_total:,} PCAP files / {batch_periods:,} periods)")
            self.lbl_stats.setText(
                f"Auto analyzing {self._pcap_batch_total:,} PCAP files across {batch_periods:,} periods..."
            )
        else:
            self.lbl_file.setText(self._active_period_title())
            self.lbl_stats.setText("Auto analyzing PCAP batch...")
        self._set_stats_style("PcapLoadingStatus")
        self._update_batch_status()
        batch_total = max(int(self._pcap_batch_total or 0), len(paths))
        self._show_period_load_progress(paths, label="Auto analyzing PCAP batch...", total=batch_total)

        controller = getattr(self.app, "dataset_controller", None) if self.app else None
        worker = PcapBatchWorker(
            paths,
            project_id=project_id,
            auto_save=auto_save,
            day_groups=batch_day_groups or None,
            pause_gate=(
                controller.import_pause_gate()
                if controller is not None and controller.import_session_active()
                else None
            ),
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
            self._update_batch_status()

    def _load_next_queued_pcap(self) -> None:
        if not self._pcap_queue:
            self._update_open_button_text()
            self._update_batch_status()
            return
        next_path = self._pcap_queue.pop(0)
        self._update_batch_status(Path(next_path).name)
        self._load_pcap_file(next_path)

    def _load_pcap_file(self, file_path: str):
        self._load_pcap_files([file_path], label="")

    def _load_pcap_files(self, file_paths: list[str], *, label: str = ""):
        if not self._ensure_project_workspace():
            return

        if self._thread is not None:
            self._info("PCAP", "PCAP analysis is already running.")
            return
        paths = [str(path) for path in file_paths if str(path or "").strip()]
        if not paths:
            return

        active_day = str(getattr(self, "_pcap_active_day", "") or "")
        if len(paths) > 1:
            self._start_period_reanalyze(paths, day=active_day, label=label)
            return

        self.btn_open.setEnabled(False)
        self.btn_open.setText("Loading...")
        self.btn_export.setEnabled(False)
        self.btn_ai_summary.setEnabled(False)
        if hasattr(self, "btn_export_metadata"):
            self.btn_export_metadata.setEnabled(False)
        if hasattr(self, "btn_reanalyze_period"):
            self.btn_reanalyze_period.setEnabled(False)
        if active_day or len(paths) > 1:
            current_text = label or self._active_period_title()
            self.lbl_file.setText(current_text)
        elif len(paths) == 1:
            current_text = label or Path(paths[0]).name
            self.lbl_file.setText(current_text)
        else:
            current_text = label or f"{len(paths):,} PCAP files"
            self.lbl_file.setText(current_text)
        self.lbl_stats.setText(
            "Analyzing capture..."
            if len(paths) == 1
            else f"Analyzing {len(paths):,} PCAP files for selected period..."
        )
        if active_day and hasattr(self, "_calendar_day_source_note"):
            source_note = self._calendar_day_source_note(len(paths), active_day)
            if source_note:
                self.lbl_stats.setText(source_note)
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
        self._batch_runner.start_crash_watch()
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
        calendar_note = ""
        day = str(self._pcap_active_day or "")
        if self._pcap_period_granularity == "day" and day and day != "undated":
            from core.period_calendar import refine_pcap_summary_for_calendar_day

            bucket_paths = list(self._pcap_day_groups.get(day, []) or [])
            summary, calendar_note = refine_pcap_summary_for_calendar_day(
                summary,
                day,
                bucket_paths=bucket_paths,
            )
        self.summary = summary
        self._saved_source_id = None
        self.btn_export.setEnabled(True)
        if hasattr(self, "btn_export_metadata"):
            self.btn_export_metadata.setEnabled(True)
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
        if hasattr(self, "btn_mark_finding"):
            self.btn_mark_finding.setEnabled(True)
        if source_count > 1 or self._hide_individual_pcap_names():
            self.lbl_file.setText(self._active_period_title())
        else:
            self.lbl_file.setText(summary.file_path or summary.file_name or "PCAP loaded")
        self._set_stats_style("HeaderStatLabel")
        self.lbl_stats.setText(
            f"{summary.format} | Packets: {summary.packet_count:,} | "
            f"Volume: {human_bytes(summary.wire_bytes, precision=2)} | "
            f"Period: {self._format_pcap_range(summary.first_seen, summary.last_seen)}"
            + (f" | {calendar_note}" if calendar_note else "")
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
        if hasattr(self, "_schedule_investigator_layout_refresh"):
            self._schedule_investigator_layout_refresh()

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

    def _on_batch_progress(self, processed: int, total: int, failed: int, current_file: str) -> None:
        self._pcap_batch_processed = processed
        self._pcap_batch_total = total
        self._pcap_batch_failed = failed
        if current_file:
            self._pcap_batch_current_label = current_file
        now = time.monotonic()
        interval = batch_progress_ui_interval(total)
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
        if hasattr(self, "btn_mark_finding"):
            self.btn_mark_finding.setEnabled(bool(last_summary))
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
                    self._try_load_saved_pcap_period(
                        str(self._pcap_active_day),
                        allow_when_paths_exist=True,
                    )
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
        self._batch_runner.stop_crash_watch()
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

    def _cleanup_batch_thread(self) -> None:
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

    def _update_batch_status(self, current_file: str = "", error_text: str = "") -> None:
        if not hasattr(self, "lbl_batch_status"):
            return

        status_text = format_batch_status_text(
            queue_auto_process=self._pcap_queue_auto_process,
            batch_running=self._batch_runner.is_running(),
            queue_length=len(self._pcap_queue),
            batch_processed=int(self._pcap_batch_processed or 0),
            batch_total=int(self._pcap_batch_total or 0),
            batch_failed=int(self._pcap_batch_failed or 0),
            error_text=error_text,
            context_day="",
            hide_individual_names=True,
        )
        if status_text is None:
            self.lbl_batch_status.clear()
            self.lbl_batch_status.hide()
            self._sync_period_selector_panel()
            return

        self.lbl_batch_status.setText(status_text)
        self.lbl_batch_status.show()
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
        if hasattr(self.app, "txt_ai_hub"):
            self.app.txt_ai_hub.setPlainText("Generating PCAP AI summary...")
        if hasattr(self.app, "go_to_ai"):
            self.app.go_to_ai()

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
        if hasattr(self.app, "publish_ai_output"):
            self.app.publish_ai_output("PCAP", "PCAP AI Summary", result)
        else:
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
        if hasattr(self.app, "txt_ai_hub"):
            self.app.txt_ai_hub.setPlainText(f"AI error: {message}")
        self.btn_ai_summary.setEnabled(True)
        self.btn_ai_summary.setText("AI Summary")

    def _refresh_project_after_batch(self) -> None:
        if self._project_batch_refresh_running:
            return
        project_id = self._current_project_id()
        if project_id is None:
            return
        controller = getattr(self.app, "dataset_controller", None) if self.app else None
        if controller is not None and (
            getattr(controller, "_import_finalize_pending", False)
            or getattr(controller, "_import_finalize_running", False)
        ):
            return
        QTimer.singleShot(0, lambda pid=project_id: self._run_project_batch_refresh(pid))

    def _run_project_batch_refresh(self, project_id: int | None) -> None:
        if project_id is None or project_id != self._current_project_id():
            return
        if self._project_batch_refresh_running:
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
