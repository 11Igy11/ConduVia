from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QDate, QObject, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QFileDialog,
    QProgressBar,
    QProgressDialog,
    QPushButton,
    QVBoxLayout,
)

from core.analysis_limits import (
    EMBEDDED_SUMMARY_TOP_N,
    PROFILE_CHART_PREVIEW_ROWS,
    SUMMARY_CARD_PADDING,
    SUMMARY_CARD_WIDTH,
    SUMMARY_VALUE_COL_WIDTH,
)
from core.analyzer import top_applications, top_dst_ips, top_protocols, top_src_ips
from core.case_ingest import evidence_paths, filter_case_scan, group_evidence_by_date
from core.db import (
    add_dataset_load,
    get_project,
    ingest_status_map,
    list_ingest_items,
    mark_ingest_items_batch,
    list_recent_datasets,
    set_project_target,
    update_dataset_scan_metadata,
    upsert_ingest_items,
)
from core.loader import list_json_files_recursive
from core.osint.imsi import format_intercept_imsi, is_imsi_target_type
from core.period_gaps import format_missing_days_summary, format_period_gap_summary, missing_period_days, summarize_partial_months
from core.period_groups import is_range_period_key, parse_range_period_key
from core.period_selector import (
    PeriodSelectorState,
    build_period_combo_entries,
    infer_default_range_bounds,
    month_view_available,
    rebuild_period_selector,
    restore_range_from_raw_keys,
)
from core.formatters import format_short_date, human_bytes
from core.project_identity import (
    identifier_values_match,
    project_identifier_rows,
    project_identifiers_text,
    target_display_label,
)
from core.protocols import format_ip_proto

from core.evidence_policy import (
    MAX_INTERACTIVE_EVIDENCE_BYTES as MAX_INTERACTIVE_FOLDER_JSON_BYTES,
    MAX_INTERACTIVE_EVIDENCE_FILES as MAX_INTERACTIVE_FOLDER_JSON_FILES,
    PERIOD_LABEL,
    format_period_day_label,
    indexed_source_message,
    period_combo_label,
    should_batch_pcap_files,
    should_open_interactively,
)


from ui.expand_dialogs import open_missing_period_days_dialog
from ui.period_selector_panel import sync_period_selector_panel, sync_pick_range_button
from ui.project_rows_dialog import open_project_rows_dialog
from ui.table_export import append_table_export_footer
from ui.thread_utils import stop_qthread
from ui.workers.dataset_workers import (
    BehaviorIndexWorker,
    CaseScanWorker,
    DatasetLoadWorker,
    FolderIngestWorker,
)

_JSON_ALL_FILES_TOKEN = "__all__"


def _format_dataset_target(target: str, target_type: str) -> str:
    from core.osint.imsi import format_identifier_display

    value = format_identifier_display(target, target_type)
    kind = str(target_type or "").strip()
    if value and kind:
        return f"{value} ({kind})"
    return value or kind or "-"


def _json_order_metadata_line(meta: dict | None) -> str:
    meta = meta or {}
    klasa = str(meta.get("OrigRegNo") or "-")
    urbroj = str(meta.get("RegNo") or "-")
    target = str(meta.get("target") or "")
    target_type = str(meta.get("targettype") or "")
    liid = str(meta.get("liid") or "-")
    bt = str(meta.get("bt") or "")
    et = str(meta.get("et") or "")
    target_label = _format_dataset_target(target, target_type)
    from core.case_metadata import LAWFUL_INTERCEPTION_DATES_LABEL, format_order_datetime

    if bt or et:
        validity = f"{format_order_datetime(bt, missing='-')} -> {format_order_datetime(et, missing='-')}"
    else:
        validity = "-"
    return (
        f"Klasa: {klasa}   |   Urbroj: {urbroj}   |   Target: {target_label}   |   "
        f"LIID: {liid}   |   {LAWFUL_INTERCEPTION_DATES_LABEL}: {validity}"
    )

class DatasetIngestMixin:
    """Evidence folder scan, ingest indexing, and import pipeline."""

    def _close_scan_progress(self) -> None:
        if self._scan_progress is not None:
            self._scan_progress.close()
            self._scan_progress = None

    def _close_ingest_progress(self) -> None:
        if self._ingest_progress is not None:
            self._ingest_progress.close()
            self._ingest_progress = None

    def _start_folder_scan(self, folder: str, *, purpose: str = "import") -> None:
        if self._thread_is_running(self._scan_thread):
            self.app._message_dialog("Dataset folder", "A folder scan is already running.", width=420)
            return

        self._scan_purpose = purpose
        if purpose == "import":
            self.begin_import_session(folder)
            self.update_import_progress(phase="Scanning evidence folder...", indeterminate=True)

        def _kickoff_scan() -> None:
            self._scan_thread = QThread(self.app)
            pause_gate = self.import_pause_gate() if purpose == "import" else None
            self._scan_worker = CaseScanWorker(folder, pause_gate=pause_gate)
            self._scan_worker.moveToThread(self._scan_thread)
            self._scan_thread.started.connect(self._scan_worker.run)
            self._scan_worker.finished.connect(self._on_folder_scan_finished, Qt.QueuedConnection)
            self._scan_worker.error.connect(self._on_folder_scan_error, Qt.QueuedConnection)
            self._scan_worker.finished.connect(self._scan_thread.quit)
            self._scan_worker.error.connect(self._scan_thread.quit)
            self._scan_worker.finished.connect(self._scan_worker.deleteLater)
            self._scan_worker.error.connect(self._scan_worker.deleteLater)
            self._scan_thread.finished.connect(self._cleanup_scan_thread)
            self._scan_thread.start()

        QTimer.singleShot(0, _kickoff_scan)

    def _cleanup_scan_thread(self) -> None:
        self._scan_thread = None
        self._scan_worker = None

    def _on_folder_scan_error(self, message: str) -> None:
        if self.import_session_active() and (
            getattr(self, "_import_cancel_requested", False) or self._import_pause_gate.is_aborted()
        ):
            return
        if self.import_session_active():
            self.end_import_session()
        from core.project_audit import record_project_activity

        record_project_activity(
            getattr(self.app, "current_project_id", None),
            "import_failed",
            f"Scan: {message}",
        )
        self.app._message_dialog("Dataset folder", "Failed to scan selected folder.", message, width=520)

    def _on_folder_scan_finished(self, scan) -> None:
        folder = str(getattr(scan, "root", "") or "")
        purpose = self._scan_purpose
        self._scan_purpose = "import"
        if not folder:
            if purpose == "import":
                self.end_import_session()
            return
        QTimer.singleShot(0, lambda f=folder, s=scan, p=purpose: self._after_folder_scan(f, s, p))

    def _after_folder_scan(self, folder: str, scan, purpose: str) -> None:
        if purpose == "json_only":
            self._start_folder_ingest(folder, scan, purpose="json_only")
            return

        scoped = self._select_case_ingest_scope(scan)
        if scoped is None:
            if self.import_session_active():
                self.end_import_session()
            return
        self._start_folder_ingest(folder, scoped, purpose="import")

    def _start_folder_ingest(self, folder: str, scan, *, purpose: str = "import") -> None:
        if self._thread_is_running(self._ingest_thread):
            self.app._message_dialog("Dataset folder", "Evidence indexing is already running.", width=420)
            return

        project_id = getattr(self.app, "current_project_id", None)
        if project_id is None:
            if purpose == "import":
                self.end_import_session()
            return

        self.reset_dataset_views(preserve_import_session=(purpose == "import"))

        total_files = len(scan.json_files or []) + len(scan.pcap_files or [])
        json_count = len(scan.json_files or [])
        pcap_count = len(scan.pcap_files or [])
        self._pending_ingest_scan = scan
        self._pending_ingest_folder = folder
        self._ingest_purpose = purpose

        if purpose == "import":
            if not self.import_session_active():
                self.begin_import_session(folder)
            self.update_import_progress(
                phase=f"Indexing {total_files:,} evidence files...",
                json_note=f"JSON: {json_count:,} files indexed" if json_count else "",
                pcap_note=f"PCAP: {pcap_count:,} files queued" if pcap_count else "",
                indeterminate=True,
            )

        pause_gate = self.import_pause_gate() if purpose == "import" else None
        self._ingest_thread = QThread(self.app)
        self._ingest_worker = FolderIngestWorker(
            project_id,
            folder,
            scan,
            pause_gate=pause_gate,
        )
        self._ingest_worker.moveToThread(self._ingest_thread)
        self._ingest_thread.started.connect(self._ingest_worker.run)
        self._ingest_worker.finished.connect(self._on_folder_ingest_finished, Qt.QueuedConnection)
        self._ingest_worker.error.connect(self._on_folder_ingest_error, Qt.QueuedConnection)
        self._ingest_worker.finished.connect(self._ingest_thread.quit)
        self._ingest_worker.error.connect(self._ingest_thread.quit)
        self._ingest_worker.finished.connect(self._ingest_worker.deleteLater)
        self._ingest_worker.error.connect(self._ingest_worker.deleteLater)
        self._ingest_thread.finished.connect(self._cleanup_ingest_thread)
        self._ingest_thread.start()

    def _cleanup_ingest_thread(self) -> None:
        self._ingest_thread = None
        self._ingest_worker = None

    def _on_folder_ingest_error(self, message: str) -> None:
        self._pending_ingest_scan = None
        self._pending_ingest_folder = ""
        if self.import_session_active() and (
            getattr(self, "_import_cancel_requested", False) or self._import_pause_gate.is_aborted()
        ):
            return
        if self.import_session_active():
            from core.project_audit import record_project_activity

            record_project_activity(
                getattr(self.app, "current_project_id", None),
                "import_failed",
                f"Ingest: {message}",
            )
            self.end_import_session()
        self.app._message_dialog("Dataset folder", "Failed to index evidence files.", message, width=520)

    def _on_folder_ingest_finished(self, scan) -> None:
        folder = self._pending_ingest_folder
        purpose = getattr(self, "_ingest_purpose", "import")
        self._pending_ingest_scan = None
        self._pending_ingest_folder = ""
        if not folder:
            if purpose == "import":
                self.end_import_session()
            return
        QTimer.singleShot(0, lambda f=folder, s=scan, p=purpose: self._after_folder_ingest(f, s, p))

    def _after_folder_ingest(self, folder: str, scan, purpose: str) -> None:
        if purpose == "json_only":
            self._finish_load_dataset_path(folder, scan)
            return
        QTimer.singleShot(0, lambda f=folder, s=scan: self._begin_import_processing(f, s))

    def _show_import_status(self, message: str) -> None:
        banner = getattr(self.app, "lbl_project_banner", None)
        if banner is None:
            return
        if not self._import_status_restore:
            self._import_status_restore = banner.text()
        banner.setText(message)

    def _clear_import_status(self) -> None:
        banner = getattr(self.app, "lbl_project_banner", None)
        if banner is None:
            return
        if self._import_status_restore:
            banner.setText(self._import_status_restore)
        self._import_status_restore = ""

    def _begin_import_processing(self, folder: str, scan) -> None:
        self._import_finalize_completed = False
        self._import_finalize_pending = False
        self._import_session_paths = self._evidence_paths_from_scan(scan)
        self._import_plan = {
            "folder": folder,
            "scan": scan,
            "phase": "register",
            "opened": None,
            "json_load_started": False,
        }
        self._import_finalize_running = True
        self.update_import_progress(phase="Preparing imported evidence...", indeterminate=True)
        QTimer.singleShot(0, self._import_process_tick)

    def _import_process_tick(self) -> None:
        if self._import_pause_gate.is_aborted() or getattr(self, "_import_cancel_requested", False):
            return
        if self.import_session_active() and self._import_pause_gate.is_paused():
            self._refresh_import_progress_dialog()
            QTimer.singleShot(400, self._import_process_tick)
            return
        plan = self._import_plan
        if not plan:
            return
        folder = str(plan["folder"])
        scan = plan["scan"]
        phase = str(plan["phase"])
        try:
            if phase == "register":
                json_files = [item.path for item in scan.json_files]
                pcap_files = [item.path for item in scan.pcap_files]
                if not json_files and not pcap_files:
                    self._finish_import_processing(None)
                    return
                plan["json_files"] = json_files
                plan["pcap_files"] = pcap_files
                from core.project_audit import record_project_activity

                record_project_activity(
                    getattr(self.app, "current_project_id", None),
                    "import_started",
                    (
                        f"{folder} | {len(json_files):,} JSON, {len(pcap_files):,} PCAP"
                    ),
                )
                self._register_project_evidence_source(folder, scan, defer_workspace_sync=True)
                plan["phase"] = "json" if json_files else "pcap"
                QTimer.singleShot(0, self._import_process_tick)
                return

            if phase == "json":
                self.update_import_progress(phase="Configuring JSON periods...", indeterminate=True)
                opened = self._process_import_json_phase(folder, scan, plan)
                if opened:
                    plan["opened"] = opened
                project_id = getattr(self.app, "current_project_id", None)
                if project_id is not None:
                    self.sync_json_periods_from_project(project_id)
                plan["phase"] = "pcap" if plan.get("pcap_files") else "done"
                QTimer.singleShot(0, self._import_process_tick)
                return

            if phase == "pcap":
                self.update_import_progress(phase="Opening PCAP evidence...", indeterminate=True)
                if plan.get("pcap_files") and hasattr(self.app, "pcap_page"):
                    if plan.get("json_load_started") and self._thread_is_running(self._load_thread):
                        self._pending_pcap_after_json = (folder, scan)
                    else:
                        pcap_opened = self._open_scanned_pcap_files(folder, scan)
                        if pcap_opened:
                            plan["opened"] = pcap_opened
                plan["phase"] = "done"
                QTimer.singleShot(0, self._import_process_tick)
                return

            if phase == "done":
                self._finish_import_processing(plan.get("opened"))
        except Exception as exc:
            from core.project_audit import record_project_activity

            record_project_activity(
                getattr(self.app, "current_project_id", None),
                "import_failed",
                f"Prepare evidence: {exc}",
            )
            self._finish_import_processing(None)
            self.app._message_dialog(
                "Import evidence folder",
                "Failed to prepare imported evidence.",
                str(exc),
                width=520,
            )

    def _finish_import_processing(self, opened: str | None) -> None:
        self._import_plan = None
        self._import_finalize_running = False
        if getattr(self, "_import_finalize_pending", False):
            self.update_import_progress(
                phase="PCAP analysis",
                detail=self._pending_import_banner_message
                or "Batch PCAP analysis running. Progress updates appear here.",
                indeterminate=True,
            )
            return
        if self._thread_is_running(getattr(self, "_load_thread", None)):
            self._defer_import_finalize = True
            self.update_import_progress(
                phase="Loading JSON flows",
                detail="Finishing JSON import...",
                indeterminate=True,
            )
            return
        self._import_finalize_completed = True
        project_id = getattr(self.app, "current_project_id", None)
        if project_id is not None and not getattr(self, "_import_finalize_pending", False):
            self.deferred_sync_project_periods(project_id)
        self._record_import_completed(project_id)
        self._finalize_import_refresh()
        self.end_import_session()

    def _record_import_completed(self, project_id: int | None) -> None:
        from core.project_audit import record_project_activity

        record_project_activity(project_id, "import_completed", "Evidence import finished.")

    def _pending_pcap_plan_will_batch(self, pending: tuple[str, object] | None) -> bool:
        if pending is None:
            return False
        folder, scan = pending
        plan = self._plan_scanned_pcap_import(folder, scan)
        return bool(plan and plan.get("save_all_periods"))

    def complete_deferred_import_finalize(self) -> None:
        if getattr(self, "_import_finalize_completed", False):
            return
        if not getattr(self, "_import_finalize_pending", False):
            return
        self._import_finalize_completed = True
        self._import_finalize_pending = False
        self._defer_import_finalize = False
        self._pending_import_banner_message = ""
        project_id = getattr(self.app, "current_project_id", None)
        self._invalidate_pcap_ingest_day_groups_cache(project_id)
        if project_id is not None:
            self.deferred_sync_project_periods(project_id)
        self._record_import_completed(project_id)
        self._finalize_import_refresh()
        self.end_import_session()

    def _process_import_json_phase(self, folder: str, scan, plan: dict) -> str | None:
        json_files = list(plan.get("json_files") or [])
        if not json_files:
            return None

        json_day_groups = group_evidence_by_date(scan.json_files)
        if self._should_load_folder_interactively(len(json_files), scan.json_size):
            if len(json_day_groups) > 1:
                self._set_json_day_groups(folder, {
                    date: evidence_paths(items)
                    for date, items in json_day_groups.items()
                })
                self._apply_imported_period_as_default(scan.first_date, scan.last_date)
                paths = list(self._json_day_groups.get(self._json_active_day, []) or [])
                if paths:
                    self.load_dataset_files(folder, paths)
                    plan["json_load_started"] = True
            else:
                self._clear_json_day_groups()
                self.load_dataset_files(folder, [str(path) for path in json_files])
                plan["json_load_started"] = True
        else:
            day_groups_dict = {
                date: evidence_paths(items)
                for date, items in json_day_groups.items()
            }
            self._set_json_day_groups(folder, day_groups_dict)
            self._apply_imported_period_as_default(scan.first_date, scan.last_date)
            self._mark_large_json_source_indexed(
                folder,
                len(json_files),
                scan.json_size,
                day_count=len(day_groups_dict),
                defer_workspace_sync=True,
            )
            if getattr(self.app, "current_project_id", None) is not None:
                self._sync_project_metadata_from_json_files(
                    int(self.app.current_project_id),
                    [str(path) for path in json_files],
                )
            paths = list(self._json_day_groups.get(self._json_active_day, []) or [])
            if paths and len(paths) <= MAX_INTERACTIVE_FOLDER_JSON_FILES:
                self.load_dataset_files(folder, paths)
                plan["json_load_started"] = True
        return "json"

    def _finalize_import_refresh(self) -> None:
        project_id = getattr(self.app, "current_project_id", None)
        if project_id is None:
            return
        QTimer.singleShot(0, lambda pid=project_id: self._finalize_import_refresh_ui(pid))

    def _finalize_import_refresh_ui(self, project_id: int) -> None:
        if project_id != getattr(self.app, "current_project_id", None):
            return
        if hasattr(self.app, "notes_controller"):
            self.app.notes_controller.refresh_activity_ui_for_project(project_id)
        if hasattr(self.app, "projects_ui_controller"):
            self.app.projects_ui_controller.refresh_recent_datasets(project_id)
            self.app.projects_ui_controller.refresh_case_dashboard()
        QTimer.singleShot(0, lambda pid=project_id: self._finalize_import_profile(pid))

    def _finalize_import_profile(self, project_id: int) -> None:
        if project_id != getattr(self.app, "current_project_id", None):
            return
        if hasattr(self.app, "refresh_activity_profile_ui"):
            self.app.refresh_activity_profile_ui()
        QTimer.singleShot(0, lambda pid=project_id: self._finalize_import_workspace(pid))

    def _finalize_import_workspace(self, project_id: int) -> None:
        if project_id != getattr(self.app, "current_project_id", None):
            return
        if hasattr(self.app, "projects_ui_controller"):
            self.app.projects_ui_controller.sync_project_workspace(project_id)
        QTimer.singleShot(0, lambda pid=project_id: self.refresh_project_behavior_index(pid))

    def _flush_pending_pcap_open(self) -> None:
        pending = self._pending_pcap_after_json
        if pending is None:
            return
        self._pending_pcap_after_json = None
        folder, scan = pending
        QTimer.singleShot(0, lambda: self._open_scanned_pcap_files(folder, scan))

    def _plan_scanned_pcap_import(self, folder: str, scan) -> dict | None:
        pcap_files = [item.path for item in scan.pcap_files]
        if not pcap_files or not hasattr(self.app, "pcap_page"):
            return None

        statuses = ingest_status_map(self.app.current_project_id, evidence_paths(scan.pcap_files))
        pending_pcap_files = [
            item
            for item in scan.pcap_files
            if statuses.get(str(item.path)) != "done"
        ]
        if not pending_pcap_files:
            return {"empty": True, "pcap_total": len(pcap_files)}

        pcap_day_groups = group_evidence_by_date(pending_pcap_files)
        use_batch = should_batch_pcap_files(len(pending_pcap_files), scan.pcap_size)
        multi_period = len(pcap_day_groups) > 1
        save_all_periods = use_batch or multi_period
        skipped = len(pcap_files) - len(pending_pcap_files)
        skipped_note = f" ({skipped:,} already processed skipped.)" if skipped else ""

        return {
            "folder": folder,
            "pcap_total": len(pcap_files),
            "pending_count": len(pending_pcap_files),
            "pcap_size": int(getattr(scan, "pcap_size", 0) or 0),
            "pending_paths": evidence_paths(pending_pcap_files),
            "day_groups": {
                date: evidence_paths(items)
                for date, items in pcap_day_groups.items()
            },
            "period_start": str(getattr(scan, "first_date", "") or ""),
            "period_end": str(getattr(scan, "last_date", "") or ""),
            "save_all_periods": save_all_periods,
            "use_batch": use_batch,
            "interactive": self._should_load_folder_interactively(len(pending_pcap_files), scan.pcap_size),
            "banner_message": (
                f"Import: {len(pending_pcap_files):,} PCAP files indexed; "
                f"batch analysis running on PCAP page.{skipped_note}"
            ),
        }

    def _open_scanned_pcap_files(self, folder: str, scan) -> str | None:
        plan = self._plan_scanned_pcap_import(folder, scan)
        if plan is None:
            return None
        if plan.get("empty"):
            if self.app.current_project_id is not None:
                self.sync_pcap_periods_from_project(self.app.current_project_id)
            self.app.go_page(self.app.IDX_PCAP, self.app._nav_pcap)
            self.app._message_dialog(
                "PCAP folder",
                f"{int(plan.get('pcap_total') or 0):,} PCAP files were found.",
                "All PCAP files from this source are already marked as processed for the active project. "
                "Use the Period selector on the PCAP page to open saved analysis or re-analyze source files.",
                width=560,
            )
            return "pcap"

        if plan.get("save_all_periods"):
            self._import_finalize_pending = True
            self._import_finalize_completed = False
            self._pending_import_banner_message = str(plan.get("banner_message") or "")

        self.app.go_page(self.app.IDX_PCAP, self.app._nav_pcap)
        QTimer.singleShot(0, lambda p=plan: self._execute_scanned_pcap_import(p))
        return "pcap"

    def _execute_scanned_pcap_import(self, plan: dict) -> None:
        if not plan or not hasattr(self.app, "pcap_page"):
            return

        folder = str(plan.get("folder") or "")
        pending_paths = list(plan.get("pending_paths") or [])
        day_groups = dict(plan.get("day_groups") or {})
        period_start = str(plan.get("period_start") or "")
        period_end = str(plan.get("period_end") or "")
        pending_count = int(plan.get("pending_count") or 0)
        pcap_total = int(plan.get("pcap_total") or pending_count)
        pcap_size = int(plan.get("pcap_size") or 0)
        save_all_periods = bool(plan.get("save_all_periods"))
        use_batch = bool(plan.get("use_batch"))

        if save_all_periods:
            self.app.pcap_page.load_pcap_queue(
                pending_paths,
                auto_save=True,
                auto_process=True,
                day_groups=day_groups,
                period_start=period_start,
                period_end=period_end,
            )
            return

        if bool(plan.get("interactive")):
            self.app.pcap_page.load_pcap_queue(
                pending_paths,
                auto_save=True,
                auto_process=False,
                day_groups=day_groups,
                period_start=period_start,
                period_end=period_end,
            )
            mode_text = (
                "ViaNyquist opened the first selected period for interactive review. "
                f"Use the {PERIOD_LABEL.strip(':')} selector on the PCAP page to switch days."
            )
        else:
            self._mark_large_pcap_source_indexed(
                folder,
                pending_count,
                pcap_size,
                pending_paths=pending_paths,
                day_groups=day_groups,
            )
            mode_text = indexed_source_message(pcap_files=pending_count)

        if pending_count > 1 or use_batch:
            skipped = pcap_total - pending_count
            skipped_text = f"\n\nSkipped already processed PCAP files: {skipped:,}." if skipped else ""
            self.app._message_dialog(
                "Import evidence folder",
                f"{pcap_total:,} PCAP files found in the selected period.",
                f"{mode_text}{skipped_text}",
                width=620,
            )

    def _start_scanned_pcap_import(self, folder: str, scan) -> None:
        plan = self._plan_scanned_pcap_import(folder, scan)
        if plan is not None and not plan.get("empty"):
            self._execute_scanned_pcap_import(plan)

    def _json_files_in_folder(self, folder: str) -> list[Path]:
        try:
            return list_json_files_recursive(folder)
        except Exception:
            return []

    def _pcap_files_in_folder(self, folder: str) -> list[Path]:
        path = Path(folder)
        if not path.exists() or not path.is_dir():
            return []
        return sorted(
            [
                item for item in path.rglob("*")
                if item.is_file() and item.suffix.lower() in {".pcap", ".pcapng", ".cap"}
            ],
            key=lambda item: str(item).casefold(),
        )

    def _should_load_folder_interactively(self, json_count: int, byte_count: int) -> bool:
        return should_open_interactively(json_count, byte_count)

    def _select_case_ingest_scope(self, scan):
        if not (scan.first_date and scan.last_date):
            return scan if self._confirm_case_ingest(scan) else None

        choice = self.app._choice_dialog(
            title="Import evidence folder",
            message="ViaNyquist scanned the selected folder/disk.",
            choices=["Import all", "Choose date range", "Cancel"],
            width=620,
        )
        if choice == "Cancel" or not choice:
            return None
        if choice == "Import all":
            return scan if self._confirm_case_ingest(scan) else None

        filtered = self._date_range_case_ingest_dialog(scan)
        if filtered is None:
            return None
        return filtered if self._confirm_case_ingest(filtered) else None

    def _date_range_case_ingest_dialog(self, scan):
        first = QDate.fromString(scan.first_date, "yyyy-MM-dd")
        last = QDate.fromString(scan.last_date, "yyyy-MM-dd")
        if not first.isValid() or not last.isValid():
            return scan

        dlg = QDialog(self.app)
        dlg.setWindowTitle("Select evidence period")
        dlg.setMinimumWidth(560)

        root = QVBoxLayout(dlg)
        root.setContentsMargins(20, 18, 20, 28)
        root.setSpacing(14)
        intro = QLabel(
            "Select the period to import. Files outside this range will stay untouched "
            "and can be imported later from the same source."
        )
        intro.setWordWrap(True)
        root.addWidget(intro)

        detected = QLabel(
            f"Detected period: {self._display_scan_period(scan)}\n"
            f"Available files: {len(scan.json_files):,} JSON, {len(scan.pcap_files):,} PCAP"
        )
        detected.setObjectName("Muted")
        detected.setWordWrap(True)
        root.addWidget(detected)

        form = QFormLayout()
        from ui.dialogs import _style_dialog_buttons, period_date_edit

        start_edit = period_date_edit(first, first, last)
        end_edit = period_date_edit(last, first, last)

        include_undated = QCheckBox("Include files without detected date")
        include_undated.setChecked(False)
        form.addRow("From:", start_edit)
        form.addRow("To:", end_edit)
        form.addRow("", include_undated)
        root.addLayout(form)

        summary = QLabel()
        summary.setObjectName("Muted")
        summary.setWordWrap(True)
        root.addWidget(summary)

        def current_filtered():
            start = start_edit.date().toString("yyyy-MM-dd")
            end = end_edit.date().toString("yyyy-MM-dd")
            if start > end:
                start, end = end, start
            return filter_case_scan(
                scan,
                start_date=start,
                end_date=end,
                include_undated=include_undated.isChecked(),
            )

        def update_summary():
            selected = current_filtered()
            summary.setText(
                f"Selected files: {len(selected.json_files):,} JSON, {len(selected.pcap_files):,} PCAP | "
                f"Size: {human_bytes(selected.total_size, precision=2)}"
            )

        start_edit.dateChanged.connect(update_summary)
        end_edit.dateChanged.connect(update_summary)
        include_undated.toggled.connect(update_summary)
        update_summary()

        buttons = QDialogButtonBox()
        btn_import = buttons.addButton("Import selected period", QDialogButtonBox.AcceptRole)
        buttons.addButton("Cancel", QDialogButtonBox.RejectRole)
        _style_dialog_buttons(buttons)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        root.addSpacing(6)
        root.addWidget(buttons)

        if dlg.exec() != QDialog.Accepted:
            return None

        selected = current_filtered()
        if not selected.file_count:
            self.app._message_dialog(
                "Import evidence folder",
                "No files match the selected period.",
                "Choose a wider date range or import the full source.",
                width=520,
            )
            return None
        return selected

    def _confirm_case_ingest(self, scan) -> bool:
        period = self._display_scan_period(scan)
        details = (
            f"Source: {scan.root}\n"
            f"JSON files: {len(scan.json_files):,}\n"
            f"PCAP files: {len(scan.pcap_files):,}\n"
            f"Total size: {human_bytes(scan.total_size, precision=2)}\n"
            f"Detected period: {period}"
        )
        if scan.skipped_dirs:
            details += f"\nSkipped folders: {scan.skipped_dirs:,}"
        if not self._should_load_folder_interactively(len(scan.json_files), scan.json_size):
            details += (
                "\n\nLarge JSON source: ViaNyquist will index the selection for the project "
                "and skip immediate table loading. Use the Period selector to open one day at a time."
            )
        if scan.pcap_files and should_batch_pcap_files(len(scan.pcap_files), scan.pcap_size):
            details += (
                "\n\nLarge PCAP source: ViaNyquist will analyze PCAP files in the background "
                "(one file at a time) and save results to the project."
            )
        return self.app._confirm_dialog(
            title="Import evidence folder",
            message="ViaNyquist scanned the selected folder/disk.",
            details=details,
            ok_text="Import",
            cancel_text="Cancel",
            width=640,
        )

    def _display_scan_period(self, scan) -> str:
        first = self._display_scan_date(scan.first_date)
        last = self._display_scan_date(scan.last_date)
        if first and last:
            return f"{first} - {last}"
        return first or last or "-"

    def _display_scan_date(self, value: str) -> str:
        date = QDate.fromString(str(value or ""), "yyyy-MM-dd")
        if not date.isValid():
            return str(value or "")
        return date.toString("dd.MM.yyyy")

    def _register_project_evidence_source(self, folder: str, scan, *, defer_workspace_sync: bool = False) -> None:
        """Register imported evidence period on the project (same idea as JSON dataset load)."""
        project_id = self.app.current_project_id
        if project_id is None:
            return

        self._import_session_registered = True
        if not self._import_session_paths:
            self._import_session_paths = self._evidence_paths_from_scan(scan)

        add_dataset_load(project_id, folder)
        json_paths = [
            str(getattr(item, "path", "") or "")
            for item in (getattr(scan, "json_files", None) or [])
            if str(getattr(item, "path", "") or "").strip()
        ]
        if json_paths:
            self._sync_project_metadata_from_json_files(project_id, json_paths)
        update_dataset_scan_metadata(
            project_id,
            folder,
            json_file_count=len(scan.json_files),
            pcap_file_count=len(scan.pcap_files),
            total_size=scan.total_size,
            first_observed=scan.first_date,
            last_observed=scan.last_date,
        )
        if defer_workspace_sync:
            return
        if hasattr(self.app, "projects_ui_controller"):
            self.app.projects_ui_controller.sync_project_workspace(project_id)
            QTimer.singleShot(0, lambda pid=project_id: self._deferred_project_refresh(pid))

    def _deferred_project_refresh(self, project_id: int | None) -> None:
        if project_id is None or project_id != getattr(self.app, "current_project_id", None):
            return
        if not hasattr(self.app, "projects_ui_controller"):
            return
        self.app.projects_ui_controller.refresh_recent_datasets(project_id)
        self.app.projects_ui_controller.refresh_case_dashboard()

    @staticmethod
    def _evidence_paths_from_scan(scan) -> list[str]:
        paths: list[str] = []
        for item in list(getattr(scan, "json_files", None) or []) + list(getattr(scan, "pcap_files", None) or []):
            path = str(getattr(item, "path", "") or "")
            if path and path not in paths:
                paths.append(path)
        return paths

    def _sync_project_metadata_from_json_files(self, project_id: int, json_paths: list[str]) -> None:
        if not project_id or not json_paths:
            return
        try:
            from core.case_metadata import sync_project_from_json_files

            sync_project_from_json_files(int(project_id), json_paths)
        except Exception:
            return
        if int(project_id) != getattr(self.app, "current_project_id", None):
            return
        if hasattr(self.app, "projects_ui_controller"):
            self.app.projects_ui_controller.on_project_selected_preview()
            self.app.projects_ui_controller.refresh_case_dashboard()

    def _json_day_groups_from_ingest(self, project_id: int | None, folder_prefix: str = "") -> dict[str, list[str]]:
        if project_id is None:
            return {}
        from core.project_evidence import json_day_groups_from_ingest

        return json_day_groups_from_ingest(int(project_id), folder_prefix=folder_prefix)

    def _mark_large_json_source_indexed(self, folder: str, file_count: int, byte_count: int, *, day_count: int = 0, defer_workspace_sync: bool = False) -> None:
        if hasattr(self.app, "lbl_path"):
            self.app.lbl_path.setText(f"Indexed JSON source: {folder}")
        periods_note = f"{day_count} periods in Period selector" if day_count else "Select Period to load a day"
        if hasattr(self.app, "lbl_stats"):
            self.app.explore_ui_controller.set_json_stats_text(
                f"JSON files indexed: {file_count:,} | Size: {human_bytes(byte_count, precision=2)} | "
                f"{periods_note} — pick a day to load flows into the table.",
                include_counts=False,
            )
        if hasattr(self.app, "lbl_json_meta"):
            self.app.lbl_json_meta.setText("")
        if defer_workspace_sync:
            return
        if hasattr(self.app, "projects_ui_controller"):
            self.app.projects_ui_controller.sync_project_workspace(self.app.current_project_id)
            self.app.projects_ui_controller.refresh_recent_datasets(self.app.current_project_id)
            self.app.projects_ui_controller.refresh_case_dashboard()
        if hasattr(self.app, "notes_controller"):
            self.app.notes_controller.refresh_activity_ui()
        if hasattr(self.app, "refresh_activity_profile_ui"):
            self.app.refresh_activity_profile_ui()
        self.refresh_project_behavior_index(self.app.current_project_id)

    def _mark_large_pcap_source_indexed(
        self,
        folder: str,
        file_count: int,
        byte_count: int,
        *,
        pending_paths: list[str] | None = None,
        day_groups: dict[str, list[str]] | None = None,
        defer_workspace_sync: bool = False,
    ) -> None:
        if hasattr(self.app, "pcap_page"):
            if day_groups and hasattr(self.app.pcap_page, "_set_day_groups"):
                self.app.pcap_page._set_day_groups(day_groups)
            elif pending_paths:
                self.app.pcap_page.load_pcap_queue(pending_paths, auto_save=False, auto_process=False)
        if hasattr(self.app, "lbl_stats"):
            self.app.lbl_stats.setText(
                f"PCAP files indexed: {file_count:,} | Size: {human_bytes(byte_count, precision=2)} | "
                "Use Period on the PCAP page or start background analysis from the batch panel."
            )
        if defer_workspace_sync:
            return
        if hasattr(self.app, "projects_ui_controller"):
            self.app.projects_ui_controller.sync_project_workspace(self.app.current_project_id)
            self.app.projects_ui_controller.refresh_recent_datasets(self.app.current_project_id)
            self.app.projects_ui_controller.refresh_case_dashboard()
        if hasattr(self.app, "refresh_activity_profile_ui"):
            self.app.refresh_activity_profile_ui()
