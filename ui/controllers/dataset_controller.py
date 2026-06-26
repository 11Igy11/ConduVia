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
    from core.case_metadata import format_order_datetime

    if bt or et:
        validity = f"{format_order_datetime(bt, missing='-')} -> {format_order_datetime(et, missing='-')}"
    else:
        validity = "-"
    return (
        f"Klasa: {klasa}   |   Urbroj: {urbroj}   |   Target: {target_label}   |   "
        f"LIID: {liid}   |   Order validity: {validity}"
    )


class DatasetController(QObject):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self._load_thread: QThread | None = None
        self._load_worker: DatasetLoadWorker | None = None
        self._scan_thread: QThread | None = None
        self._scan_worker: CaseScanWorker | None = None
        self._scan_progress = None
        self._scan_purpose = "import"
        self._ingest_thread: QThread | None = None
        self._ingest_worker: FolderIngestWorker | None = None
        self._ingest_progress = None
        self._pending_ingest_scan = None
        self._pending_ingest_folder = ""
        self._behavior_index_thread: QThread | None = None
        self._behavior_index_worker: BehaviorIndexWorker | None = None
        self._json_day_groups: dict[str, list[str]] = {}
        self._json_day_groups_raw: dict[str, list[str]] = {}
        self._json_period_granularity = "day"
        self._json_period_range_start = ""
        self._json_period_range_end = ""
        self._json_day_source = ""
        self._json_active_day = ""
        self._json_day_switching = False
        self._json_active_file = ""
        self._json_file_switching = False
        self._json_gap_info: dict[str, object] = {}
        self._pending_behavior_index_project_id: int | None = None
        self._pending_pcap_after_json: tuple[str, object] | None = None
        self._dataset_load_progress = None
        self._import_finalize_running = False
        self._import_plan: dict | None = None
        self._import_status_restore = ""
        self._defer_import_finalize = False
        self._pending_import_banner_message = ""
        self._import_finalize_completed = False
        self._import_finalize_pending = False

    def behavior_index_running(self) -> bool:
        return self._behavior_index_thread is not None

    def should_defer_profile_heavy_work(self) -> bool:
        if (
            self._import_finalize_running
            or getattr(self, "_import_finalize_pending", False)
            or getattr(self, "_defer_import_finalize", False)
        ):
            return True
        if self.behavior_index_running():
            return True
        pcap_page = getattr(self.app, "pcap_page", None)
        if pcap_page is not None and pcap_page.batch_is_running():
            return True
        return False

    def _thread_is_running(self, thread: QThread | None) -> bool:
        return thread is not None and thread.isRunning()

    def _close_scan_progress(self) -> None:
        if self._scan_progress is not None:
            self._scan_progress.close()
            self._scan_progress = None

    def _close_ingest_progress(self) -> None:
        if self._ingest_progress is not None:
            self._ingest_progress.close()
            self._ingest_progress = None

    def _close_dataset_load_progress(self) -> None:
        bar = getattr(self.app, "json_load_progress", None)
        if bar is not None:
            bar.hide()
            bar.setRange(0, 100)
            bar.setValue(0)
        lbl = getattr(self.app, "lbl_json_load_progress", None)
        if lbl is not None:
            lbl.hide()
            lbl.clear()
        self._dataset_load_progress = None
        self._sync_json_gap_visibility()

    def _show_dataset_load_progress(self, *, file_count: int, period_label: str = "") -> None:
        self._close_dataset_load_progress()
        bar = getattr(self.app, "json_load_progress", None)
        if bar is None:
            return
        label = period_label or "Loading JSON period..."
        if file_count > 1:
            bar.setRange(0, file_count)
            bar.setValue(0)
            progress_text = f"0 / {file_count} — {label}"
        else:
            bar.setRange(0, 0)
            progress_text = label
        lbl = getattr(self.app, "lbl_json_load_progress", None)
        if lbl is not None:
            lbl.setText(progress_text)
            lbl.show()
        bar.show()
        self._sync_json_gap_visibility()
        self._dataset_load_progress = bar

    @Slot(int, int, str)
    def _on_dataset_load_progress(self, current: int, total: int, file_name: str) -> None:
        bar = self._dataset_load_progress or getattr(self.app, "json_load_progress", None)
        if bar is None:
            return
        if total > 0:
            bar.setRange(0, total)
            bar.setValue(current)
            progress_text = f"{current} / {total} — {file_name}"
        else:
            progress_text = file_name
        lbl = getattr(self.app, "lbl_json_load_progress", None)
        if lbl is not None and progress_text:
            lbl.setText(progress_text)
            lbl.show()

    def _split_ranked_lines(self, items):
        left_lines = []
        right_lines = []

        for i, (name, count) in enumerate(items, start=1):
            left_lines.append(f"{i}. {name}")
            right_lines.append(str(count))

        return "\n".join(left_lines), "\n".join(right_lines)

    def clear_summary_preview_rows(self, rows, *, message: str = "") -> None:
        for index, (name_lbl, count_lbl) in enumerate(rows):
            if index == 0 and message:
                name_lbl.setText(message)
            else:
                name_lbl.setText("")
            count_lbl.setText("")

    def _fill_summary_preview_rows(self, rows, items) -> None:
        if not rows:
            return
        fm = QFontMetrics(rows[0][0].font())
        name_w = max(SUMMARY_CARD_WIDTH - SUMMARY_CARD_PADDING - SUMMARY_VALUE_COL_WIDTH - 6, 80)

        for index, (name_lbl, count_lbl) in enumerate(rows):
            if index < len(items):
                name, count = items[index]
                label = f"{index + 1}. {name}"
                name_lbl.setText(fm.elidedText(label, Qt.ElideRight, name_w))
                count_lbl.setText(str(count))
            else:
                name_lbl.setText("")
                count_lbl.setText("")

    def _start_folder_scan(self, folder: str, *, purpose: str = "import") -> None:
        if self._thread_is_running(self._scan_thread):
            self.app._message_dialog("Dataset folder", "A folder scan is already running.", width=420)
            return

        self._scan_purpose = purpose
        title = "Import evidence folder" if purpose == "import" else "Scan dataset folder"
        self._scan_progress = QProgressDialog("Scanning evidence folder...", None, 0, 0, self.app)
        self._scan_progress.setWindowTitle(title)
        self._scan_progress.setWindowModality(Qt.NonModal)
        self._scan_progress.setMinimumDuration(0)
        self._scan_progress.setCancelButton(None)
        self._scan_progress.setMinimumWidth(460)
        self._scan_progress.show()

        def _kickoff_scan() -> None:
            self._scan_thread = QThread(self.app)
            self._scan_worker = CaseScanWorker(folder)
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

    @Slot()
    def _cleanup_scan_thread(self) -> None:
        self._scan_thread = None
        self._scan_worker = None
        self._close_scan_progress()

    @Slot(str)
    def _on_folder_scan_error(self, message: str) -> None:
        self._close_scan_progress()
        self.app._message_dialog("Dataset folder", "Failed to scan selected folder.", message, width=520)

    @Slot(object)
    def _on_folder_scan_finished(self, scan) -> None:
        folder = str(getattr(scan, "root", "") or "")
        purpose = self._scan_purpose
        self._scan_purpose = "import"
        self._close_scan_progress()
        if not folder:
            return
        QTimer.singleShot(0, lambda f=folder, s=scan, p=purpose: self._after_folder_scan(f, s, p))

    def _after_folder_scan(self, folder: str, scan, purpose: str) -> None:
        if purpose == "json_only":
            self._start_folder_ingest(folder, scan, purpose="json_only")
            return

        scoped = self._select_case_ingest_scope(scan)
        if scoped is None:
            return
        self._start_folder_ingest(folder, scoped, purpose="import")

    def _start_folder_ingest(self, folder: str, scan, *, purpose: str = "import") -> None:
        if self._thread_is_running(self._ingest_thread):
            self.app._message_dialog("Dataset folder", "Evidence indexing is already running.", width=420)
            return

        project_id = getattr(self.app, "current_project_id", None)
        if project_id is None:
            return

        self.reset_dataset_views()

        total_files = len(scan.json_files or []) + len(scan.pcap_files or [])
        self._pending_ingest_scan = scan
        self._pending_ingest_folder = folder
        self._ingest_purpose = purpose

        self._ingest_progress = QProgressDialog(
            f"Indexing {total_files:,} evidence files...",
            None,
            0,
            0,
            self.app,
        )
        self._ingest_progress.setWindowTitle("Index evidence")
        self._ingest_progress.setWindowModality(Qt.NonModal)
        self._ingest_progress.setMinimumDuration(0)
        self._ingest_progress.setCancelButton(None)
        self._ingest_progress.setMinimumWidth(460)
        self._ingest_progress.show()

        self._ingest_thread = QThread(self.app)
        self._ingest_worker = FolderIngestWorker(project_id, folder, scan)
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

    @Slot()
    def _cleanup_ingest_thread(self) -> None:
        self._ingest_thread = None
        self._ingest_worker = None
        self._close_ingest_progress()

    @Slot(str)
    def _on_folder_ingest_error(self, message: str) -> None:
        self._close_ingest_progress()
        self._pending_ingest_scan = None
        self._pending_ingest_folder = ""
        self.app._message_dialog("Dataset folder", "Failed to index evidence files.", message, width=520)

    @Slot(object)
    def _on_folder_ingest_finished(self, scan) -> None:
        folder = self._pending_ingest_folder
        purpose = getattr(self, "_ingest_purpose", "import")
        self._close_ingest_progress()
        self._pending_ingest_scan = None
        self._pending_ingest_folder = ""
        if not folder:
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
        self._import_plan = {
            "folder": folder,
            "scan": scan,
            "phase": "register",
            "opened": None,
            "json_load_started": False,
        }
        self._import_finalize_running = True
        self._show_import_status("Preparing imported evidence…")
        QTimer.singleShot(0, self._import_process_tick)

    def _import_process_tick(self) -> None:
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
                self._register_project_evidence_source(folder, scan, defer_workspace_sync=True)
                plan["phase"] = "json" if json_files else "pcap"
                QTimer.singleShot(0, self._import_process_tick)
                return

            if phase == "json":
                self._show_import_status("Configuring JSON periods…")
                opened = self._process_import_json_phase(folder, scan, plan)
                if opened:
                    plan["opened"] = opened
                plan["phase"] = "pcap" if plan.get("pcap_files") else "done"
                QTimer.singleShot(0, self._import_process_tick)
                return

            if phase == "pcap":
                self._show_import_status("Opening PCAP evidence…")
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
            self._show_import_status(
                self._pending_import_banner_message
                or "PCAP batch analysis running — see the PCAP page for progress."
            )
            return
        self._clear_import_status()
        self._import_finalize_completed = True
        self._finalize_import_refresh()

    def complete_deferred_import_finalize(self) -> None:
        if getattr(self, "_import_finalize_completed", False):
            return
        if not getattr(self, "_import_finalize_pending", False):
            return
        self._import_finalize_completed = True
        self._import_finalize_pending = False
        self._defer_import_finalize = False
        self._pending_import_banner_message = ""
        self._clear_import_status()
        pcap_page = getattr(self.app, "pcap_page", None)
        if pcap_page is not None and getattr(pcap_page, "_pcap_day_groups_raw", None):
            pcap_page._update_period_gap_banner(list(pcap_page._pcap_day_groups_raw.keys()))
            pcap_page._sync_period_gap_visibility()
        self._finalize_import_refresh()

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

    def _process_scanned_folder(self, folder: str, scan, *, defer_workspace_sync: bool = False) -> str | None:
        """Legacy single-pass import helper; interactive import uses _import_process_tick."""
        plan: dict = {"json_load_started": False, "pcap_files": [item.path for item in scan.pcap_files]}
        opened = self._process_import_json_phase(folder, scan, plan)
        pcap_files = plan.get("pcap_files") or []
        if pcap_files and hasattr(self.app, "pcap_page"):
            if plan.get("json_load_started") and self._thread_is_running(self._load_thread):
                self._pending_pcap_after_json = (folder, scan)
                return opened or "json"
            pcap_opened = self._open_scanned_pcap_files(folder, scan)
            if pcap_opened:
                return pcap_opened
        return opened

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

    def load_dataset_dialog(self):
        if not self._ensure_active_project():
            return None

        choice = self.app._choice_dialog(
            title="Open dataset",
            message="What do you want to open?",
            choices=["Folder", "JSON file", "PCAP file"],
            width=540,
        )

        if choice == "Folder":
            folder = QFileDialog.getExistingDirectory(self.app, "Select dataset folder or evidence disk")
            if not folder:
                return None
            self._start_folder_scan(folder)
            return None

        if choice == "JSON file":
            file_path, _ = QFileDialog.getOpenFileName(
                self.app,
                "Select JSON file",
                "",
                "JSON files (*.json)",
            )
            if not file_path:
                return None
            self.load_dataset_file(file_path)
            return "json"

        if choice == "PCAP file":
            file_path, _ = QFileDialog.getOpenFileName(
                self.app,
                "Select PCAP file",
                "",
                "Capture files (*.pcap *.pcapng);;All files (*.*)",
            )
            if not file_path:
                return None
            if hasattr(self.app, "pcap_page"):
                self.app.go_page(self.app.IDX_PCAP, self.app._nav_pcap)
                self.app.pcap_page.load_pcap(file_path)
            return "pcap"

        return None

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
        from ui.dialogs import period_date_edit

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
        for button in buttons.buttons():
            button.setMinimumHeight(42)
            button.setMinimumWidth(110)
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

        add_dataset_load(project_id, folder)
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

    def _json_day_groups_from_ingest(self, project_id: int | None, folder_prefix: str = "") -> dict[str, list[str]]:
        if project_id is None:
            return {}
        prefix_key = ""
        if folder_prefix:
            try:
                prefix_key = str(Path(folder_prefix).resolve()).casefold()
            except Exception:
                prefix_key = str(folder_prefix).casefold()

        by_day: dict[str, list[str]] = {}
        for item in list_ingest_items(project_id, file_type="json", limit=50000):
            path = str(item.file_path or "").strip()
            if not path or not Path(path).is_file():
                continue
            if prefix_key:
                try:
                    if not str(Path(path).resolve()).casefold().startswith(prefix_key):
                        continue
                except Exception:
                    if prefix_key not in path.casefold():
                        continue
            day = str(item.observed_date or "undated").strip() or "undated"
            if path not in by_day.setdefault(day, []):
                by_day[day].append(path)
        return by_day

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

    def render_summary(self):
        flows = self.app.flow_controller.get_all()
        preview = EMBEDDED_SUMMARY_TOP_N
        rows_by_key = getattr(self.app, "summary_preview_rows", {})

        if not flows:
            for rows in rows_by_key.values():
                self.clear_summary_preview_rows(rows, message="No flows loaded.")
            for button in getattr(self.app, "summary_expand_buttons", {}).values():
                button.setEnabled(False)
            return

        src_items = top_src_ips(flows, limit=preview)
        dst_items = top_dst_ips(flows, limit=preview)
        proto_items = [(format_ip_proto(proto), c) for proto, c in top_protocols(flows, limit=preview)]
        app_items = top_applications(flows, limit=preview)

        dataset_items = {
            "src": src_items,
            "dst": dst_items,
            "proto": proto_items,
            "apps": app_items,
        }
        for key, items in dataset_items.items():
            rows = rows_by_key.get(key)
            if rows is not None:
                self._fill_summary_preview_rows(rows, items)

        for key, button in getattr(self.app, "summary_expand_buttons", {}).items():
            if key == "src":
                total = len(top_src_ips(flows, limit=100000))
            elif key == "dst":
                total = len(top_dst_ips(flows, limit=100000))
            elif key == "proto":
                total = len(top_protocols(flows, limit=100000))
            else:
                total = len(top_applications(flows, limit=100000))
            button.setEnabled(total > preview)
            if total > preview:
                button.setToolTip(f"{total:,} rows — embedded view shows top {preview}.")
            else:
                button.setToolTip("")

    def expand_dataset_summary(self, kind: str) -> None:
        flows = self.app.flow_controller.get_all()
        if not flows:
            self.app._message_dialog("Dataset summary", "No flows loaded.", width=380)
            return

        if kind == "src":
            title = "Top source IPs"
            rows = [{"rank": idx, "value": name, "count": count} for idx, (name, count) in enumerate(top_src_ips(flows, limit=100000), start=1)]
        elif kind == "dst":
            title = "Top destination IPs"
            rows = [{"rank": idx, "value": name, "count": count} for idx, (name, count) in enumerate(top_dst_ips(flows, limit=100000), start=1)]
        elif kind == "proto":
            title = "Top protocols"
            rows = [{"rank": idx, "value": format_ip_proto(proto), "count": count} for idx, (proto, count) in enumerate(top_protocols(flows, limit=100000), start=1)]
        elif kind == "apps":
            title = "Top applications"
            rows = [{"rank": idx, "value": name, "count": count} for idx, (name, count) in enumerate(top_applications(flows, limit=100000), start=1)]
        else:
            return

        source_label = str(getattr(self.app, "current_folder", "") or self._json_day_source or "")
        open_project_rows_dialog(
            self.app,
            title,
            [("rank", "#"), ("value", "Name"), ("count", "Count")],
            rows,
            export_source_label=source_label,
        )

    def load_dataset_path(self, folder: str):
        if not self._ensure_active_project():
            return

        folder = str(folder)
        path = Path(folder)
        if not path.exists():
            self.app._message_dialog("Dataset", "Folder not found.", folder, width=480)
            return

        self._start_folder_scan(folder, purpose="json_only")

    def _finish_load_dataset_path(self, folder: str, scan) -> None:
        json_files = [item.path for item in scan.json_files]
        if not json_files:
            self.app._message_dialog("Dataset folder", "No JSON files were found in the selected folder.", folder, width=520)
            return

        add_dataset_load(self.app.current_project_id, folder)
        update_dataset_scan_metadata(
            self.app.current_project_id,
            folder,
            json_file_count=len(scan.json_files),
            pcap_file_count=len(scan.pcap_files),
            total_size=scan.total_size,
            first_observed=scan.first_date,
            last_observed=scan.last_date,
        )

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
            else:
                self._clear_json_day_groups()
                self.load_dataset_files(folder, [str(path) for path in json_files])
        else:
            day_groups_dict = {
                date: evidence_paths(items)
                for date, items in json_day_groups.items()
            }
            self._set_json_day_groups(folder, day_groups_dict)
            self._apply_imported_period_as_default(scan.first_date, scan.last_date)
            self._mark_large_json_source_indexed(folder, len(json_files), scan.json_size, day_count=len(day_groups_dict))
            paths = list(self._json_day_groups.get(self._json_active_day, []) or [])
            if paths and len(paths) <= MAX_INTERACTIVE_FOLDER_JSON_FILES:
                self.load_dataset_files(folder, paths)

    def _upsert_json_ingest_items(self, source_root: str, items) -> None:
        project_id = getattr(self.app, "current_project_id", None)
        if project_id is None:
            return
        item_rows = [
            {
                "file_path": str(item.path),
                "file_name": item.path.name,
                "file_type": "json",
                "file_size": item.size,
                "observed_date": item.observed_date,
            }
            for item in items
        ]
        upsert_ingest_items(
            project_id,
            source_root,
            item_rows,
        )
        mark_ingest_items_batch(
            project_id,
            [row["file_path"] for row in item_rows],
            "done",
        )

    def load_dataset_file(self, file_path: str):
        if not self._ensure_active_project():
            return

        file_path = str(file_path)
        fp = Path(file_path)

        if not fp.exists() or not fp.is_file():
            self.app._message_dialog("Dataset", "File not found.", file_path, width=480)
            return

        self.reset_loaded_flow_views()
        previous_path = self._get_previous_dataset_path(file_path)
        self._start_dataset_load("file", file_path, previous_path)

    def load_dataset_files(self, source_path: str, files: list[str], *, progress_label: str = ""):
        if not self._ensure_active_project():
            return

        if not files:
            return

        self.reset_loaded_flow_views()
        previous_path = self._get_previous_dataset_path(source_path)
        self._start_dataset_load(
            "files",
            source_path,
            previous_path,
            files=files,
            progress_label=progress_label,
        )

    def _apply_imported_period_as_default(self, start: str = "", end: str = "") -> None:
        from core.period_gaps import normalize_period_day

        start_day = normalize_period_day(start)
        end_day = normalize_period_day(end)
        if not start_day or not end_day:
            days = sorted(
                normalize_period_day(day)
                for day in self._json_day_groups_raw.keys()
                if normalize_period_day(day)
            )
            if not days:
                return
            start_day, end_day = days[0], days[-1]

        self._json_period_range_start = start_day
        self._json_period_range_end = end_day
        self._json_period_granularity = "range"

        mode_combo = getattr(self.app, "cmb_json_period_mode", None)
        if mode_combo is not None:
            mode_combo.blockSignals(True)
            idx = mode_combo.findData("range")
            if idx >= 0:
                mode_combo.setCurrentIndex(idx)
            mode_combo.blockSignals(False)
        self._sync_json_range_button()
        if self._json_day_groups_raw:
            self._rebuild_json_period_combo()

    def on_json_period_mode_changed(self, index: int) -> None:
        combo = getattr(self.app, "cmb_json_period_mode", None)
        if combo is None:
            return
        mode = str(combo.itemData(index) or combo.currentData() or "day")
        if mode == self._json_period_granularity:
            return
        if mode == "month":
            if not month_view_available(self._json_day_groups_raw.keys()):
                combo.blockSignals(True)
                day_index = combo.findData(self._json_period_granularity or "day")
                if day_index >= 0:
                    combo.setCurrentIndex(day_index)
                combo.blockSignals(False)
                self.app._message_dialog(
                    "Month view unavailable",
                    "Month view requires a complete calendar month (every day indexed).",
                    "Use Day view for partial imports.",
                    width=520,
                )
                return
        if mode == "range":
            if not self.configure_json_period_range():
                combo.blockSignals(True)
                revert_index = combo.findData(self._json_period_granularity or "day")
                if revert_index >= 0:
                    combo.setCurrentIndex(revert_index)
                combo.blockSignals(False)
                return
        elif self._json_period_granularity == "range":
            self._json_period_range_start = ""
            self._json_period_range_end = ""
        if self._load_thread is not None:
            combo.blockSignals(True)
            revert_index = combo.findData(self._json_period_granularity or "day")
            if revert_index >= 0:
                combo.setCurrentIndex(revert_index)
            combo.blockSignals(False)
            self.app._message_dialog(
                "JSON dataset",
                "Wait for the current JSON load to finish, then change the period again.",
                width=480,
            )
            return
        self._json_period_granularity = mode
        self._sync_json_range_button()
        if not self._json_day_groups_raw:
            return
        active = self._json_active_day
        self._rebuild_json_period_combo()
        day_combo = getattr(self.app, "cmb_json_day", None)
        if day_combo is not None and active:
            idx = day_combo.findData(active)
            if idx >= 0:
                day_combo.blockSignals(True)
                day_combo.setCurrentIndex(idx)
                day_combo.blockSignals(False)
        self._sync_json_active_day_from_combo()
        self._try_load_active_json_period(force=True)

    def configure_json_period_range(self) -> bool:
        from core.period_gaps import missing_days_in_range, normalize_period_day
        from ui.dialogs import missing_range_import_dialog, period_range_dialog

        days = sorted(
            normalize_period_day(day)
            for day in self._json_day_groups_raw.keys()
            if normalize_period_day(day)
        )
        if not days:
            self.app._message_dialog(
                "Selected period",
                "No indexed JSON days are available yet.",
                width=420,
            )
            return False
        selected = period_range_dialog(
            self.app,
            title="Select JSON period",
            first_day=days[0],
            last_day=days[-1],
            present_days=list(self._json_day_groups_raw.keys()),
        )
        if not selected:
            return False
        start, end = selected
        missing = missing_days_in_range(self._json_day_groups_raw.keys(), start, end)
        if missing:
            choice = missing_range_import_dialog(
                self.app,
                title="Missing JSON datasets",
                missing_days=missing,
            )
            if choice == "Import missing periods…":
                self.load_dataset_dialog()
                return False
            if choice != "Continue without import":
                return False
        self._json_period_range_start = start
        self._json_period_range_end = end
        self._sync_json_range_button()
        self._log_period_selected("JSON", start, end)
        if self._json_period_granularity == "range" and self._json_day_groups_raw:
            self._rebuild_json_period_combo()
            self._sync_json_active_day_from_combo()
            self._try_load_active_json_period(force=True)
        self._sync_json_period_selector_panel()
        return True

    def _log_period_selected(self, kind: str, start: str, end: str) -> None:
        project_id = getattr(self.app, "current_project_id", None)
        if project_id is None:
            return
        from core.db import add_activity
        from core.evidence_policy import format_period_day_label

        start_label = format_period_day_label(start) if start else "-"
        end_label = format_period_day_label(end) if end else "-"
        add_activity(int(project_id), "import_period_selected", f"{kind} {start_label} → {end_label}")
        if hasattr(self.app, "notes_controller"):
            self.app.notes_controller.refresh_activity_ui_for_project(int(project_id))

    def _sync_json_range_button(self) -> None:
        sync_pick_range_button(
            getattr(self.app, "btn_json_pick_range", None),
            granularity=self._json_period_granularity,
            has_periods=bool(self._json_day_groups_raw),
        )

    def _indexed_json_day_bounds(self) -> tuple[str, str]:
        from core.period_gaps import normalize_period_day

        days = sorted(
            normalize_period_day(day)
            for day in self._json_day_groups_raw.keys()
            if normalize_period_day(day)
        )
        if not days:
            return "", ""
        return days[0], days[-1]

    def on_json_day_changed(self, index: int):
        if self._json_day_switching or index < 0 or not self._json_day_groups:
            return
        combo = getattr(self.app, "cmb_json_day", None)
        if combo is None:
            return
        day = str(combo.itemData(index) or "")
        if not day:
            return
        self._json_active_day = day
        self._json_active_file = ""
        self._rebuild_json_file_combo()
        self._load_active_json_period(force=True)

    def on_json_file_changed(self, index: int) -> None:
        if self._json_file_switching or index < 0:
            return
        file_combo = getattr(self.app, "cmb_json_file", None)
        if file_combo is None or not file_combo.isVisible():
            return
        token = str(file_combo.itemData(index) or "")
        self._json_active_file = "" if token == _JSON_ALL_FILES_TOKEN else token
        self._load_active_json_period(force=True)

    def _active_json_period_files(self) -> list[str]:
        day = str(self._json_active_day or "")
        return list(self._json_day_groups.get(day, []) or [])

    def _rebuild_json_file_combo(self) -> None:
        file_combo = getattr(self.app, "cmb_json_file", None)
        if file_combo is None:
            return
        files = self._active_json_period_files()
        self._json_file_switching = True
        file_combo.blockSignals(True)
        file_combo.clear()
        if len(files) <= 1:
            file_combo.setVisible(False)
            self._json_active_file = ""
        else:
            file_combo.addItem(f"All files ({len(files):,})", _JSON_ALL_FILES_TOKEN)
            for path in sorted(files, key=lambda item: Path(item).name.casefold()):
                file_combo.addItem(Path(path).name, path)
            file_combo.setVisible(True)
            if self._json_active_file and self._json_active_file in files:
                index = file_combo.findData(self._json_active_file)
                if index >= 0:
                    file_combo.setCurrentIndex(index)
            else:
                self._json_active_file = ""
                file_combo.setCurrentIndex(0)
        file_combo.blockSignals(False)
        self._json_file_switching = False

    def _set_json_day_groups(self, source_path: str, day_groups: dict[str, list[str]]) -> list[str]:
        cleaned = {
            str(day): [str(path) for path in paths if str(path or "").strip()]
            for day, paths in (day_groups or {}).items()
        }
        cleaned = {day: paths for day, paths in cleaned.items() if paths}
        self._json_day_groups_raw = dict(sorted(cleaned.items(), key=lambda pair: (pair[0] == "undated", pair[0])))
        self._json_day_source = str(source_path or "")
        if not self._json_day_groups_raw:
            self._clear_json_day_groups()
            return []
        return self._rebuild_json_period_combo()

    def _rebuild_json_period_combo(self) -> list[str]:
        combo = getattr(self.app, "cmb_json_day", None)
        label = getattr(self.app, "lbl_json_day", None)
        if not self._json_day_groups_raw or combo is None or label is None:
            self._reset_json_period_ui(keep_raw=False)
            return []

        previous_day = str(self._json_active_day or combo.currentData() or "")
        previous_granularity = self._json_period_granularity
        state = PeriodSelectorState(
            granularity=self._json_period_granularity,
            range_start=self._json_period_range_start,
            range_end=self._json_period_range_end,
            day_groups_raw=self._json_day_groups_raw,
            active_key=self._json_active_day,
        )
        paths = rebuild_period_selector(
            state,
            kind="JSON",
            recover_empty_range=True,
            previous_key=previous_day,
        )
        if not state.day_groups:
            return []

        self._json_period_granularity = state.granularity
        self._json_period_range_start = state.range_start
        self._json_period_range_end = state.range_end
        self._json_day_groups = state.day_groups
        if state.granularity != previous_granularity:
            mode_combo = getattr(self.app, "cmb_json_period_mode", None)
            if mode_combo is not None:
                mode_combo.blockSignals(True)
                mode_index = mode_combo.findData(state.granularity or "day")
                if mode_index >= 0:
                    mode_combo.setCurrentIndex(mode_index)
                mode_combo.blockSignals(False)

        self._json_day_switching = True
        combo.blockSignals(True)
        combo.clear()
        for key, entry_label, _paths in build_period_combo_entries(
            state.day_groups,
            granularity=state.granularity,
            kind="JSON",
        ):
            combo.addItem(entry_label, key)
        if previous_day:
            index = combo.findData(previous_day)
            if index >= 0:
                combo.setCurrentIndex(index)
        combo.blockSignals(False)
        combo.setVisible(True)
        label.setText(PERIOD_LABEL)
        label.setVisible(True)
        mode_combo = getattr(self.app, "cmb_json_period_mode", None)
        if mode_combo is not None:
            mode_combo.setVisible(True)
        self._json_day_switching = False
        self._json_active_day = state.active_key
        self._json_active_file = ""
        self._rebuild_json_file_combo()
        self._update_json_gap_banner(list(self._json_day_groups_raw.keys()))
        self._sync_json_period_selector_panel()
        return paths

    def _sync_json_active_day_from_combo(self) -> None:
        combo = getattr(self.app, "cmb_json_day", None)
        if combo is None:
            return
        self._json_active_day = str(combo.currentData() or "")
        self._json_active_file = ""
        self._rebuild_json_file_combo()

    def _try_load_active_json_period(self, *, force: bool = True) -> None:
        if self._json_active_day and self._active_json_period_files():
            self._load_active_json_period(force=force)

    def _load_active_json_period(self, *, force: bool = False) -> None:
        if self._json_day_switching or not self._json_day_groups or not self._json_day_source:
            return
        if self._load_thread is not None:
            return
        combo = getattr(self.app, "cmb_json_day", None)
        day = str(self._json_active_day or (combo.currentData() if combo is not None else "") or "")
        if not day:
            return
        files = self._active_json_period_files()
        if not files:
            return
        active_file = str(self._json_active_file or "").strip()
        if active_file and active_file in files:
            files = [active_file]
        if not force and self.app.flow_controller.get_all():
            return
        self._json_active_day = day
        period_label = self._format_day_label(day)
        if self._json_period_granularity == "month":
            period_label = f"Loading JSON month {period_label} ({len(files):,} files)..."
        elif self._json_period_granularity == "range":
            period_label = f"Loading JSON period {period_label} ({len(files):,} files)..."
        elif len(files) == 1:
            period_label = f"Loading JSON file {Path(files[0]).name}..."
        elif len(files) > 1:
            period_label = f"Loading JSON day {period_label} ({len(files):,} files)..."
        self.load_dataset_files(self._json_day_source, files, progress_label=period_label)

    def _sync_json_period_selector_panel(self) -> None:
        sync_period_selector_panel(
            has_periods=bool(self._json_day_groups_raw),
            granularity=self._json_period_granularity,
            period_label=getattr(self.app, "lbl_json_day", None),
            day_combo=getattr(self.app, "cmb_json_day", None),
            mode_combo=getattr(self.app, "cmb_json_period_mode", None),
            pick_range_button=getattr(self.app, "btn_json_pick_range", None),
            period_row=getattr(self.app, "json_period_row", None),
        )

    def _restore_json_period_range_from_days(self) -> None:
        if not self._json_day_groups_raw:
            return

        state = PeriodSelectorState(
            granularity=self._json_period_granularity,
            range_start=self._json_period_range_start,
            range_end=self._json_period_range_end,
            day_groups_raw=self._json_day_groups_raw,
        )
        if restore_range_from_raw_keys(state):
            self._json_period_range_start = state.range_start
            self._json_period_range_end = state.range_end
            self._json_period_granularity = state.granularity
            mode_combo = getattr(self.app, "cmb_json_period_mode", None)
            if mode_combo is not None:
                mode_combo.blockSignals(True)
                idx = mode_combo.findData("range")
                if idx >= 0:
                    mode_combo.setCurrentIndex(idx)
                mode_combo.blockSignals(False)
            self._sync_json_range_button()
            return

        if self._json_period_granularity != "range":
            return
        if self._json_period_range_start and self._json_period_range_end:
            return
        start, end = infer_default_range_bounds(self._json_day_groups_raw)
        if start and end:
            self._json_period_range_start = start
            self._json_period_range_end = end

    def _clear_json_day_groups(self) -> None:
        self._reset_json_period_ui(keep_raw=False)

    def _reset_json_period_ui(self, *, keep_raw: bool = False) -> None:
        if not keep_raw:
            self._json_day_groups_raw = {}
            self._json_day_source = ""
        self._json_day_groups = {}
        self._json_active_day = ""
        self._json_active_file = ""
        combo = getattr(self.app, "cmb_json_day", None)
        file_combo = getattr(self.app, "cmb_json_file", None)
        mode_combo = getattr(self.app, "cmb_json_period_mode", None)
        label = getattr(self.app, "lbl_json_day", None)
        if combo is not None:
            self._json_day_switching = True
            combo.blockSignals(True)
            combo.clear()
            combo.blockSignals(False)
            self._json_day_switching = False
        if file_combo is not None:
            self._json_file_switching = True
            file_combo.blockSignals(True)
            file_combo.clear()
            file_combo.blockSignals(False)
            file_combo.setVisible(False)
            self._json_file_switching = False
        self._sync_json_period_selector_panel()
        self._update_json_gap_banner(list(self._json_day_groups_raw.keys()) if keep_raw else [])

    def _sync_json_gap_visibility(self) -> None:
        loading = self._load_thread is not None
        lbl = getattr(self.app, "lbl_json_gaps", None)
        btn = getattr(self.app, "btn_expand_json_gaps", None)
        if lbl is not None:
            lbl.setVisible(not loading)
        if btn is not None:
            missing_count = int(self._json_gap_info.get("missing_count") or 0)
            btn.setVisible(missing_count > 0 and not loading)

    def _update_json_gap_banner(self, present_days: list[str] | None = None) -> None:
        days = list(
            present_days
            if present_days is not None
            else self._json_day_groups_raw.keys()
            or self._json_day_groups.keys()
        )
        gap = missing_period_days(days)
        self._json_gap_info = gap
        summary = format_period_gap_summary(
            days,
            granularity=getattr(self, "_json_period_granularity", "day"),
        )
        if getattr(self, "_json_period_granularity", "day") == "day":
            partial = summarize_partial_months(days)
            if partial:
                summary = f"{summary}\n{partial}" if summary else partial
        lbl = getattr(self.app, "lbl_json_gaps", None)
        btn = getattr(self.app, "btn_expand_json_gaps", None)
        if lbl is not None:
            lbl.setText(summary)
            lbl.setToolTip(summary)
        if btn is not None:
            missing_count = int(gap.get("missing_count") or 0)
            btn.setVisible(missing_count > 0)
            btn.setText(f"Missing days ({missing_count:,})")
        self._sync_json_gap_visibility()

    def open_json_missing_days_dialog(self) -> None:
        open_missing_period_days_dialog(
            self.app,
            title="Missing JSON days",
            missing_days=list(self._json_gap_info.get("missing_days") or []),
            first_day_label=self._format_day_label(str(self._json_gap_info.get("first_day") or "")),
            last_day_label=self._format_day_label(str(self._json_gap_info.get("last_day") or "")),
            evidence_kind="JSON",
            format_day_label=self._format_day_label,
            on_empty=lambda title, message: self.app._message_dialog(title, message, width=420),
            append_export_footer=lambda footer, table: append_table_export_footer(
                self.app,
                footer,
                title="Missing JSON days",
                table=table,
                project_id=self.app.current_project_id,
                category="json",
                source_label=str(getattr(self, "_json_day_source", "") or ""),
            ),
        )

    def _format_day_label(self, day: str) -> str:
        return format_period_day_label(day)

    def _get_previous_dataset_path(self, current_path: str) -> str:
        if self.app.current_project_id is None:
            return ""

        recent = list_recent_datasets(self.app.current_project_id, limit=2)
        if not recent:
            return ""

        previous_path = str(recent[0])
        if previous_path == str(current_path):
            return ""

        return previous_path

    def _start_dataset_load(
        self,
        mode: str,
        path: str,
        previous_path: str = "",
        files: list[str] | None = None,
        *,
        progress_label: str = "",
    ):
        if self._thread_is_running(self._load_thread):
            self.app._message_dialog("Dataset", "A dataset is already loading.", width=420)
            return

        file_list = list(files or [])
        show_progress = mode == "files" and bool(file_list)
        if show_progress:
            self._show_dataset_load_progress(
                file_count=len(file_list),
                period_label=progress_label or "Loading JSON period...",
            )

        self._set_loading(True)
        if hasattr(self.app, "lbl_path"):
            kind = "folder selection" if mode == "files" else ("folder" if mode == "folder" else "JSON file")
            self.app.lbl_path.setText(f"Analyzing {kind}: {path}")
        if hasattr(self.app, "lbl_stats"):
            self.app.explore_ui_controller.set_json_stats_text("Loading and parsing JSON flows. Please wait...", include_counts=False)
        if hasattr(self.app, "lbl_json_meta"):
            self.app.lbl_json_meta.setText("")

        self._load_thread = QThread(self.app)
        self._load_worker = DatasetLoadWorker(
            mode=mode,
            path=path,
            previous_path=previous_path,
            project_id=self.app.current_project_id,
            files=files,
        )

        self._load_worker.moveToThread(self._load_thread)
        self._load_thread.started.connect(self._load_worker.run)
        self._load_worker.progress.connect(self._on_dataset_load_progress, Qt.QueuedConnection)
        self._load_worker.finished.connect(self._on_dataset_loaded, Qt.QueuedConnection)
        self._load_worker.error.connect(self._on_dataset_load_error, Qt.QueuedConnection)
        self._load_worker.finished.connect(self._load_thread.quit)
        self._load_worker.error.connect(self._load_thread.quit)
        self._load_worker.finished.connect(self._load_worker.deleteLater)
        self._load_worker.error.connect(self._load_worker.deleteLater)
        self._load_thread.finished.connect(self._cleanup_load_thread)
        self._load_thread.start()

    @Slot(object)
    def _on_dataset_loaded(self, result: dict):
        self._close_dataset_load_progress()
        if result.get("project_id") != self.app.current_project_id:
            self.app._message_dialog(
                "Dataset",
                "Dataset load finished, but the active project changed. The loaded data was ignored.",
                width=520,
            )
            return

        if not self._confirm_or_bind_project_target(result.get("meta") or {}):
            return

        path = str(result["path"])
        files = result["files"]
        flows = result["flows"]
        compare_result = result.get("compare_result")

        self.app.current_folder = Path(result["current_folder"])
        self.app.flow_controller.page_size = self.app.PAGE_SIZE
        self.app.flow_controller.set_flows(flows)

        if hasattr(self.app, "registry_page"):
            self.app.registry_page.set_dataset(path, files, flows, compare_result=compare_result)

        if hasattr(self.app, "listing_page"):
            self.app.listing_page.set_dataset(path, files, flows, compare_result=compare_result)

        self.app.lbl_path.setText(str(result["dataset_label"]))
        stats_label = str(result["stats_label"])
        if self._json_active_day:
            day_label = self._format_day_label(self._json_active_day)
            day_files = len(self._json_day_groups.get(self._json_active_day, []))
            stats_label = (
                f"{stats_label} | Period: {day_label} ({day_files:,} JSON files)"
            )
        self.app.explore_ui_controller.set_json_stats_text(stats_label)
        if hasattr(self.app, "lbl_json_meta"):
            self.app.lbl_json_meta.setText(_json_order_metadata_line(result.get("meta") or {}))

        if self.app.current_project_id is not None:
            meta = dict(result.get("meta") or {})
            source_file = str(files[0] if files else path)
            try:
                from core.case_metadata import sync_case_metadata_from_json
                from core.db import add_activity

                warnings = sync_case_metadata_from_json(
                    int(self.app.current_project_id),
                    meta,
                    source_file=source_file,
                )
                for warning in warnings:
                    add_activity(
                        int(self.app.current_project_id),
                        "case_metadata_mismatch",
                        warning,
                    )
                    self.app._message_dialog(
                        "Case metadata",
                        warning,
                        "Save/load continued. Review Klasa/Urbroj in Projects.",
                        width=520,
                    )
            except Exception:
                pass

        if self.app.current_project_id is not None:
            add_dataset_load(self.app.current_project_id, path)
            if hasattr(self.app, "projects_ui_controller"):
                self.app.projects_ui_controller.sync_project_workspace(self.app.current_project_id)
            self.app.projects_ui_controller.refresh_recent_datasets(self.app.current_project_id)
            self.app.notes_controller.refresh_activity_ui()
            self._start_behavior_index(self.app.current_project_id)

        self.render_summary()

        self.app.model.set_flows(self.app.flow_controller.get_loaded())

        self.app.search.setText("")
        self.app.explore_ui_controller.leave_conversation(clear_search=False)

        self.app.explore_ui_controller.update_loaded_label()
        self.app.explore_ui_controller.update_load_more_enabled()

        self.app.tabs.setCurrentIndex(1)
        self.app._flows_expanded = False
        self.app.details_panel.show()
        self.app.btn_expand_flows.setText("Expand Flows")
        self.app.splitter.setSizes([920, 420])
        self.app.explore_ui_controller.update_detail(None)
        self._reset_ai_outputs_for_new_dataset()
        if hasattr(self.app, "findings_controller"):
            self.app.findings_controller.refresh_ui()
        if hasattr(self.app, "osint_ui_controller"):
            self.app.osint_ui_controller.refresh()
        self._flush_pending_pcap_open()
        self._sync_json_period_selector_panel()

    def _reset_ai_outputs_for_new_dataset(self) -> None:
        if hasattr(self.app, "txt_ai_summary"):
            self.app.txt_ai_summary.clear()
        if hasattr(self.app, "btn_ai_summary"):
            self.app.btn_ai_summary.setEnabled(True)
            self.app.btn_ai_summary.setText("Generate AI Summary")
        if hasattr(self.app, "ai_task_controller"):
            self.app.ai_task_controller.shutdown(wait_ms=2000)
        if hasattr(self.app, "_ai_output_state"):
            from ui.ai_output import AIOutputState

            self.app._ai_output_state = AIOutputState()
        if hasattr(self.app, "txt_ai_hub"):
            self.app.txt_ai_hub.clear()
        if hasattr(self.app, "lbl_ai_hub_title"):
            self.app.lbl_ai_hub_title.setText("AI output")
        if hasattr(self.app, "lbl_ai_hub_context"):
            self.app.lbl_ai_hub_context.clear()

    def _ensure_active_project(self) -> bool:
        if self.app.current_project_id is not None:
            project = get_project(self.app.current_project_id)
            if project and (project.base_folder or "").strip():
                return True

            self.app._message_dialog(
                "Dataset",
                "Set a Workspace folder for the active project first.",
                "Datasets are stored, exported and checked through the project Workspace folder.",
                width=500,
            )
            return False

        self.app._message_dialog(
            "Dataset",
            "Open an active project first.",
            "Datasets are stored in the active project Workspace and checked against the active project target.",
            width=480,
        )
        return False

    def _dataset_target_from_meta(self, meta: dict) -> tuple[str, str]:
        target_identifier = str(meta.get("target") or "").strip()
        target_type = str(meta.get("targettype") or "").strip()
        return target_identifier, target_type

    def _format_target(self, target_identifier: str, target_type: str) -> str:
        return _format_dataset_target(target_identifier, target_type)

    def _project_target_details(self, project) -> str:
        known = project_identifiers_text(project)
        fallback = target_display_label(project)
        if known == "-" and fallback == "-":
            return "-"
        if known == "-":
            return fallback
        if fallback == "-" or fallback in known:
            return known
        return f"{known}\nLegacy target: {fallback}"

    def _target_matches(
        self,
        project_identifier: str,
        project_type: str,
        dataset_identifier: str,
        dataset_type: str,
    ) -> bool:
        same_identifier = identifier_values_match(
            project_identifier,
            dataset_identifier,
            project_type=project_type,
            dataset_type=dataset_type,
        )
        if not same_identifier:
            return False

        if project_type and dataset_type:
            return project_type.strip().casefold() == dataset_type.strip().casefold()

        return True

    def _target_matches_project(self, project, dataset_identifier: str, dataset_type: str) -> bool:
        rows = project_identifier_rows(project)
        if not rows and (project.target_identifier or "").strip():
            return self._target_matches(
                project.target_identifier,
                project.target_type,
                dataset_identifier,
                dataset_type,
            )

        for row in rows:
            value = str(row.get("value") or "").strip()
            kind = str(row.get("type") or "").strip()
            if identifier_values_match(
                value,
                dataset_identifier,
                project_type=kind,
                dataset_type=dataset_type,
            ):
                return True

        return False

    def _refresh_selected_project_preview(self, project_id: int) -> None:
        selected_item = self.app.projects_list.currentItem()
        if selected_item and int(selected_item.data(Qt.UserRole)) == project_id:
            self.app.projects_ui_controller.on_project_selected_preview()

    def _confirm_or_bind_project_target(self, meta: dict) -> bool:
        project_id = self.app.current_project_id
        if project_id is None:
            return False

        project = get_project(project_id)
        if not project:
            self.app._message_dialog("Dataset", "Project not found.", width=400)
            return False

        dataset_identifier, dataset_type = self._dataset_target_from_meta(meta)
        if is_imsi_target_type(dataset_type):
            dataset_identifier = format_intercept_imsi(dataset_identifier)
        project_identifier = (project.target_identifier or "").strip()
        project_type = (project.target_type or "").strip()
        project_details = self._project_target_details(project)

        if not dataset_identifier:
            details = (
                f"Project identifiers: {project_details}\n"
                "Dataset target: -\n\n"
                "ViaNyquist cannot verify whether this dataset belongs to the active project."
            )
            return self.app._confirm_dialog(
                title="Dataset target missing",
                message="Dataset does not contain a target identifier.",
                details=details,
                ok_text="Load anyway",
                cancel_text="Cancel",
                width=520,
            )

        if not project_identifier and not project_identifier_rows(project):
            set_project_target(project_id, dataset_identifier, dataset_type)
            self._refresh_selected_project_preview(project_id)
            return True

        same_identifier = identifier_values_match(
            project_identifier,
            dataset_identifier,
            project_type=project_type,
            dataset_type=dataset_type,
        )
        if same_identifier and not project_type and dataset_type:
            set_project_target(project_id, project_identifier, dataset_type)
            self._refresh_selected_project_preview(project_id)
            return True

        if same_identifier and project_type and not dataset_type:
            details = (
                f"Project identifiers: {project_details}\n"
                f"Dataset target: {self._format_target(dataset_identifier, dataset_type)}\n\n"
                "The identifier matches, but the dataset does not contain a target type."
            )
            return self.app._confirm_dialog(
                title="Dataset target type missing",
                message="Dataset target type could not be verified.",
                details=details,
                ok_text="Load anyway",
                cancel_text="Cancel",
                width=540,
            )

        if self._target_matches_project(project, dataset_identifier, dataset_type):
            return True

        details = (
            f"Project identifiers: {project_details}\n"
            f"Dataset target: {self._format_target(dataset_identifier, dataset_type)}\n\n"
            "This may mean the selected dataset belongs to a different target than the active project."
        )
        return self.app._confirm_dialog(
            title="Dataset target mismatch",
            message="Dataset target does not match the active project.",
            details=details,
            ok_text="Load anyway",
            cancel_text="Cancel",
            width=560,
        )

    @Slot(str, str)
    def _on_dataset_load_error(self, title: str, details: str):
        self._close_dataset_load_progress()
        if hasattr(self.app, "lbl_stats"):
            self.app.explore_ui_controller.set_json_stats_text("JSON dataset load failed.", include_counts=False)
        self.app._message_dialog("Dataset", title, details, width=520)
        self._flush_pending_pcap_open()

    @Slot()
    def _cleanup_load_thread(self):
        self._close_dataset_load_progress()
        self._load_worker = None
        self._load_thread = None
        self._set_loading(False)

    def deferred_sync_project_periods(self, project_id: int | None) -> None:
        """Populate JSON/PCAP period selectors without loading flows or PCAP analysis."""
        if project_id is None or self.app.current_project_id != project_id:
            return
        self.sync_json_periods_from_project(project_id)
        self.sync_pcap_periods_from_project(project_id)

    def _restore_pcap_period_range_from_days(self, pcap_page, by_day: dict[str, list[str]]) -> None:
        from core.period_gaps import normalize_period_day
        from core.period_groups import is_range_period_key, parse_range_period_key

        for key in by_day:
            if is_range_period_key(key):
                start, end = parse_range_period_key(key)
                if start and end:
                    pcap_page._apply_imported_period_range_only(start, end)
                    return

        days = sorted(
            normalize_period_day(day)
            for day in by_day.keys()
            if normalize_period_day(day)
        )
        if len(days) >= 2:
            pcap_page._apply_imported_period_range_only(days[0], days[-1])

    def sync_json_periods_from_project(self, project_id: int | None) -> None:
        """Restore JSON period selector from saved ingest items after opening a project."""
        if project_id is None:
            self._clear_json_day_groups()
            return

        by_day = self._json_day_groups_from_ingest(project_id)
        if not by_day:
            self._clear_json_day_groups()
            return

        source_root = ""
        for folder in list_recent_datasets(project_id, limit=20):
            folder = str(folder or "").strip()
            if folder:
                source_root = folder
                break
        if not source_root:
            source_root = str(Path(by_day[sorted(by_day)[0]][0]).parent)

        self._set_json_day_groups(source_root, by_day)
        self._restore_json_period_range_from_days()
        if self._json_day_groups_raw:
            self._rebuild_json_period_combo()

        total_files = sum(len(paths) for paths in by_day.values())
        if hasattr(self.app, "lbl_path") and not str(getattr(self.app, "current_folder", "") or "").strip():
            self.app.lbl_path.setText(f"Project: {getattr(self.app, 'current_project_name', '') or 'active'}")
        indexed_msg = (
            f"{total_files:,} JSON files indexed across {len(by_day)} periods. "
            f"Select Period above to load flows into the table."
        )
        if hasattr(self.app, "lbl_stats"):
            self.app.explore_ui_controller.set_json_stats_text(indexed_msg, include_counts=False)

    def sync_pcap_periods_from_project(self, project_id: int | None) -> None:
        """Restore PCAP period selector from ingest index (lightweight, no auto-load)."""
        from core.project_evidence import pcap_day_groups_from_ingest

        pcap_page = getattr(self.app, "pcap_page", None)
        if pcap_page is None:
            return
        if project_id is None:
            pcap_page._clear_day_groups()
            return

        by_day = pcap_day_groups_from_ingest(project_id)
        if not by_day:
            pcap_page._clear_day_groups()
            return

        pcap_page._set_day_groups(by_day, allow_empty_days=True)
        self._restore_pcap_period_range_from_days(pcap_page, by_day)
        pcap_page._sync_period_selector_panel()
        pcap_page._update_period_gap_banner(list(by_day.keys()))
        if getattr(pcap_page, "summary", None) is None and hasattr(pcap_page, "lbl_stats"):
            if pcap_page.batch_is_running():
                return
            total_files = sum(len(paths) for paths in by_day.values())
            saved_only = sum(1 for paths in by_day.values() if not paths)
            saved_note = f" ({saved_only} saved-only)" if saved_only else ""
            pcap_page.lbl_stats.setText(
                f"{total_files:,} PCAP files indexed across {len(by_day)} periods{saved_note}. "
                f"Select Period above to open saved analysis or re-analyze source files."
            )

    def refresh_project_behavior_index(self, project_id: int | None):
        self._start_behavior_index(project_id)

    def _start_behavior_index(self, project_id: int | None):
        if project_id is None:
            return
        if self._behavior_index_thread is not None:
            self._pending_behavior_index_project_id = project_id
            return

        self._behavior_index_thread = QThread(self.app)
        self._behavior_index_worker = BehaviorIndexWorker(project_id)
        self._behavior_index_worker.moveToThread(self._behavior_index_thread)

        self._behavior_index_thread.started.connect(self._behavior_index_worker.run)
        self._behavior_index_worker.finished.connect(self._on_behavior_index_finished, Qt.QueuedConnection)
        self._behavior_index_worker.error.connect(self._on_behavior_index_error, Qt.QueuedConnection)
        self._behavior_index_worker.finished.connect(self._behavior_index_thread.quit)
        self._behavior_index_worker.error.connect(self._behavior_index_thread.quit)
        self._behavior_index_worker.finished.connect(self._behavior_index_worker.deleteLater)
        self._behavior_index_worker.error.connect(self._behavior_index_worker.deleteLater)
        self._behavior_index_thread.finished.connect(self._cleanup_behavior_index_thread)
        self._behavior_index_thread.start()

    @Slot(object)
    def _on_behavior_index_finished(self, profile: dict):
        if profile.get("project_id") != self.app.current_project_id:
            return

        page = getattr(self.app, "activity_profile_page", None)
        if page is not None:
            page._behavior_cache_key = ""
            page._behavior_cache_flows = []
            page._behavior_index_requested_project_id = None
        if hasattr(self.app, "refresh_activity_profile_ui"):
            self.app.refresh_activity_profile_ui()

    @Slot(str)
    def _on_behavior_index_error(self, message: str):
        if hasattr(self.app, "lbl_stats"):
            self.app.explore_ui_controller.set_json_stats_text(
                f"Project profile index failed: {message}",
                include_counts=False,
            )

    @Slot()
    def _cleanup_behavior_index_thread(self):
        self._behavior_index_worker = None
        self._behavior_index_thread = None
        pending_project_id = getattr(self, "_pending_behavior_index_project_id", None)
        self._pending_behavior_index_project_id = None
        if pending_project_id is not None:
            self._start_behavior_index(pending_project_id)

    def _set_loading(self, loading: bool):
        if not hasattr(self.app, "btn_load"):
            return

        self.app.btn_load.setEnabled(not loading)
        self.app.btn_load.setText("Loading..." if loading else "Load dataset")

    def reset_loaded_flow_views(self) -> None:
        """Clear loaded flow/table views without removing indexed period selectors."""
        app = self.app
        app.current_folder = None
        app._current_flow = None
        app._conversation_on = False
        app._flows_expanded = False

        app.flow_controller.set_flows([])
        app.model.set_flows([])

        app.search.blockSignals(True)
        app.search.setText("")
        app.search.blockSignals(False)

        app.proxy.set_filter_text("")
        app.proxy.clear_conversation()

        if app.table.selectionModel():
            app.table.clearSelection()

        app.explore_ui_controller.update_detail(None)
        app.explore_ui_controller.update_mode_label()
        app.explore_ui_controller.update_conversation_summary()
        app.explore_ui_controller.update_loaded_label()
        app.explore_ui_controller.update_load_more_enabled()
        app.explore_ui_controller.update_showing()

        app.lbl_path.setText("No dataset loaded")
        app.explore_ui_controller.set_json_stats_text("", include_counts=False)
        if hasattr(app, "lbl_json_meta"):
            app.lbl_json_meta.setText("")
        app.lbl_conv_summary.clear()
        app.lbl_conv_summary.hide()
        app.lbl_mode.clear()
        app.lbl_mode.hide()

        for rows in getattr(app, "summary_preview_rows", {}).values():
            self.clear_summary_preview_rows(rows)

        app.txt_ai_summary.clear()

        if hasattr(app, "details_panel"):
            app.details_panel.show()
        if hasattr(app, "btn_expand_flows"):
            app.btn_expand_flows.setText("Expand Flows")

        if hasattr(app, "registry_page"):
            app.registry_page.set_dataset("", [], [])

        if hasattr(app, "listing_page"):
            try:
                app.listing_page.set_dataset("", [], [])
            except Exception:
                pass

    def reset_dataset_views(self) -> None:
        """Full dataset reset including period selectors (project change / new import)."""
        self.reset_loaded_flow_views()
        self._clear_json_day_groups()

        if hasattr(self.app, "pcap_page"):
            self.app.pcap_page.clear_project_view()

    def clear_context(self) -> None:
        self.reset_dataset_views()
    def shutdown_background_tasks(self, wait_ms: int = 5000) -> None:
        self._close_scan_progress()
        self._close_ingest_progress()
        self._close_dataset_load_progress()
        self._pending_pcap_after_json = None
        for thread_name in (
            "_load_thread",
            "_scan_thread",
            "_ingest_thread",
            "_behavior_index_thread",
        ):
            stop_qthread(getattr(self, thread_name, None), wait_ms=wait_ms)
            setattr(self, thread_name, None)
        for worker_name in (
            "_load_worker",
            "_scan_worker",
            "_ingest_worker",
            "_behavior_index_worker",
        ):
            setattr(self, worker_name, None)
        self._pending_behavior_index_project_id = None
