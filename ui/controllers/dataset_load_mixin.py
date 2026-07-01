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

class DatasetLoadMixin:
    """JSON dataset loading, target binding, and load progress UI."""

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
        if self.import_session_active():
            label = period_label or "Loading JSON period..."
            self.route_json_load_progress(0, file_count if file_count > 1 else 0, label, period_label=label)
            return
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

    def _on_dataset_load_progress(self, current: int, total: int, file_name: str) -> None:
        if self.route_json_load_progress(current, total, file_name):
            return
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
            pause_gate=self.import_pause_gate() if self.import_session_active() else None,
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

    def _on_dataset_load_error(self, title: str, details: str):
        self._close_dataset_load_progress()
        if hasattr(self.app, "lbl_stats"):
            self.app.explore_ui_controller.set_json_stats_text("JSON dataset load failed.", include_counts=False)
        self.app._message_dialog("Dataset", title, details, width=520)
        self._flush_pending_pcap_open()

    def _cleanup_load_thread(self):
        self._close_dataset_load_progress()
        self._load_worker = None
        self._load_thread = None
        self._set_loading(False)
