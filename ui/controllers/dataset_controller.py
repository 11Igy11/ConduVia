from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QDate, QObject, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtGui import QFontMetrics
from PySide6.QtWidgets import (
    QCalendarWidget,
    QCheckBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QFileDialog,
    QProgressDialog,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
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
from core.case_ingest import evidence_paths, filter_case_scan, group_evidence_by_date, scan_case_source
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
from core.loader import list_json_files_recursive, load_folder_recursive, load_json_file
from core.period_gaps import format_missing_days_summary, missing_period_days
from core.parser import extract_dataset_meta
from core.formatters import format_short_date, human_bytes
from core.project_behavior_index import build_project_behavior_index
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


from ui.project_rows_dialog import open_project_rows_dialog
from ui.thread_utils import stop_qthread


def _json_order_metadata_line(meta: dict | None) -> str:
    meta = meta or {}
    klasa = str(meta.get("OrigRegNo") or "-")
    urbroj = str(meta.get("RegNo") or "-")
    target = str(meta.get("target") or "")
    target_type = str(meta.get("targettype") or "")
    liid = str(meta.get("liid") or "-")
    bt = str(meta.get("bt") or "")
    et = str(meta.get("et") or "")
    target_label = f"{target} ({target_type})" if target or target_type else "-"
    if bt or et:
        validity = f"{format_short_date(bt, missing='-')} -> {format_short_date(et, missing='-')}"
    else:
        validity = "-"
    return (
        f"Klasa: {klasa}   |   Urbroj: {urbroj}   |   Target: {target_label}   |   "
        f"LIID: {liid}   |   Order validity: {validity}"
    )


class DatasetLoadWorker(QObject):
    finished = Signal(object)
    error = Signal(str, str)

    def __init__(
        self,
        *,
        mode: str,
        path: str,
        previous_path: str = "",
        project_id: int | None = None,
        files: list[str] | None = None,
    ):
        super().__init__()
        self.mode = mode
        self.path = path
        self.previous_path = previous_path
        self.project_id = project_id
        self.files = files or []

    @Slot()
    def run(self):
        try:
            previous_flows = self._load_previous_flows()

            if self.mode == "folder":
                files, flows = load_folder_recursive(self.path, debug=False)
                dataset_label = f"Dataset: {self.path}"
                stats_label = f"JSON files: {len(files)} | Total flow records: {len(flows)}"
                current_folder = self.path
            elif self.mode == "files":
                files = [Path(path) for path in self.files if str(path or "").strip()]
                flows = []
                for fp in files:
                    flows.extend(load_json_file(fp, debug=False))
                dataset_label = f"Dataset selection: {self.path}"
                stats_label = f"JSON files: {len(files)} | Total flow records: {len(flows)}"
                current_folder = self.path
            elif self.mode == "file":
                fp = Path(self.path)
                flows = load_json_file(fp, debug=False)
                files = [fp]
                dataset_label = f"Dataset file: {self.path}"
                stats_label = f"JSON files: 1 | Total flow records: {len(flows)}"
                current_folder = str(fp.parent)
            else:
                raise ValueError(f"Unsupported dataset mode: {self.mode}")

            meta = self._extract_meta(files)
            compare_result = self._build_compare(flows, previous_flows)

            self.finished.emit({
                "mode": self.mode,
                "path": self.path,
                "files": files,
                "flows": flows,
                "compare_result": compare_result,
                "dataset_label": dataset_label,
                "stats_label": stats_label,
                "current_folder": current_folder,
                "project_id": self.project_id,
                "meta": meta,
            })
        except Exception as e:
            title = "Failed to load dataset folder." if self.mode in {"folder", "files"} else "Failed to load JSON file."
            self.error.emit(title, str(e))

    def _load_previous_flows(self) -> list[dict]:
        if not self.previous_path:
            return []

        try:
            prev = Path(self.previous_path)
            if prev.is_file():
                return load_json_file(prev, debug=False)
            if prev.is_dir():
                return []
        except Exception:
            return []

        return []

    def _extract_meta(self, files: list[Path]) -> dict:
        if not files:
            return {}

        try:
            return extract_dataset_meta(files[0])
        except Exception:
            return {}

    def _build_compare(self, flows: list[dict], previous_flows: list[dict]) -> dict | None:
        if not previous_flows:
            return None

        from core.compare import compare_flows, summarize_new_flows

        compare_result = compare_flows(flows, previous_flows)
        compare_result["summary_new"] = summarize_new_flows(compare_result["new"])
        return compare_result


class BehaviorIndexWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, project_id: int):
        super().__init__()
        self.project_id = project_id

    @Slot()
    def run(self):
        try:
            self.finished.emit(build_project_behavior_index(self.project_id))
        except Exception as exc:
            self.error.emit(str(exc))


class CaseScanWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, folder: str):
        super().__init__()
        self.folder = folder

    @Slot()
    def run(self):
        try:
            self.finished.emit(scan_case_source(self.folder))
        except Exception as exc:
            self.error.emit(str(exc))


class FolderIngestWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, project_id: int, folder: str, scan):
        super().__init__()
        self.project_id = project_id
        self.folder = folder
        self.scan = scan

    @Slot()
    def run(self):
        try:
            json_files = list(self.scan.json_files or [])
            pcap_files = list(self.scan.pcap_files or [])

            if json_files:
                upsert_ingest_items(
                    self.project_id,
                    self.folder,
                    (
                        {
                            "file_path": str(item.path),
                            "file_name": item.path.name,
                            "file_type": "json",
                            "file_size": item.size,
                            "observed_date": item.observed_date,
                        }
                        for item in json_files
                    ),
                )
                mark_ingest_items_batch(
                    self.project_id,
                    [str(item.path) for item in json_files],
                    "done",
                )

            if pcap_files:
                upsert_ingest_items(
                    self.project_id,
                    self.folder,
                    (
                        {
                            "file_path": str(item.path),
                            "file_name": item.path.name,
                            "file_type": item.kind,
                            "file_size": item.size,
                            "observed_date": item.observed_date,
                        }
                        for item in pcap_files
                    ),
                )

            self.finished.emit(self.scan)
        except Exception as exc:
            self.error.emit(str(exc))


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
        self._json_day_source = ""
        self._json_active_day = ""
        self._json_day_switching = False
        self._json_gap_info: dict[str, object] = {}
        self._pending_behavior_index_project_id: int | None = None

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
        if self._scan_thread is not None:
            self.app._message_dialog("Dataset folder", "A folder scan is already running.", width=420)
            return

        self._scan_purpose = purpose
        title = "Import evidence folder" if purpose == "import" else "Scan dataset folder"
        self._scan_progress = QProgressDialog("Scanning evidence folder...", None, 0, 0, self.app)
        self._scan_progress.setWindowTitle(title)
        self._scan_progress.setWindowModality(Qt.WindowModal)
        self._scan_progress.setMinimumDuration(0)
        self._scan_progress.setCancelButton(None)
        self._scan_progress.setMinimumWidth(460)
        self._scan_progress.show()

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
        self._scan_thread.finished.connect(self._scan_thread.deleteLater)
        self._scan_thread.finished.connect(self._cleanup_scan_thread)
        self._scan_thread.start()

    @Slot()
    def _cleanup_scan_thread(self) -> None:
        self._scan_thread = None
        self._scan_worker = None
        if self._scan_progress is not None:
            self._scan_progress.close()
            self._scan_progress = None

    @Slot(str)
    def _on_folder_scan_error(self, message: str) -> None:
        self._cleanup_scan_thread()
        self.app._message_dialog("Dataset folder", "Failed to scan selected folder.", message, width=520)

    @Slot(object)
    def _on_folder_scan_finished(self, scan) -> None:
        folder = str(getattr(scan, "root", "") or "")
        purpose = self._scan_purpose
        self._scan_purpose = "import"
        self._cleanup_scan_thread()
        if not folder:
            return

        if purpose == "json_only":
            self._start_folder_ingest(folder, scan, purpose="json_only")
            return

        scoped = self._select_case_ingest_scope(scan)
        if scoped is None:
            return
        self._start_folder_ingest(folder, scoped, purpose="import")

    def _start_folder_ingest(self, folder: str, scan, *, purpose: str = "import") -> None:
        if self._ingest_thread is not None:
            self.app._message_dialog("Dataset folder", "Evidence indexing is already running.", width=420)
            return

        project_id = getattr(self.app, "current_project_id", None)
        if project_id is None:
            return

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
        self._ingest_progress.setWindowModality(Qt.WindowModal)
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
        self._ingest_thread.finished.connect(self._ingest_thread.deleteLater)
        self._ingest_thread.finished.connect(self._cleanup_ingest_thread)
        self._ingest_thread.start()

    @Slot()
    def _cleanup_ingest_thread(self) -> None:
        self._ingest_thread = None
        self._ingest_worker = None
        if self._ingest_progress is not None:
            self._ingest_progress.close()
            self._ingest_progress = None

    @Slot(str)
    def _on_folder_ingest_error(self, message: str) -> None:
        self._cleanup_ingest_thread()
        self._pending_ingest_scan = None
        self._pending_ingest_folder = ""
        self.app._message_dialog("Dataset folder", "Failed to index evidence files.", message, width=520)

    @Slot(object)
    def _on_folder_ingest_finished(self, scan) -> None:
        folder = self._pending_ingest_folder
        purpose = getattr(self, "_ingest_purpose", "import")
        self._cleanup_ingest_thread()
        self._pending_ingest_scan = None
        self._pending_ingest_folder = ""
        if not folder:
            return

        if purpose == "json_only":
            self._finish_load_dataset_path(folder, scan)
            return
        self._process_scanned_folder(folder, scan)

    def _process_scanned_folder(self, folder: str, scan) -> str | None:
        json_files = [item.path for item in scan.json_files]
        pcap_files = [item.path for item in scan.pcap_files]

        if not json_files and not pcap_files:
            self.app._message_dialog(
                "Dataset folder",
                "No JSON or PCAP files were found in the selected folder.",
                folder,
                width=520,
            )
            return None

        opened = None
        self._register_project_evidence_source(folder, scan)
        if json_files:
            json_day_groups = group_evidence_by_date(scan.json_files)
            if self._should_load_folder_interactively(len(json_files), scan.json_size):
                if len(json_day_groups) > 1:
                    first_day_paths = self._set_json_day_groups(folder, {
                        date: evidence_paths(items)
                        for date, items in json_day_groups.items()
                    })
                    if first_day_paths:
                        self.load_dataset_files(folder, first_day_paths)
                else:
                    self._clear_json_day_groups()
                    self.load_dataset_files(folder, [str(path) for path in json_files])
            else:
                day_groups_dict = {
                    date: evidence_paths(items)
                    for date, items in json_day_groups.items()
                }
                self._set_json_day_groups(folder, day_groups_dict)
                self._mark_large_json_source_indexed(folder, len(json_files), scan.json_size, day_count=len(day_groups_dict))
                first_paths = list(self._json_day_groups.get(self._json_active_day, []) or [])
                if first_paths and len(first_paths) <= MAX_INTERACTIVE_FOLDER_JSON_FILES:
                    self.load_dataset_files(folder, first_paths)
            opened = "json"

        if pcap_files and hasattr(self.app, "pcap_page"):
            statuses = ingest_status_map(self.app.current_project_id, evidence_paths(scan.pcap_files))
            pending_pcap_files = [
                item
                for item in scan.pcap_files
                if statuses.get(str(item.path)) != "done"
            ]
            if not pending_pcap_files:
                self.app._message_dialog(
                    "PCAP folder",
                    f"{len(pcap_files)} PCAP files were found.",
                    "All PCAP files from this source are already marked as processed for the active project.",
                    width=560,
                )
                return opened or "pcap"

            pcap_day_groups = group_evidence_by_date(pending_pcap_files)
            use_batch = should_batch_pcap_files(len(pending_pcap_files), scan.pcap_size)
            multi_period = len(pcap_day_groups) > 1
            save_all_periods = use_batch or multi_period
            self.app.go_page(self.app.IDX_PCAP, self.app._nav_pcap)
            if save_all_periods:
                self.app.pcap_page.load_pcap_queue(
                    evidence_paths(pending_pcap_files),
                    auto_save=True,
                    auto_process=True,
                    day_groups={
                        date: evidence_paths(items)
                        for date, items in pcap_day_groups.items()
                    },
                )
                mode_text = indexed_source_message(
                    pcap_files=len(pending_pcap_files),
                    batch_started=True,
                )
            elif self._should_load_folder_interactively(len(pending_pcap_files), scan.pcap_size):
                self.app.pcap_page.load_pcap_queue(
                    evidence_paths(pending_pcap_files),
                    auto_save=True,
                    auto_process=False,
                    day_groups={
                        date: evidence_paths(items)
                        for date, items in pcap_day_groups.items()
                    },
                )
                mode_text = (
                    "ViaNyquist opened the first selected period for interactive review. "
                    f"Use the {PERIOD_LABEL.strip(':')} selector on the PCAP page to switch days."
                )
            else:
                self._mark_large_pcap_source_indexed(
                    folder,
                    len(pending_pcap_files),
                    scan.pcap_size,
                    pending_paths=evidence_paths(pending_pcap_files),
                    day_groups={
                        date: evidence_paths(items)
                        for date, items in pcap_day_groups.items()
                    },
                )
                mode_text = indexed_source_message(pcap_files=len(pending_pcap_files))
            opened = "pcap"
            if len(pending_pcap_files) > 1 or use_batch:
                skipped = len(pcap_files) - len(pending_pcap_files)
                skipped_text = f"\n\nSkipped already processed PCAP files: {skipped:,}." if skipped else ""
                self.app._message_dialog(
                    "Import evidence folder",
                    f"{len(pcap_files):,} PCAP files found in the selected period.",
                    f"{mode_text}{skipped_text}",
                    width=620,
                )

        return opened

    def load_dataset_dialog(self):
        if not self._ensure_active_project():
            return None

        choice = self.app._choice_dialog(
            title="Open dataset",
            message="What do you want to open?",
            choices=["Folder", "JSON file", "PCAP file"],
            width=560,
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
        start_edit = self._date_edit(first, first, last)
        end_edit = self._date_edit(last, first, last)

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

    def _date_edit(self, value: QDate, minimum: QDate, maximum: QDate) -> QDateEdit:
        edit = QDateEdit(value)
        edit.setCalendarPopup(True)
        edit.setDisplayFormat("dd/MM/yyyy")
        edit.setMinimumDate(minimum)
        edit.setMaximumDate(maximum)
        edit.setFixedWidth(220)
        calendar = QCalendarWidget(edit)
        calendar.setGridVisible(True)
        calendar.setFixedSize(430, 340)
        calendar.setVerticalHeaderFormat(QCalendarWidget.NoVerticalHeader)
        calendar.setHorizontalHeaderFormat(QCalendarWidget.ShortDayNames)
        edit.setCalendarWidget(calendar)
        return edit

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
        return date.toString("dd/MM/yyyy")

    def _register_project_evidence_source(self, folder: str, scan) -> None:
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

    def _mark_large_json_source_indexed(self, folder: str, file_count: int, byte_count: int, *, day_count: int = 0) -> None:
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

        open_project_rows_dialog(
            self.app,
            title,
            [("rank", "#"), ("value", "Name"), ("count", "Count")],
            rows,
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
                first_day_paths = self._set_json_day_groups(folder, {
                    date: evidence_paths(items)
                    for date, items in json_day_groups.items()
                })
                if first_day_paths:
                    self.load_dataset_files(folder, first_day_paths)
            else:
                self._clear_json_day_groups()
                self.load_dataset_files(folder, [str(path) for path in json_files])
        else:
            day_groups_dict = {
                date: evidence_paths(items)
                for date, items in json_day_groups.items()
            }
            self._set_json_day_groups(folder, day_groups_dict)
            self._mark_large_json_source_indexed(folder, len(json_files), scan.json_size, day_count=len(day_groups_dict))
            first_paths = list(self._json_day_groups.get(self._json_active_day, []) or [])
            if first_paths and len(first_paths) <= MAX_INTERACTIVE_FOLDER_JSON_FILES:
                self.load_dataset_files(folder, first_paths)

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

        self._clear_json_day_groups()
        previous_path = self._get_previous_dataset_path(file_path)
        self._start_dataset_load("file", file_path, previous_path)

    def load_dataset_files(self, source_path: str, files: list[str]):
        if not self._ensure_active_project():
            return

        if not files:
            return

        previous_path = self._get_previous_dataset_path(source_path)
        self._start_dataset_load("files", source_path, previous_path, files=files)

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
        self._load_active_json_period(force=True)

    def _set_json_day_groups(self, source_path: str, day_groups: dict[str, list[str]]) -> list[str]:
        cleaned = {
            str(day): [str(path) for path in paths if str(path or "").strip()]
            for day, paths in (day_groups or {}).items()
        }
        cleaned = {day: paths for day, paths in cleaned.items() if paths}
        self._json_day_groups = dict(sorted(cleaned.items(), key=lambda pair: (pair[0] == "undated", pair[0])))
        self._json_day_source = str(source_path or "")

        combo = getattr(self.app, "cmb_json_day", None)
        label = getattr(self.app, "lbl_json_day", None)
        if not self._json_day_groups or combo is None or label is None:
            self._clear_json_day_groups()
            return []

        self._json_day_switching = True
        combo.blockSignals(True)
        combo.clear()
        for day, paths in self._json_day_groups.items():
            combo.addItem(period_combo_label(day, len(paths), kind="JSON"), day)
        combo.blockSignals(False)
        combo.setVisible(True)
        if label is not None:
            label.setText(PERIOD_LABEL)
        label.setVisible(True)
        self._json_day_switching = False
        self._json_active_day = str(combo.currentData() or next(iter(self._json_day_groups)))
        if not self.app.flow_controller.get_all():
            QTimer.singleShot(0, self._load_active_json_period)
        self._update_json_gap_banner(list(self._json_day_groups.keys()))
        return list(self._json_day_groups.get(self._json_active_day, []))

    def _load_active_json_period(self, *, force: bool = False) -> None:
        if self._json_day_switching or not self._json_day_groups or not self._json_day_source:
            return
        if self._load_thread is not None:
            return
        combo = getattr(self.app, "cmb_json_day", None)
        day = str(self._json_active_day or (combo.currentData() if combo is not None else "") or "")
        if not day:
            return
        files = list(self._json_day_groups.get(day, []))
        if not files:
            return
        if not force and self.app.flow_controller.get_all():
            return
        self._json_active_day = day
        self.load_dataset_files(self._json_day_source, files)

    def _clear_json_day_groups(self) -> None:
        self._json_day_groups = {}
        self._json_day_source = ""
        self._json_active_day = ""
        combo = getattr(self.app, "cmb_json_day", None)
        label = getattr(self.app, "lbl_json_day", None)
        if combo is not None:
            self._json_day_switching = True
            combo.blockSignals(True)
            combo.clear()
            combo.blockSignals(False)
            combo.setVisible(False)
            self._json_day_switching = False
        if label is not None:
            label.setVisible(False)
        self._update_json_gap_banner([])

    def _update_json_gap_banner(self, present_days: list[str] | None = None) -> None:
        days = present_days if present_days is not None else list(self._json_day_groups.keys())
        gap = missing_period_days(days)
        self._json_gap_info = gap
        summary = format_missing_days_summary(gap)
        lbl = getattr(self.app, "lbl_json_gaps", None)
        btn = getattr(self.app, "btn_expand_json_gaps", None)
        if lbl is not None:
            lbl.setText(summary)
            lbl.setToolTip(summary)
        if btn is not None:
            missing_count = int(gap.get("missing_count") or 0)
            btn.setVisible(missing_count > 0)
            btn.setText(f"Missing days ({missing_count:,})")

    def open_json_missing_days_dialog(self) -> None:
        missing = list(self._json_gap_info.get("missing_days") or [])
        if not missing:
            self.app._message_dialog("Missing days", "No internal gaps in the indexed period range.", width=420)
            return

        first = self._format_day_label(str(self._json_gap_info.get("first_day") or ""))
        last = self._format_day_label(str(self._json_gap_info.get("last_day") or ""))

        dlg = QDialog(self.app)
        dlg.setWindowTitle("Missing JSON days")
        dlg.resize(720, 560)
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(14, 14, 14, 28)
        hint = QLabel(
            f"{len(missing):,} indexed days missing between {first} and {last}. "
            "These are internal gaps — calendar days inside the imported period with no JSON files."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        table = QTableWidget(len(missing), 2, dlg)
        table.setHorizontalHeaderLabels(["Missing day", "ISO date"])
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        for row_index, day in enumerate(missing):
            table.setItem(row_index, 0, QTableWidgetItem(self._format_day_label(day)))
            table.setItem(row_index, 1, QTableWidgetItem(day))
        table.resizeColumnsToContents()
        layout.addWidget(table, 1)

        footer = QHBoxLayout()
        footer.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setMinimumHeight(42)
        close_btn.clicked.connect(dlg.accept)
        footer.addWidget(close_btn)
        layout.addLayout(footer)
        dlg.exec()

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

    def _start_dataset_load(self, mode: str, path: str, previous_path: str = "", files: list[str] | None = None):
        if self._load_thread is not None:
            self.app._message_dialog("Dataset", "A dataset is already loading.", width=420)
            return

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
        self._load_worker.finished.connect(self._on_dataset_loaded, Qt.QueuedConnection)
        self._load_worker.error.connect(self._on_dataset_load_error, Qt.QueuedConnection)
        self._load_worker.finished.connect(self._load_thread.quit)
        self._load_worker.error.connect(self._load_thread.quit)
        self._load_worker.finished.connect(self._load_worker.deleteLater)
        self._load_worker.error.connect(self._load_worker.deleteLater)
        self._load_thread.finished.connect(self._load_thread.deleteLater)
        self._load_thread.finished.connect(self._cleanup_load_thread)
        self._load_thread.start()

    @Slot(object)
    def _on_dataset_loaded(self, result: dict):
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
        if target_identifier and target_type:
            return f"{target_identifier} ({target_type})"
        return target_identifier or target_type or "-"

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
        if hasattr(self.app, "lbl_stats"):
            self.app.explore_ui_controller.set_json_stats_text("JSON dataset load failed.", include_counts=False)
        self.app._message_dialog("Dataset", title, details, width=520)

    @Slot()
    def _cleanup_load_thread(self):
        self._load_worker = None
        self._load_thread = None
        self._set_loading(False)

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

        total_files = sum(len(paths) for paths in by_day.values())
        if hasattr(self.app, "lbl_path") and not str(getattr(self.app, "current_folder", "") or "").strip():
            self.app.lbl_path.setText(f"Project: {getattr(self.app, 'current_project_name', '') or 'active'}")
        indexed_msg = (
            f"{total_files:,} JSON files indexed across {len(by_day)} periods. "
            f"Select Period above to load a day into the registry."
        )
        if hasattr(self.app, "lbl_stats"):
            self.app.explore_ui_controller.set_json_stats_text(indexed_msg, include_counts=False)

    def sync_pcap_periods_from_project(self, project_id: int | None) -> None:
        """Restore PCAP period selector from saved ingest and project PCAP rows."""
        from core.project_evidence import build_project_evidence_snapshot

        pcap_page = getattr(self.app, "pcap_page", None)
        if pcap_page is None:
            return
        if project_id is None:
            pcap_page._clear_day_groups()
            return

        evidence = build_project_evidence_snapshot(project_id)
        by_day = dict(evidence["pcap"]["day_groups"])
        if not by_day:
            pcap_page._clear_day_groups()
            return

        pcap_page._set_day_groups(by_day, allow_empty_days=True)
        pcap_page._update_period_gap_banner(list(by_day.keys()))
        if getattr(pcap_page, "summary", None) is None and hasattr(pcap_page, "lbl_stats"):
            total_files = sum(len(paths) for paths in by_day.values())
            saved_only = sum(1 for paths in by_day.values() if not paths)
            saved_note = f" ({saved_only} saved-only)" if saved_only else ""
            pcap_page.lbl_stats.setText(
                f"{total_files:,} PCAP files indexed across {len(by_day)} periods{saved_note}. "
                f"Select Period above to open saved analysis or re-analyze source files."
            )
        QTimer.singleShot(0, lambda: pcap_page.load_active_period(prefer_saved=True))

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
        self._behavior_index_thread.finished.connect(self._behavior_index_thread.deleteLater)
        self._behavior_index_thread.finished.connect(self._cleanup_behavior_index_thread)
        self._behavior_index_thread.start()

    @Slot(object)
    def _on_behavior_index_finished(self, profile: dict):
        if profile.get("project_id") != self.app.current_project_id:
            return

        if hasattr(self.app, "activity_profile_page"):
            self.app.activity_profile_page.invalidate_project_cache()
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

    def clear_context(self) -> None:
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

    def shutdown_background_tasks(self, wait_ms: int = 5000) -> None:
        for progress_name in ("_scan_progress", "_ingest_progress"):
            progress = getattr(self, progress_name, None)
            if progress is not None:
                progress.close()
                setattr(self, progress_name, None)
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
