from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QDate, QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QCalendarWidget,
    QCheckBox,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QFileDialog,
    QVBoxLayout,
)

from core.analyzer import top_applications, top_dst_ips, top_protocols, top_src_ips
from core.case_ingest import evidence_paths, filter_case_scan, group_evidence_by_date, scan_case_source
from core.db import (
    add_dataset_load,
    get_project,
    ingest_status_map,
    mark_ingest_item,
    list_recent_datasets,
    set_project_target,
    update_dataset_scan_metadata,
    upsert_ingest_items,
)
from core.loader import list_json_files_recursive, load_folder_recursive, load_json_file
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

    def run(self):
        try:
            previous_flows = self._load_previous_flows()

            if self.mode == "folder":
                files, flows = load_folder_recursive(self.path, debug=False)
                dataset_label = f"Dataset: {self.path}"
                stats_label = f"JSON files: {len(files)}   |   Total flow records: {len(flows)}"
                current_folder = self.path
            elif self.mode == "files":
                files = [Path(path) for path in self.files if str(path or "").strip()]
                flows = []
                for fp in files:
                    flows.extend(load_json_file(fp, debug=False))
                dataset_label = f"Dataset selection: {self.path}"
                stats_label = f"JSON files: {len(files)}   |   Total flow records: {len(flows)}"
                current_folder = self.path
            elif self.mode == "file":
                fp = Path(self.path)
                flows = load_json_file(fp, debug=False)
                files = [fp]
                dataset_label = f"Dataset file: {self.path}"
                stats_label = f"JSON files: 1   |   Total flow records: {len(flows)}"
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

    def run(self):
        try:
            self.finished.emit(build_project_behavior_index(self.project_id))
        except Exception as exc:
            self.error.emit(str(exc))


class DatasetController(QObject):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self._load_thread: QThread | None = None
        self._load_worker: DatasetLoadWorker | None = None
        self._behavior_index_thread: QThread | None = None
        self._behavior_index_worker: BehaviorIndexWorker | None = None
        self._json_day_groups: dict[str, list[str]] = {}
        self._json_day_source = ""
        self._json_active_day = ""
        self._json_day_switching = False
        self._pending_behavior_index_project_id: int | None = None

    def _split_ranked_lines(self, items):
        left_lines = []
        right_lines = []

        for i, (name, count) in enumerate(items, start=1):
            left_lines.append(f"{i}. {name}")
            right_lines.append(str(count))

        return "\n".join(left_lines), "\n".join(right_lines)

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
            try:
                scan = scan_case_source(folder)
            except Exception as exc:
                self.app._message_dialog("Dataset folder", "Failed to scan selected folder.", str(exc), width=520)
                return None

            scan = self._select_case_ingest_scope(scan)
            if scan is None:
                return None

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
            if json_files:
                add_dataset_load(self.app.current_project_id, folder)
                self._upsert_json_ingest_items(folder, scan.json_files)
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
                    self._clear_json_day_groups()
                    self._mark_large_json_source_indexed(folder, len(json_files), scan.json_size)
                opened = "json"

            if pcap_files and hasattr(self.app, "pcap_page"):
                upsert_ingest_items(
                    self.app.current_project_id,
                    folder,
                    (
                        {
                            "file_path": str(item.path),
                            "file_name": item.path.name,
                            "file_type": item.kind,
                            "file_size": item.size,
                            "observed_date": item.observed_date,
                        }
                        for item in scan.pcap_files
                    ),
                )
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
                self.app.go_page(self.app.IDX_PCAP, self.app._nav_pcap)
                if use_batch:
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
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
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

    def _mark_large_json_source_indexed(self, folder: str, file_count: int, byte_count: int) -> None:
        if hasattr(self.app, "lbl_path"):
            self.app.lbl_path.setText(f"Indexed JSON source: {folder}")
        if hasattr(self.app, "lbl_stats"):
            self.app.lbl_stats.setText(
                f"JSON files indexed: {file_count:,} | Size: {human_bytes(byte_count, precision=2)} | "
                "Open a narrower folder/date range for interactive table review."
            )
        if hasattr(self.app, "lbl_json_meta"):
            self.app.lbl_json_meta.setText("")
        if hasattr(self.app, "projects_ui_controller"):
            self.app.projects_ui_controller.sync_project_workspace(self.app.current_project_id)
            self.app.projects_ui_controller.refresh_recent_datasets(self.app.current_project_id)
            self.app.projects_ui_controller.refresh_case_dashboard(self.app.current_project_id)
        if hasattr(self.app, "refresh_activity_ui"):
            self.app.refresh_activity_ui()
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
            self.app.projects_ui_controller.refresh_case_dashboard(self.app.current_project_id)
        if hasattr(self.app, "refresh_activity_profile_ui"):
            self.app.refresh_activity_profile_ui()

    def render_summary(self):
        flows = self.app.flow_controller.get_all()

        if not flows:
            self.app.txt_top_src_left.setText("No flows loaded.")
            self.app.txt_top_src_right.setText("")

            self.app.txt_top_dst_left.setText("No flows loaded.")
            self.app.txt_top_dst_right.setText("")

            self.app.txt_top_proto_left.setText("No flows loaded.")
            self.app.txt_top_proto_right.setText("")

            self.app.txt_top_apps_left.setText("No flows loaded.")
            self.app.txt_top_apps_right.setText("")
            return

        src_items = top_src_ips(flows, limit=5)
        dst_items = top_dst_ips(flows, limit=5)
        proto_items = [(format_ip_proto(proto), c) for proto, c in top_protocols(flows, limit=5)]
        app_items = top_applications(flows, limit=5)

        left, right = self._split_ranked_lines(src_items)
        self.app.txt_top_src_left.setText(left)
        self.app.txt_top_src_right.setText(right)

        left, right = self._split_ranked_lines(dst_items)
        self.app.txt_top_dst_left.setText(left)
        self.app.txt_top_dst_right.setText(right)

        left, right = self._split_ranked_lines(proto_items)
        self.app.txt_top_proto_left.setText(left)
        self.app.txt_top_proto_right.setText(right)

        left, right = self._split_ranked_lines(app_items)
        self.app.txt_top_apps_left.setText(left)
        self.app.txt_top_apps_right.setText(right)

    def load_dataset_path(self, folder: str):
        if not self._ensure_active_project():
            return

        folder = str(folder)
        path = Path(folder)
        if not path.exists():
            self.app._message_dialog("Dataset", "Folder not found.", folder, width=480)
            return

        try:
            scan = scan_case_source(folder)
        except Exception as exc:
            self.app._message_dialog("Dataset folder", "Failed to scan selected folder.", str(exc), width=520)
            return

        json_files = [item.path for item in scan.json_files]
        if not json_files:
            self.app._message_dialog("Dataset folder", "No JSON files were found in the selected folder.", folder, width=520)
            return

        add_dataset_load(self.app.current_project_id, folder)
        self._upsert_json_ingest_items(folder, scan.json_files)
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
            self._clear_json_day_groups()
            self._mark_large_json_source_indexed(folder, len(json_files), scan.json_size)

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
        for row in item_rows:
            mark_ingest_item(project_id, row["file_path"], "done")

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
        if self._load_thread is not None:
            return
        combo = getattr(self.app, "cmb_json_day", None)
        if combo is None:
            return
        day = str(combo.itemData(index) or "")
        files = list(self._json_day_groups.get(day, []))
        if not files:
            return
        self._json_active_day = day
        self.load_dataset_files(self._json_day_source, files)

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
        return list(self._json_day_groups.get(self._json_active_day, []))

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
            self.app.lbl_stats.setText("Loading and parsing JSON flows. Please wait...")
        if hasattr(self.app, "lbl_json_meta"):
            self.app.lbl_json_meta.setText("")

        self._load_thread = QThread()
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
            stats_label = f"{stats_label}   |   Day: {self._format_day_label(self._json_active_day)}"
        self.app.lbl_stats.setText(stats_label)
        if hasattr(self.app, "lbl_json_meta"):
            self.app.lbl_json_meta.setText(_json_order_metadata_line(result.get("meta") or {}))

        if self.app.current_project_id is not None:
            add_dataset_load(self.app.current_project_id, path)
            if hasattr(self.app, "projects_ui_controller"):
                self.app.projects_ui_controller.sync_project_workspace(self.app.current_project_id)
            self.app.projects_ui_controller.refresh_recent_datasets(self.app.current_project_id)
            self.app.refresh_activity_ui()
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

    def _on_dataset_load_error(self, title: str, details: str):
        if hasattr(self.app, "lbl_stats"):
            self.app.lbl_stats.setText("JSON dataset load failed.")
        self.app._message_dialog("Dataset", title, details, width=520)

    def _cleanup_load_thread(self):
        self._load_worker = None
        self._load_thread = None
        self._set_loading(False)

    def refresh_project_behavior_index(self, project_id: int | None):
        self._start_behavior_index(project_id)

    def _start_behavior_index(self, project_id: int | None):
        if project_id is None:
            return
        if self._behavior_index_thread is not None:
            self._pending_behavior_index_project_id = project_id
            return

        self._behavior_index_thread = QThread()
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

    def _on_behavior_index_finished(self, profile: dict):
        if profile.get("project_id") != self.app.current_project_id:
            return

        if hasattr(self.app, "activity_profile_page"):
            self.app.activity_profile_page.invalidate_project_cache()
        self.app.refresh_activity_profile_ui()

    def _on_behavior_index_error(self, message: str):
        if hasattr(self.app, "lbl_stats"):
            self.app.lbl_stats.setText(f"Project profile index failed: {message}")

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
