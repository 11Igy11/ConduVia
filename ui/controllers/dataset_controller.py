from __future__ import annotations

from ui.controllers.dataset_ingest_mixin import DatasetIngestMixin
from ui.controllers.dataset_load_mixin import DatasetLoadMixin
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
    embedded_expand_available,
    embedded_expand_tooltip,
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


def _day_groups_equal(
    left: dict[str, list[str]] | None,
    right: dict[str, list[str]] | None,
) -> bool:
    left = left or {}
    right = right or {}
    if set(left) != set(right):
        return False
    for day in left:
        if list(left.get(day) or []) != list(right.get(day) or []):
            return False
    return True


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


class DatasetController(DatasetLoadMixin, DatasetIngestMixin, QObject):
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
        self._pcap_ingest_day_groups_cache: dict[int, dict[str, list[str]]] = {}
        self._json_ingest_day_groups_cache: dict[int, dict[str, list[str]]] = {}
        self._deferred_sync_timer: QTimer | None = None
        self._deferred_sync_project_id: int | None = None

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
        if pcap_page is not None:
            if pcap_page.batch_is_running():
                return True
            if getattr(pcap_page, "_thread", None) is not None:
                return True
        return False

    def _thread_is_running(self, thread: QThread | None) -> bool:
        return thread is not None and thread.isRunning()

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
            button.setEnabled(embedded_expand_available(total, preview_rows=preview))
            tooltip = embedded_expand_tooltip(total, preview_rows=preview)
            button.setToolTip(tooltip)

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

    def _apply_json_full_period_index(self) -> None:
        """Show every indexed JSON day after reloading ingest (not only the last import window)."""
        self._json_period_granularity = "day"
        self._json_period_range_start = ""
        self._json_period_range_end = ""
        mode_combo = getattr(self.app, "cmb_json_period_mode", None)
        if mode_combo is not None:
            mode_combo.blockSignals(True)
            day_index = mode_combo.findData("day")
            if day_index >= 0:
                mode_combo.setCurrentIndex(day_index)
            mode_combo.blockSignals(False)
        self._sync_json_range_button()
        if self._json_day_groups_raw:
            self._rebuild_json_period_combo()
        self._sync_json_period_selector_panel()

    def _apply_period_index_after_project_sync(self, by_day: dict[str, list[str]], *, kind: str) -> None:
        from core.period_gaps import normalize_period_day
        from core.period_groups import is_range_period_key, parse_range_period_key

        daily_keys = [day for day in by_day if normalize_period_day(day)]
        range_keys = [day for day in by_day if is_range_period_key(day)]

        if kind == "json":
            if len(range_keys) == 1 and not daily_keys:
                start, end = parse_range_period_key(range_keys[0])
                if start and end:
                    self._apply_imported_period_as_default(start, end)
                    return
            self._apply_json_full_period_index()
            return

        pcap_page = getattr(self.app, "pcap_page", None)
        if pcap_page is None:
            return
        if len(range_keys) == 1 and not daily_keys:
            start, end = parse_range_period_key(range_keys[0])
            if start and end:
                pcap_page._apply_imported_period_range_only(start, end)
                return
        pcap_page._apply_full_project_period_index()

    def deferred_sync_project_periods(self, project_id: int | None) -> None:
        """Populate JSON/PCAP period selectors without loading flows or PCAP analysis."""
        if project_id is None:
            return
        self._deferred_sync_project_id = int(project_id)
        timer = self._deferred_sync_timer
        if timer is None:
            timer = QTimer(self)
            timer.setSingleShot(True)
            timer.timeout.connect(self._run_deferred_sync_project_periods)
            self._deferred_sync_timer = timer
        if timer.isActive():
            timer.stop()
        timer.start(50)

    def _run_deferred_sync_project_periods(self) -> None:
        project_id = self._deferred_sync_project_id
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

        by_day = self._cached_json_day_groups(project_id)
        if not by_day:
            self._clear_json_day_groups()
            return

        if _day_groups_equal(self._json_day_groups_raw, by_day):
            self._sync_json_period_selector_panel()
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
        self._apply_period_index_after_project_sync(by_day, kind="json")

        total_files = sum(len(paths) for paths in by_day.values())
        if hasattr(self.app, "lbl_path") and not str(getattr(self.app, "current_folder", "") or "").strip():
            self.app.lbl_path.setText(f"Project: {getattr(self.app, 'current_project_name', '') or 'active'}")
        indexed_msg = (
            f"{total_files:,} JSON files indexed across {len(by_day)} periods. "
            f"Select Period above to load flows into the table."
        )
        if hasattr(self.app, "lbl_stats"):
            self.app.explore_ui_controller.set_json_stats_text(indexed_msg, include_counts=False)

    def _cached_json_day_groups(self, project_id: int) -> dict[str, list[str]]:
        cached = self._json_ingest_day_groups_cache.get(int(project_id))
        if cached is not None:
            return dict(cached)
        by_day = self._json_day_groups_from_ingest(project_id)
        self._json_ingest_day_groups_cache[int(project_id)] = dict(by_day)
        return by_day

    def _cached_pcap_day_groups(self, project_id: int) -> dict[str, list[str]]:
        from core.project_evidence import pcap_day_groups_from_ingest

        cached = self._pcap_ingest_day_groups_cache.get(int(project_id))
        if cached is not None:
            return dict(cached)
        by_day = pcap_day_groups_from_ingest(project_id)
        self._pcap_ingest_day_groups_cache[int(project_id)] = dict(by_day)
        return by_day

    def _invalidate_ingest_day_groups_cache(self, project_id: int | None = None) -> None:
        if project_id is None:
            self._pcap_ingest_day_groups_cache.clear()
            self._json_ingest_day_groups_cache.clear()
            return
        self._pcap_ingest_day_groups_cache.pop(int(project_id), None)
        self._json_ingest_day_groups_cache.pop(int(project_id), None)

    def _invalidate_pcap_ingest_day_groups_cache(self, project_id: int | None = None) -> None:
        self._invalidate_ingest_day_groups_cache(project_id)

    def sync_pcap_periods_from_project(self, project_id: int | None) -> None:
        """Restore PCAP period selector from ingest index (lightweight, no auto-load)."""
        pcap_page = getattr(self.app, "pcap_page", None)
        if pcap_page is None:
            return
        if project_id is None:
            pcap_page._clear_day_groups()
            return

        by_day = self._cached_pcap_day_groups(project_id)
        if not by_day:
            pcap_page._clear_day_groups()
            return

        if _day_groups_equal(getattr(pcap_page, "_pcap_day_groups_raw", {}), by_day):
            pcap_page._sync_period_selector_panel()
            return

        pcap_page._set_day_groups(by_day, allow_empty_days=True)
        self._apply_period_index_after_project_sync(by_day, kind="pcap")
        pcap_page._sync_period_selector_panel()
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
        self._reset_import_finalize_state()
        self.reset_loaded_flow_views()
        self._clear_json_day_groups()

        if hasattr(self.app, "pcap_page"):
            self.app.pcap_page.clear_project_view()

    def _reset_import_finalize_state(self) -> None:
        """Clear deferred import flags so project switches cannot leave the UI stuck."""
        self._import_finalize_pending = False
        self._import_finalize_running = False
        self._import_finalize_completed = False
        self._defer_import_finalize = False
        self._import_plan = None
        self._pending_import_banner_message = ""
        self._clear_import_status()
        self._invalidate_ingest_day_groups_cache()

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