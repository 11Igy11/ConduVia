from ui.explore_widgets import AITextWorker
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTableView
from ui.column_picker_dialog import ColumnPickerDialog
from ui.export_menu import popup_export_menu
from ui.font_utils import apply_named_style
from ui.flow_columns import DEFAULT_FLOW_COLUMNS, available_flow_columns
from ui.table_export import export_table_dialog

from core.formatters import format_export_cell, human_bytes
from core.protocols import format_ip_proto

class ExploreUIController:
    def __init__(self, app):
        self.app = app
        self._json_stats_base = ""
        self._json_stats_include_counts = True
        self._flows_custom_columns: list[str] = []

    def on_page_size_changed(self, txt: str):
        try:
            self.app.PAGE_SIZE = max(250, int(txt))
        except Exception:
            self.app.PAGE_SIZE = 2000

        self.app.flow_controller.page_size = self.app.PAGE_SIZE
        self.update_loaded_label()
        self.update_load_more_enabled()

    def update_loaded_label(self):
        self.refresh_json_header_stats()

    def refresh_json_header_stats(self) -> None:
        parts: list[str] = []
        base = str(getattr(self, "_json_stats_base", "") or "").strip()
        if base:
            parts.append(base)
        if getattr(self, "_json_stats_include_counts", True):
            total = self.app.flow_controller.get_total_count()
            loaded = self.app.flow_controller.get_loaded_count()
            if total:
                parts.append(f"Loaded: {loaded} / {total}")
            shown_total = self.app.flow_controller.get_loaded_count()
            shown = self.app.proxy.rowCount()
            if shown_total:
                parts.append(f"Showing: {shown} / {shown_total} (loaded)")
        self.app.lbl_stats.setText(" | ".join(parts))
        if hasattr(self.app, "lbl_loaded"):
            self.app.lbl_loaded.clear()
        if hasattr(self.app, "lbl_showing"):
            self.app.lbl_showing.clear()

    def set_json_stats_text(
        self,
        text: str,
        *,
        include_counts: bool = True,
        loading: bool = False,
    ) -> None:
        self._json_stats_base = str(text or "")
        self._json_stats_include_counts = include_counts
        if hasattr(self.app, "lbl_stats"):
            apply_named_style(
                self.app.lbl_stats,
                "PcapLoadingStatus" if loading else "HeaderStatLabel",
            )
        self.refresh_json_header_stats()

    def update_load_more_enabled(self):
        self.app.btn_load_more.setEnabled(
            self.app.flow_controller.get_loaded_count() < self.app.flow_controller.get_total_count()
        )

    def load_next_page(self):
        flows = self.app.flow_controller.load_next_page()
        self.app.model.set_flows(flows)
        self.update_loaded_label()
        self.update_load_more_enabled()
        self.update_showing()

    def on_table_scrolled(self, value: int):
        if self.app.flow_controller.get_total_count() == 0:
            return

        if self.app._conversation_on:
            return

        bar = self.app.table.verticalScrollBar()
        if bar.maximum() <= 0:
            return

        if value >= int(bar.maximum() * 0.92):
            if self.app.flow_controller.get_loaded_count() < self.app.flow_controller.get_total_count():
                self.load_next_page()

    def on_row_selected(self, *args):
        sel = self.app.table.selectionModel().selectedRows()
        if not sel:
            self.update_detail(None)
            return

        proxy_index = sel[0]
        source_index = self.app.proxy.mapToSource(proxy_index)
        row = source_index.row()

        flow = self.app.flow_controller.get_flow_by_row(row)
        self.update_detail(flow)

    def update_detail(self, flow):
        self.app._current_flow = flow

        if not flow:
            self.app.d_src.setText("-")
            self.app.d_dst.setText("-")
            self.app.d_proto.setText("-")
            self.app.d_app.setText("-")
            self.app.d_bytes.setText("-")
            self.app.d_packets.setText("-")
            self.app.d_duration.setText("-")
            self.app.d_sni.setText("-")
            return

        self.app.d_src.setText(f"{flow.get('src_ip','')}:{flow.get('src_port','')}")
        self.app.d_dst.setText(f"{flow.get('dst_ip','')}:{flow.get('dst_port','')}")
        self.app.d_proto.setText(format_ip_proto(flow.get("protocol", "")))
        self.app.d_app.setText(str(flow.get("application_name", "")))
        self.app.d_bytes.setText(human_bytes(flow.get("bidirectional_bytes", 0), precision=2))
        self.app.d_packets.setText(str(flow.get("bidirectional_packets", "")))
        self.app.d_duration.setText(str(flow.get("bidirectional_duration_ms", "")))
        self.app.d_sni.setText(str(flow.get("requested_server_name", "")))

    def enter_conversation(self, src: str, dst: str):
        if not src or not dst:
            return

        self.ensure_pair_loaded(src, dst)

        self.app.proxy.set_conversation(src, dst)
        self.app._conversation_on = True

        self.app.btn_toggle_conv.setText("Conversation: ON")

        self.update_mode_label()
        self.update_showing()
        self.update_conversation_summary()

        self.app.proxy.invalidate()

    def leave_conversation(self, clear_search: bool = False):
        self.app.proxy.clear_conversation()
        self.app._conversation_on = False

        self.app.btn_toggle_conv.setText("Conversation: OFF")

        self.update_mode_label()
        self.update_conversation_summary()

        if clear_search:
            self.app.search.setText("")

        self.update_showing()

    def toggle_conversation(self):
        if self.app._conversation_on:
            self.leave_conversation()
            return

        if not self.app._current_flow:
            self.app._message_dialog("Conversation", "Select a flow first (Flows tab).", width=420)
            return

        src = self.app.current_value("src_ip")
        dst = self.app.current_value("dst_ip")

        self.enter_conversation(src, dst)

    def update_mode_label(self):
        if self.app._conversation_on and self.app.proxy.conv_a and self.app.proxy.conv_b:
            a = self.app.proxy.conv_a
            b = self.app.proxy.conv_b

            self.app.lbl_mode.setText(f"Mode: Conversation between {a} ⇄ {b}")
            self.app.lbl_mode.show()
        else:
            self.app.lbl_mode.clear()
            self.app.lbl_mode.hide()

    def update_conversation_summary(self):
        if not self.app._conversation_on:
            self.app.lbl_conv_summary.clear()
            self.app.lbl_conv_summary.hide()
            return

        rows = self.app.proxy.rowCount()
        if rows == 0:
            self.app.lbl_conv_summary.clear()
            self.app.lbl_conv_summary.hide()
            return

        total_bytes = 0
        apps = {}

        bytes_col = self._flow_column_index("bidirectional_bytes")
        app_col = self._flow_column_index("application_name")

        for r in range(rows):
            idx_bytes = self.app.proxy.index(r, bytes_col) if bytes_col >= 0 else None
            idx_app = self.app.proxy.index(r, app_col) if app_col >= 0 else None

            b = self.app.proxy.data(idx_bytes, Qt.DisplayRole) if idx_bytes is not None else 0
            app_name = self.app.proxy.data(idx_app, Qt.DisplayRole) or "" if idx_app is not None else ""

            try:
                total_bytes += int(b)
            except Exception:
                pass

            apps[app_name] = apps.get(app_name, 0) + 1

        top_app = max(apps, key=apps.get) if apps else "-"

        self.app.lbl_conv_summary.setText(
            f"Conversation — Flows: {rows} | Volume: {human_bytes(total_bytes, precision=2)} | Top app: {top_app}"
        )
        self.app.lbl_conv_summary.show()

    def update_showing(self):
        self.refresh_json_header_stats()

    def ensure_pair_loaded(self, src: str, dst: str):
        """Ensure at least one flow for (src,dst) exists in loaded flows; expand paging if needed."""
        flows = self.app.flow_controller.ensure_pair_loaded(src, dst)
        self.app.model.set_flows(flows)
        self.update_loaded_label()
        self.update_load_more_enabled()
        self.update_showing()

    def scroll_to_flow_pair(self, src: str, dst: str):
        src_col = self._flow_column_index("src_ip")
        dst_col = self._flow_column_index("dst_ip")
        if src_col < 0 or dst_col < 0:
            return None, None

        for r_idx in range(self.app.proxy.rowCount()):
            idx0 = self.app.proxy.index(r_idx, src_col)
            src_ip = self.app.proxy.data(idx0, Qt.DisplayRole)
            dst_ip = self.app.proxy.data(self.app.proxy.index(r_idx, dst_col), Qt.DisplayRole)

            if (src_ip == src and dst_ip == dst) or (src_ip == dst and dst_ip == src):
                self.app.table.scrollTo(idx0, QTableView.PositionAtCenter)
                return idx0, r_idx

        return None, None

    def select_flow_pair(self, src: str, dst: str):
        self.app.table.clearSelection()

        idx0, r_idx = self.scroll_to_flow_pair(src, dst)
        if idx0 is None:
            return False

        self.app.table.setCurrentIndex(idx0)
        self.app.table.selectRow(r_idx)
        self.update_showing()
        return True
    
    def apply_filter_ip(self, ip: str):
        if not ip:
            return

        self.app.search.setText(ip)
        self.app.search.setFocus()

    def toggle_flows_expanded(self):
        self.app._flows_expanded = not self.app._flows_expanded

        if self.app._flows_expanded:
            self.app.details_panel.hide()
            self.app.btn_expand_flows.setText("Collapse Flows")
            self.app.splitter.setSizes([1400, 0])
        else:
            self.app.details_panel.show()
            self.app.btn_expand_flows.setText("Expand Flows")
            self.app.splitter.setSizes([920, 420])

    def copy_selected_cell_value(self):
        index = self.app.table.currentIndex()
        if not index.isValid():
            return

        value = self.app.proxy.data(index)
        if value is None:
            return

        self.app.copy_text(str(value))

    def copy_current_flow_multiline(self):
        if not self.app._current_flow:
            return

        flow = self.app._current_flow

        lines = [
            f"Source IP: {flow.get('src_ip', '')}",
            f"Source Port: {flow.get('src_port', '')}",
            f"Destination IP: {flow.get('dst_ip', '')}",
            f"Destination Port: {flow.get('dst_port', '')}",
            f"Protocol: {format_ip_proto(flow.get('protocol', ''))}",
            f"Application: {flow.get('application_name', '')}",
            f"Bytes: {human_bytes(flow.get('bidirectional_bytes', 0), precision=2)}",
            f"Duration(ms): {flow.get('bidirectional_duration_ms', '')}",
            f"SNI: {flow.get('requested_server_name', '')}",
        ]

        self.app.copy_text("\n".join(lines))

    def export_flows_table(self, export_format: str | None = None) -> None:
        flows, export_note = self._flows_for_export()
        if not flows:
            self.app._message_dialog("Export table", "No flows are loaded or visible.", width=420)
            return

        if export_format:
            export_table_dialog(
                self.app,
                "Flows",
                self.app.table,
                export_format,
                project_id=self.app.current_project_id,
                category="json",
                flows_override=flows,
                flow_columns=self.app.model.columns(),
            )
            if export_note:
                self.app._message_dialog("Export table", export_note, width=520)
            return

        popup_export_menu(
            self.app.btn_export_flows,
            {
                fmt: (lambda chosen=fmt: self.export_flows_table(chosen))
                for fmt, _ in (
                    ("csv", "Export CSV"),
                    ("xlsx", "Export Excel"),
                    ("html", "Export HTML"),
                )
            },
        )

    def _flows_for_export(self) -> tuple[list[dict], str]:
        flows: list[dict] = []
        seen: set[int] = set()
        for row_idx in range(self.app.proxy.rowCount()):
            source_index = self.app.proxy.mapToSource(self.app.proxy.index(row_idx, 0))
            source_row = source_index.row()
            if source_row < 0 or source_row in seen:
                continue
            seen.add(source_row)
            flow = self.app.flow_controller.get_flow_by_row(source_row)
            if isinstance(flow, dict):
                flows.append(flow)

        note = ""
        total = self.app.flow_controller.get_total_count()
        loaded = self.app.flow_controller.get_loaded_count()
        if flows and total > loaded:
            note = (
                f"Exported {len(flows):,} visible flow(s). "
                f"The full period contains {total:,} flows but only {loaded:,} are loaded in the table. "
                "Use Load more before export if you need the entire period."
            )
        return flows, note

    def generate_ai_summary(self):
        flows = self.app.flow_controller.get_all()

        if not flows:
            self.app._message_dialog("AI Assistant", "Load a dataset first.", width=400)
            return

        if self.app.ai_task_controller.is_busy():
            self.app._message_dialog("AI Assistant", "AI summary is already running.", width=420)
            return

        self.app.btn_ai_summary.setEnabled(False)
        if hasattr(self.app, "txt_ai_hub"):
            self.app.txt_ai_hub.setPlainText("Generating AI summary...")
        self.app.btn_ai_summary.setText("Generating...")

        dataset_path = str(self.app.current_folder) if self.app.current_folder else ""

        controller = getattr(self.app, "dataset_controller", None)
        active_day = str(getattr(controller, "_json_active_day", "") or "") if controller is not None else ""
        period_mode = str(getattr(controller, "_json_period_granularity", "day") or "day") if controller is not None else "day"
        from core.evidence_policy import format_period_day_label

        period_label = format_period_day_label(active_day) if active_day else ""

        worker = AITextWorker(
            self.app.ai_service.generate_dataset_summary,
            list(flows),
            self.app.current_project_name,
            dataset_path,
            period_label=period_label,
            period_mode=period_mode,
        )
        self.app.ai_task_controller.start("summary", worker)

    def explain_selected_flow(self):
        if not self.app._current_flow:
            self.app._message_dialog("AI Assistant", "Select a flow first.", width=400)
            return

        if self.app.ai_task_controller.is_busy():
            self.app._message_dialog("AI Assistant", "Another AI task is already running.", width=430)
            return

        self.app.btn_ai_explain.setEnabled(False)
        if hasattr(self.app, "txt_ai_hub"):
            self.app.txt_ai_hub.setPlainText("Generating AI flow explanation...")

        worker = AITextWorker(
            self.app.ai_service.explain_flow,
            dict(self.app._current_flow),
        )
        self.app.ai_task_controller.start("flow", worker)

    def _flow_column_index(self, key: str) -> int:
        model = getattr(self.app, "model", None)
        if model is None or not hasattr(model, "column_index"):
            return -1
        return int(model.column_index(key))

    def _available_flow_columns(self) -> list[str]:
        flows = self.app.flow_controller.get_all()
        return available_flow_columns(list(flows))

    def update_flows_view_controls(self) -> None:
        combo = getattr(self.app, "cmb_flows_view", None)
        customize = getattr(self.app, "btn_customize_flows", None)
        if combo is None or customize is None:
            return
        has_flows = bool(self.app.flow_controller.get_all())
        combo.setEnabled(has_flows)
        mode = str(combo.currentData() or "default")
        customize.setVisible(has_flows and mode == "custom")

    def on_flows_view_mode_changed(self, index: int) -> None:
        combo = getattr(self.app, "cmb_flows_view", None)
        if combo is None or index < 0:
            return

        mode = str(combo.itemData(index) or "default")
        if mode == "all":
            columns = self._available_flow_columns()
            self.app.model.set_columns(columns)
        elif mode == "custom":
            columns = list(self._flows_custom_columns or DEFAULT_FLOW_COLUMNS)
            self.app.model.set_columns(columns)
        else:
            self.app.model.set_columns(list(DEFAULT_FLOW_COLUMNS))
        self.update_flows_view_controls()

    def open_flows_customize_dialog(self) -> None:
        flows = self.app.flow_controller.get_all()
        if not flows:
            self.app._message_dialog("Flows", "Load flows first.", width=420)
            return

        dlg = ColumnPickerDialog(
            current_columns=self.app.model.columns(),
            all_columns=self._available_flow_columns(),
            parent=self.app,
        )
        if not dlg.exec():
            return

        selected = dlg.get_selected_columns()
        if not selected:
            return

        self._flows_custom_columns = list(selected)
        self.app.model.set_columns(selected)
        combo = getattr(self.app, "cmb_flows_view", None)
        if combo is not None:
            custom_index = combo.findData("custom")
            if custom_index >= 0:
                combo.blockSignals(True)
                combo.setCurrentIndex(custom_index)
                combo.blockSignals(False)
        self.update_flows_view_controls()

