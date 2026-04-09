from core.protocols import format_ip_proto
from PySide6.QtCore import QThread
from PySide6.QtWidgets import QApplication
from ui.explore_widgets import AITextWorker
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTableView

class ExploreUIController:
    def __init__(self, app):
        self.app = app

    def on_page_size_changed(self, txt: str):
        try:
            self.app.PAGE_SIZE = max(250, int(txt))
        except Exception:
            self.app.PAGE_SIZE = 2000

        self.app.flow_controller.page_size = self.app.PAGE_SIZE
        self.update_loaded_label()
        self.update_load_more_enabled()

    def update_loaded_label(self):
        total = self.app.flow_controller.get_total_count()
        loaded = self.app.flow_controller.get_loaded_count()
        if total:
            self.app.lbl_loaded.setText(f"Loaded: {loaded} / {total}")
        else:
            self.app.lbl_loaded.setText("")

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
        self.app.d_bytes.setText(str(flow.get("bidirectional_bytes", "")))
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

        for r in range(rows):
            idx_bytes = self.app.proxy.index(r, 6)
            idx_app = self.app.proxy.index(r, 5)

            b = self.app.proxy.data(idx_bytes, Qt.DisplayRole)
            app = self.app.proxy.data(idx_app, Qt.DisplayRole) or ""

            try:
                total_bytes += int(b)
            except Exception:
                pass

            apps[app] = apps.get(app, 0) + 1

        top_app = max(apps, key=apps.get) if apps else "-"

        self.app.lbl_conv_summary.setText(
            f"Conversation — Flows: {rows} | Bytes: {total_bytes:,} | Top app: {top_app}"
        )
        self.app.lbl_conv_summary.show()

    def update_showing(self):
        total = self.app.flow_controller.get_loaded_count()
        shown = self.app.proxy.rowCount()

        if total:
            self.app.lbl_showing.setText(f"Showing: {shown} / {total} (loaded)")
        else:
            self.app.lbl_showing.setText("")

    def ensure_pair_loaded(self, src: str, dst: str):
        """Ensure at least one flow for (src,dst) exists in loaded flows; expand paging if needed."""
        flows = self.app.flow_controller.ensure_pair_loaded(src, dst)
        self.app.model.set_flows(flows)
        self.update_loaded_label()
        self.update_load_more_enabled()
        self.update_showing()

    def scroll_to_flow_pair(self, src: str, dst: str):
        for r_idx in range(self.app.proxy.rowCount()):
            idx0 = self.app.proxy.index(r_idx, 0)
            src_ip = self.app.proxy.data(idx0, Qt.DisplayRole)
            dst_ip = self.app.proxy.data(self.app.proxy.index(r_idx, 2), Qt.DisplayRole)

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
            f"Bytes: {flow.get('bidirectional_bytes', '')}",
            f"Duration(ms): {flow.get('bidirectional_duration_ms', '')}",
            f"SNI: {flow.get('requested_server_name', '')}",
        ]

        self.app.copy_text("\n".join(lines))

    def generate_ai_summary(self):
        flows = self.app.flow_controller.get_all()

        if not flows:
            self.app._message_dialog("AI Assistant", "Load a dataset first.", width=400)
            return

        if self.app._ai_thread is not None:
            self.app._message_dialog("AI Assistant", "AI summary is already running.", width=420)
            return

        self.app.btn_ai_summary.setEnabled(False)
        self.app.txt_ai_summary.setPlainText("Generating AI summary...")
        self.app.btn_ai_summary.setText("Generating...")
        QApplication.processEvents()

        dataset_path = str(self.app.current_folder) if self.app.current_folder else ""

        self.app._ai_mode = "summary"
        self.app._ai_thread = QThread()
        self.app._ai_worker = AITextWorker(
            self.app.ai_service.generate_dataset_summary,
            list(flows),
            self.app.current_project_name,
            dataset_path,
        )

        self.app._ai_worker.moveToThread(self.app._ai_thread)
        self.app._ai_thread.started.connect(self.app._ai_worker.run)
        self.app._ai_worker.finished.connect(self.app.on_ai_task_finished)
        self.app._ai_worker.error.connect(self.app.on_ai_task_error)

        self.app._ai_worker.finished.connect(self.app._ai_thread.quit)
        self.app._ai_worker.error.connect(self.app._ai_thread.quit)

        self.app._ai_thread.finished.connect(self.app._cleanup_ai_thread)

        self.app._ai_thread.start()

    def explain_selected_flow(self):
        if not self.app._current_flow:
            self.app._message_dialog("AI Assistant", "Select a flow first.", width=400)
            return

        if self.app._ai_thread is not None:
            self.app._message_dialog("AI Assistant", "Another AI task is already running.", width=430)
            return

        self.app._ai_mode = "flow"
        self.app.btn_ai_explain.setEnabled(False)
        self.app.txt_ai_summary.setPlainText("Generating AI flow explanation...")
        self.app.tabs.setCurrentIndex(0)

        self.app._ai_thread = QThread()
        self.app._ai_worker = AITextWorker(
            self.app.ai_service.explain_flow,
            dict(self.app._current_flow),
        )

        self.app._ai_worker.moveToThread(self.app._ai_thread)
        self.app._ai_thread.started.connect(self.app._ai_worker.run)
        self.app._ai_worker.finished.connect(self.app.on_ai_task_finished)
        self.app._ai_worker.error.connect(self.app.on_ai_task_error)

        self.app._ai_worker.finished.connect(self.app._ai_thread.quit)
        self.app._ai_worker.error.connect(self.app._ai_thread.quit)

        self.app._ai_thread.finished.connect(self.app._cleanup_ai_thread)

        self.app._ai_thread.start()

    