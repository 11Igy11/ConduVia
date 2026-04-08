from core.protocols import format_ip_proto

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
        self.app.update_showing()

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