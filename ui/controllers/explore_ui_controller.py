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