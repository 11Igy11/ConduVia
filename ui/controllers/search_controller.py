class SearchController:
    def __init__(self, parent_app):
        self.parent_app = parent_app

    def schedule_search_filter(self, *_):
        self.parent_app._search_timer.start(300)

    def apply_search_filter(self):
        text = self.parent_app.search.text()
        self.parent_app.proxy.set_filter_text(text)
        self.parent_app.explore_ui_controller.update_showing()