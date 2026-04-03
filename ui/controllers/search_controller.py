class SearchController:
    def __init__(self, app):
        self.app = app

    def apply_search_filter(self):
        text = self.app.search.text()
        self.app.proxy.set_filter_text(text)
        self.app.update_showing()