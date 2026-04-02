from core.db import list_findings


class FindingsController:
    def __init__(self):
        self.rows = []

    # ---------- load ----------
    def load_rows(self, project_id: int):
        if project_id is None:
            self.rows = []
            return []

        self.rows = list(list_findings(project_id, limit=500))
        return self.rows

    # ---------- filter + sort ----------
    def get_filtered_rows(self, status_sel, search, tagq, findings_page):
        search = (search or "").strip().lower()
        tagq = (tagq or "").strip().lower()
        status_sel = (status_sel or "All").strip()

        rows = [
            r for r in self.rows
            if findings_page.matches_filters(r, status_sel, search, tagq)
        ]

        rows = findings_page.sort_rows(rows, findings_page.cmb_find_sort.currentText())
        return rows