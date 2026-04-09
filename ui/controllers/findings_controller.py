from core.db import list_findings, get_finding


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
    
    def prepare_render_rows(self, rows, status_emoji_fn):
        render_rows = []

        for r in rows:
            rr = dict(r)
            rr["status_emoji"] = status_emoji_fn(r["status"])
            render_rows.append(rr)

        return render_rows
    
    def get_selected_row(self, finding_id: int | None):
        if finding_id is None:
            return None, None

        row = get_finding(finding_id)
        if row is None:
            return finding_id, None

        return finding_id, row