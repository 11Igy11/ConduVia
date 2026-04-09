from core.db import get_project_notes, set_project_notes, list_activity


class NotesController:
    def __init__(self):
        pass

    # ---------- Notes ----------
    def load_notes(self, project_id: int | None) -> str:
        if project_id is None:
            return ""
        return get_project_notes(project_id) or ""

    def save_notes(self, project_id: int | None, text: str) -> None:
        if project_id is None:
            return
        set_project_notes(project_id, text or "")

    # ---------- Activity ----------
    def load_activity(self, project_id: int | None, limit: int = 200):
        if project_id is None:
            return []
        return list_activity(project_id, limit=limit)