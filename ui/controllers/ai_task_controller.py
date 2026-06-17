from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, QThread, Slot

from ui.explore_widgets import AITextWorker
from ui.thread_utils import stop_qthread

if TYPE_CHECKING:
    from ui.app import App


class AiTaskController(QObject):
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app

    def is_busy(self) -> bool:
        return self.app._ai_thread is not None

    def start(self, mode: str, worker: AITextWorker) -> bool:
        if self.is_busy():
            return False

        app = self.app
        app._ai_mode = mode
        app._ai_thread = QThread(app)
        app._ai_worker = worker
        app._ai_worker.moveToThread(app._ai_thread)
        app._ai_thread.started.connect(app._ai_worker.run)
        app._ai_worker.finished.connect(self.on_finished)
        app._ai_worker.error.connect(self.on_error)
        app._ai_worker.finished.connect(app._ai_thread.quit)
        app._ai_worker.error.connect(app._ai_thread.quit)
        app._ai_worker.finished.connect(app._ai_worker.deleteLater)
        app._ai_worker.error.connect(app._ai_worker.deleteLater)
        app._ai_thread.finished.connect(self.cleanup)
        app._ai_thread.start()
        return True

    @Slot(str)
    def on_finished(self, result: str) -> None:
        app = self.app
        app.txt_ai_summary.setPlainText(result)
        title = {
            "summary": "JSON Dataset Summary",
            "flow": "Flow Explanation",
            "finding": "Finding Explanation",
        }.get(app._ai_mode or "", "AI Summary")
        app.publish_ai_output("JSON", title, result)
        project_id = getattr(app, "current_project_id", None)
        if project_id is not None and (result or "").strip() and app._ai_mode in {"summary", "flow", "finding"}:
            try:
                from core.db import add_activity

                add_activity(int(project_id), "ai_summary_generated", title)
                if hasattr(app, "notes_controller"):
                    app.notes_controller.refresh_activity_ui_for_project(int(project_id))
            except Exception:
                pass
        self._restore_mode_ui()

    @Slot(str)
    def on_error(self, message: str) -> None:
        self.app.txt_ai_summary.setPlainText(f"AI error: {message}")
        self._restore_mode_ui()

    @Slot()
    def cleanup(self) -> None:
        app = self.app
        stop_qthread(app._ai_thread, wait_ms=500)
        app._ai_worker = None
        app._ai_thread = None
        app._ai_mode = None

    def shutdown(self, wait_ms: int = 5000) -> None:
        app = self.app
        stop_qthread(app._ai_thread, wait_ms=max(500, wait_ms))
        app._ai_worker = None
        app._ai_thread = None
        app._ai_mode = None

    def _restore_mode_ui(self) -> None:
        app = self.app
        if app._ai_mode == "summary":
            app.btn_ai_summary.setEnabled(True)
            app.btn_ai_summary.setText("Generate AI Summary")
        elif app._ai_mode == "flow":
            app.btn_ai_explain.setEnabled(True)
        elif app._ai_mode == "finding":
            app.btn_finding_ai.setEnabled(True)
