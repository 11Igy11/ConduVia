from __future__ import annotations

from PySide6.QtCore import QThread


def stop_qthread(thread: QThread | None, wait_ms: int = 5000) -> None:
    if thread is None:
        return
    if thread.isRunning():
        thread.quit()
        if not thread.wait(wait_ms):
            thread.terminate()
            thread.wait(1000)
