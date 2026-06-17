from __future__ import annotations

from PySide6.QtCore import QThread


def stop_qthread(thread: QThread | None, wait_ms: int = 5000) -> None:
    if thread is None:
        return
    try:
        if not thread.isRunning():
            return
        thread.quit()
        if wait_ms <= 0:
            wait_ms = 1
        if not thread.wait(wait_ms):
            thread.terminate()
            thread.wait(max(1000, min(wait_ms, 5000)))
    except RuntimeError:
        # C++ object already deleted.
        return


def stop_qthreads(*threads: QThread | None, wait_ms: int = 5000) -> None:
    for thread in threads:
        stop_qthread(thread, wait_ms=wait_ms)
