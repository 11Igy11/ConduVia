"""Shared QObject worker + QThread lifecycle helpers."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QObject, QThread, Qt

from ui.thread_utils import stop_qthread


class WorkerRunner(QObject):
    """Run a worker object on a background QThread with standard wiring."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: QObject | None = None

    @property
    def thread(self) -> QThread | None:
        return self._thread

    @property
    def worker(self) -> QObject | None:
        return self._worker

    def is_running(self) -> bool:
        return self._thread is not None

    def start(
        self,
        worker: QObject,
        *,
        thread_parent: QObject | None = None,
        finished_slot: Callable[[str], None] | None = None,
        error_slot: Callable[[str], None] | None = None,
        cleanup_slot: Callable[[], None] | None = None,
        connection_type: Qt.ConnectionType = Qt.QueuedConnection,
    ) -> bool:
        if self.is_running():
            return False

        parent = thread_parent or self.parent()
        if parent is None:
            parent = self

        self._worker = worker
        self._thread = QThread(parent)
        worker.moveToThread(self._thread)
        self._thread.started.connect(worker.run)  # type: ignore[attr-defined]
        if finished_slot is not None:
            worker.finished.connect(finished_slot, connection_type)  # type: ignore[attr-defined]
        if error_slot is not None:
            worker.error.connect(error_slot, connection_type)  # type: ignore[attr-defined]
        worker.finished.connect(self._thread.quit)  # type: ignore[attr-defined]
        worker.error.connect(self._thread.quit)  # type: ignore[attr-defined]
        worker.finished.connect(worker.deleteLater)  # type: ignore[attr-defined]
        worker.error.connect(worker.deleteLater)  # type: ignore[attr-defined]
        if cleanup_slot is not None:
            self._thread.finished.connect(cleanup_slot)
        self._thread.finished.connect(self._clear_refs)
        self._thread.start()
        return True

    def stop(self, wait_ms: int = 5000) -> None:
        stop_qthread(self._thread, wait_ms=wait_ms)
        self._clear_refs()

    def _clear_refs(self) -> None:
        self._thread = None
        self._worker = None
