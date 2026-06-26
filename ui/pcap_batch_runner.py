"""QThread lifecycle for PCAP batch analysis workers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from PySide6.QtCore import QObject, QThread, Qt

from ui.thread_utils import stop_qthread

if TYPE_CHECKING:
    from ui.workers.pcap_workers import PcapBatchWorker


class PcapBatchRunner(QObject):
    """Run PcapBatchWorker on a background QThread with standard wiring."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._thread: QThread | None = None
        self._worker: PcapBatchWorker | None = None
        self._faulthandler_cancel = None

    @property
    def worker(self) -> PcapBatchWorker | None:
        return self._worker

    def is_running(self) -> bool:
        return self._thread is not None

    def start(
        self,
        worker: PcapBatchWorker,
        *,
        thread_parent: QObject,
        progress_slot: Callable[[int, int, int, str], None],
        finished_slot: Callable[[object, int, int], None],
        cleanup_slot: Callable[[], None] | None = None,
        connection_type: Qt.ConnectionType = Qt.QueuedConnection,
    ) -> bool:
        if self.is_running():
            return False

        self._start_faulthandler_watch()
        self._worker = worker
        self._thread = QThread(thread_parent)
        worker.moveToThread(self._thread)
        self._thread.started.connect(worker.run)
        worker.progress.connect(progress_slot, connection_type)
        worker.finished.connect(finished_slot, connection_type)
        worker.finished.connect(self._thread.quit)
        worker.finished.connect(worker.deleteLater)

        def _cleanup() -> None:
            self._stop_faulthandler_watch()
            if cleanup_slot is not None:
                cleanup_slot()
            self._clear_refs()

        self._thread.finished.connect(_cleanup)
        self._thread.start()
        return True

    def request_stop(self) -> None:
        if self._worker is not None:
            self._worker.request_stop()

    def start_crash_watch(self) -> None:
        self._start_faulthandler_watch()

    def stop_crash_watch(self) -> None:
        self._stop_faulthandler_watch()

    def stop(self, wait_ms: int = 5000) -> None:
        self.request_stop()
        stop_qthread(self._thread, wait_ms=wait_ms)
        self._stop_faulthandler_watch()
        self._clear_refs()

    def _clear_refs(self) -> None:
        self._thread = None
        self._worker = None

    def _start_faulthandler_watch(self) -> None:
        import faulthandler

        from ui.crash_logging import _TeeTextIO, _open_crash_log_handles

        self._stop_faulthandler_watch()
        try:
            handles = _open_crash_log_handles()
            if not handles:
                return
            tee = _TeeTextIO(handles)
            self._faulthandler_cancel = faulthandler.dump_traceback_later(
                45,
                repeat=True,
                file=tee,
            )
        except Exception:
            pass

    def _stop_faulthandler_watch(self) -> None:
        cancel = self._faulthandler_cancel
        self._faulthandler_cancel = None
        if cancel is not None:
            try:
                cancel()
            except Exception:
                pass
