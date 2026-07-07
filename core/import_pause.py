"""Thread-safe pause gate for long-running import workers."""

from __future__ import annotations

import threading


class ImportPauseGate:
    """Cooperative pause between import steps (JSON files, PCAP files, phases)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._paused = False
        self._aborted = False

    def pause(self) -> None:
        with self._lock:
            self._paused = True

    def resume(self) -> None:
        with self._cond:
            self._paused = False
            self._cond.notify_all()

    def is_paused(self) -> bool:
        with self._lock:
            return self._paused

    def is_aborted(self) -> bool:
        with self._lock:
            return self._aborted

    def wait_if_paused(self) -> bool:
        """Block until resumed. Returns False when aborted."""
        with self._cond:
            while self._paused and not self._aborted:
                self._cond.wait(timeout=0.25)
            return not self._aborted

    def abort(self) -> None:
        with self._cond:
            self._aborted = True
            self._paused = False
            self._cond.notify_all()

    def reset(self) -> None:
        with self._cond:
            self._paused = False
            self._aborted = False
