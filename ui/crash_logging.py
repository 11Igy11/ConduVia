from __future__ import annotations

import sys
import traceback
from datetime import datetime
from pathlib import Path


class _TeeTextIO:
    """Write faulthandler / crash output to every configured log path."""

    def __init__(self, handles: list):
        self._handles = handles

    def write(self, data: str) -> int:
        if not data:
            return 0
        for handle in self._handles:
            try:
                handle.write(data)
                handle.flush()
            except Exception:
                continue
        return len(data)

    def flush(self) -> None:
        for handle in self._handles:
            try:
                handle.flush()
            except Exception:
                continue

    def fileno(self) -> int:
        if self._handles:
            return self._handles[0].fileno()
        raise OSError("no log handles")


def crash_log_paths() -> list[Path]:
    roots: list[Path] = []
    try:
        roots.append(Path(__file__).resolve().parent.parent / "via_nyquist_crash.log")
    except Exception:
        pass
    try:
        roots.append(Path.home() / "Desktop" / "via_nyquist_crash.log")
    except Exception:
        pass
    try:
        roots.append(Path.home() / "via_nyquist_crash.log")
    except Exception:
        pass
    unique: list[Path] = []
    seen: set[str] = set()
    for path in roots:
        key = str(path).casefold()
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _open_crash_log_handles() -> list:
    handles = []
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for path in crash_log_paths():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle = path.open("a", encoding="utf-8")
            handle.write(f"\n--- ViaNyquist session {stamp} ---\n")
            handle.flush()
            handles.append(handle)
        except Exception:
            continue
    return handles


def write_crash_log(exc_type, exc, tb) -> list[Path]:
    written: list[Path] = []
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = f"\n--- ViaNyquist crash {stamp} ---\n"
    body_parts: list[str] = [header]
    try:
        if tb is not None:
            body_parts.append("".join(traceback.format_exception(exc_type, exc, tb)))
        else:
            body_parts.append(f"{getattr(exc_type, '__name__', exc_type)}: {exc!r}\n")
    except Exception:
        body_parts.append(f"{getattr(exc_type, '__name__', exc_type)}: (traceback unavailable)\n")
    body = "".join(body_parts)

    for path in crash_log_paths():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(body)
            written.append(path)
        except Exception:
            continue
    return written


def install_crash_logging() -> None:
    import faulthandler

    handles = _open_crash_log_handles()
    if handles:
        faulthandler.enable(file=_TeeTextIO(handles), all_threads=True)
    else:
        faulthandler.enable()

    def _log_unhandled(exc_type, exc, tb):
        write_crash_log(exc_type, exc, tb)
        try:
            sys.__excepthook__(exc_type, exc, tb)
        except Exception:
            pass

    sys.excepthook = _log_unhandled
