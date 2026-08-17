"""Project activity audit trail (SQLite + optional workspace file log)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from core.db import add_activity, get_project


def append_project_workspace_log(project_id: int, line: str) -> None:
    project = get_project(project_id)
    if project is None:
        return
    base = str(getattr(project, "base_folder", "") or "").strip()
    if not base:
        return
    logs_dir = Path(base) / "logs"
    try:
        logs_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        path = logs_dir / "via_nyquist.log"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} | {line.rstrip()}\n")
    except Exception:
        return


def record_project_activity(
    project_id: int | None,
    event_type: str,
    message: str = "",
    *,
    file_log: bool = True,
) -> None:
    if project_id is None:
        return
    pid = int(project_id)
    event = (event_type or "").strip() or "event"
    msg = str(message or "")
    add_activity(pid, event, msg)
    if file_log:
        append_project_workspace_log(pid, f"{event} | {msg}")
