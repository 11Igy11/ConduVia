"""Pure helpers for PCAP batch progress UI (no Qt)."""

from __future__ import annotations


def batch_progress_ui_interval(total: int) -> float:
    count = max(0, int(total or 0))
    if count >= 1000:
        return 1.0
    if count >= 200:
        return 0.5
    if count >= 50:
        return 0.25
    return 0.15


def format_batch_status_text(
    *,
    queue_auto_process: bool,
    batch_running: bool,
    queue_length: int,
    batch_processed: int,
    batch_total: int,
    batch_failed: int,
    error_text: str = "",
    context_day: str = "",
    hide_individual_names: bool = False,
) -> str | None:
    """Return status line text, or None when the batch panel should stay hidden."""
    batch_total = int(batch_total or 0)
    batch_processed = int(batch_processed or 0)
    has_batch = bool(queue_length) or (
        batch_total > 0 and (batch_processed < batch_total or batch_running)
    )
    if not has_batch:
        return None

    if queue_auto_process or batch_running:
        remaining = max(0, batch_total - batch_processed)
    else:
        remaining = int(queue_length or 0)

    mode = "Auto batch" if queue_auto_process else "Manual queue"
    if not hide_individual_names and context_day:
        mode = f"{mode} | {context_day}"

    parts = [
        f"{mode}: {batch_processed:,} / {batch_total:,} processed",
        f"{remaining:,} remaining",
    ]
    if batch_failed:
        parts.append(f"{batch_failed:,} failed")
    if error_text:
        parts.append(f"last error: {error_text[:160]}")
    return " | ".join(parts)
