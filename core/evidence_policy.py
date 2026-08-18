from __future__ import annotations

"""Shared rules and UI copy for JSON/PCAP evidence handling.

Selecting a JSON or PCAP Day/Month/Range always starts a background load.
MAX_INTERACTIVE_* only influences the default period after a large import
(Day vs Range), not whether a selected period can be opened.
"""

from pathlib import Path

MAX_INTERACTIVE_EVIDENCE_FILES = 100
MAX_INTERACTIVE_EVIDENCE_BYTES = 512 * 1024 * 1024

PERIOD_LABEL = "Period:"


def should_open_interactively(file_count: int, byte_count: int) -> bool:
    return (
        int(file_count or 0) <= MAX_INTERACTIVE_EVIDENCE_FILES
        and int(byte_count or 0) <= MAX_INTERACTIVE_EVIDENCE_BYTES
    )


def should_batch_pcap_files(file_count: int, byte_count: int = 0) -> bool:
    """True when more than one PCAP should be analyzed as a background job."""
    return int(file_count or 0) > 1


def evidence_byte_count(paths: list[str] | tuple[str, ...] | None) -> int:
    total = 0
    for path in paths or []:
        try:
            total += Path(path).stat().st_size
        except OSError:
            continue
    return total


def oversized_interactive_load_message(
    *,
    kind: str,
    file_count: int,
    byte_count: int = 0,
    period_label: str = "",
) -> tuple[str, str]:
    from core.formatters import human_bytes

    kind_upper = str(kind or "evidence").strip().upper() or "EVIDENCE"
    title = f"{kind_upper} period is too large to open interactively"
    size_text = f"{int(file_count or 0):,} files"
    if byte_count:
        size_text += f" ({human_bytes(int(byte_count), precision=2)})"
    period_text = f"Selected period: {period_label}. " if period_label else ""
    details = (
        f"{period_text}This selection has {size_text}, which exceeds the interactive limit "
        f"({MAX_INTERACTIVE_EVIDENCE_FILES:,} files or "
        f"{human_bytes(MAX_INTERACTIVE_EVIDENCE_BYTES, precision=0)}). "
        "The evidence stays indexed. Switch Period to Day to review one day at a time, "
        "or use Profile for the full-set summary."
    )
    return title, details


def period_view_caption(period_mode: str, period_label: str, flow_count: int) -> str:
    mode = str(period_mode or "day")
    if mode == "month":
        prefix = "Month aggregate"
    elif mode == "range":
        prefix = "Selected period"
    else:
        prefix = "Day view"
    label = str(period_label or "").strip() or "—"
    return f"{prefix}: {label} · {int(flow_count or 0):,} flows loaded"


def format_period_day_label(day: str) -> str:
    return _format_period_day_label_impl(str(day or "").strip(), _depth=0)


def _format_period_day_label_impl(text: str, *, _depth: int) -> str:
    if _depth > 8:
        return text
    if text == "undated":
        return "Undated"
    if text.startswith("range:"):
        from core.period_groups import parse_range_period_key

        start, end = parse_range_period_key(text)
        if start and end:
            left = _format_period_day_label_impl(start, _depth=_depth + 1)
            right = _format_period_day_label_impl(end, _depth=_depth + 1)
            return f"{left} – {right}"
    if len(text) == 10 and text[4] == "-" and text[7] == "-":
        return f"{text[8:10]}/{text[5:7]}/{text[:4]}"
    return text


def period_combo_label(day: str, file_count: int, *, kind: str = "files") -> str:
    return f"{format_period_day_label(day)} ({file_count:,} {kind})"


def indexed_source_message(*, json_files: int = 0, pcap_files: int = 0, batch_started: bool = False) -> str:
    parts: list[str] = []
    if json_files:
        parts.append(f"{json_files:,} JSON files indexed for this project")
    if pcap_files:
        text = f"{pcap_files:,} PCAP files indexed for this project"
        if batch_started:
            text += "; background analysis started on the PCAP page"
        parts.append(text)
    if not parts:
        return "Evidence indexed for this project."
    return ". ".join(parts) + ". Use the Period selector to review one day at a time."
