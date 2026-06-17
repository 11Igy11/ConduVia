from __future__ import annotations

"""Shared rules and UI copy for JSON/PCAP evidence handling."""

MAX_INTERACTIVE_EVIDENCE_FILES = 100
MAX_INTERACTIVE_EVIDENCE_BYTES = 512 * 1024 * 1024
MAX_INTERACTIVE_PCAP_FILES_PER_OPEN = 10

PERIOD_LABEL = "Period:"


def should_open_interactively(file_count: int, byte_count: int) -> bool:
    return (
        int(file_count or 0) <= MAX_INTERACTIVE_EVIDENCE_FILES
        and int(byte_count or 0) <= MAX_INTERACTIVE_EVIDENCE_BYTES
    )


def should_batch_pcap_files(file_count: int, byte_count: int) -> bool:
    count = int(file_count or 0)
    if count <= 0:
        return False
    if not should_open_interactively(count, byte_count):
        return True
    return count > MAX_INTERACTIVE_PCAP_FILES_PER_OPEN


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
