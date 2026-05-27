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
    if day == "undated":
        return "Undated"
    if len(day) == 10 and day[4] == "-" and day[7] == "-":
        return f"{day[8:10]}/{day[5:7]}/{day[:4]}"
    return str(day or "")


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
