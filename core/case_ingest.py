from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

JSON_SUFFIXES = {".json"}
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
SKIP_DIR_NAMES = {"@eadir", "@tmp", "$recycle.bin", "system volume information"}

_FULL_DATE_RE = re.compile(r"(20\d{2})([01]\d)([0-3]\d)")
_YYMMDD_RE = re.compile(r"(?<!\d)(\d{2})([01]\d)([0-3]\d)(?!\d)")


@dataclass(frozen=True)
class EvidenceFile:
    path: Path
    kind: str
    size: int
    observed_date: str = ""


@dataclass(frozen=True)
class CaseIngestScan:
    root: Path
    json_files: tuple[EvidenceFile, ...]
    pcap_files: tuple[EvidenceFile, ...]
    skipped_dirs: int = 0

    @property
    def file_count(self) -> int:
        return len(self.json_files) + len(self.pcap_files)

    @property
    def total_size(self) -> int:
        return sum(item.size for item in self.json_files) + sum(item.size for item in self.pcap_files)

    @property
    def json_size(self) -> int:
        return sum(item.size for item in self.json_files)

    @property
    def pcap_size(self) -> int:
        return sum(item.size for item in self.pcap_files)

    @property
    def first_date(self) -> str:
        dates = [item.observed_date for item in self.files if item.observed_date]
        return min(dates) if dates else ""

    @property
    def last_date(self) -> str:
        dates = [item.observed_date for item in self.files if item.observed_date]
        return max(dates) if dates else ""

    @property
    def files(self) -> tuple[EvidenceFile, ...]:
        return tuple(sorted(
            (*self.json_files, *self.pcap_files),
            key=lambda item: (item.observed_date or "9999-99-99", str(item.path).casefold()),
        ))


def scan_case_source(root: str | Path) -> CaseIngestScan:
    """Scan a folder, disk root or optical media root for ViaNyquist evidence files.

    The scan intentionally reads directory metadata only. It does not parse JSON
    content and it does not open PCAP payloads, so it is suitable as the first
    pass over very large evidence media.
    """
    root_path = Path(root)
    if not root_path.exists() or not root_path.is_dir():
        raise FileNotFoundError(f"Folder not found: {root_path}")

    json_files: list[EvidenceFile] = []
    pcap_files: list[EvidenceFile] = []
    skipped_dirs = 0

    stack = [root_path]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            skipped_dirs += 1
            continue

        dirs: list[Path] = []
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.strip().casefold() in SKIP_DIR_NAMES:
                        skipped_dirs += 1
                        continue
                    dirs.append(Path(entry.path))
                    continue

                if not entry.is_file(follow_symlinks=False):
                    continue

                path = Path(entry.path)
                suffix = path.suffix.casefold()
                if suffix not in JSON_SUFFIXES and suffix not in PCAP_SUFFIXES:
                    continue

                try:
                    size = int(entry.stat(follow_symlinks=False).st_size)
                except OSError:
                    size = 0

                evidence = EvidenceFile(
                    path=path,
                    kind="json" if suffix in JSON_SUFFIXES else "pcap",
                    size=size,
                    observed_date=_extract_observed_date(path, root_path),
                )
                if suffix in JSON_SUFFIXES:
                    json_files.append(evidence)
                else:
                    pcap_files.append(evidence)
            except OSError:
                continue

        stack.extend(sorted(dirs, key=lambda item: item.name.casefold(), reverse=True))

    return CaseIngestScan(
        root=root_path,
        json_files=tuple(_sort_evidence(json_files)),
        pcap_files=tuple(_sort_evidence(pcap_files)),
        skipped_dirs=skipped_dirs,
    )


def evidence_paths(files: Iterable[EvidenceFile]) -> list[str]:
    return [str(item.path) for item in files]


def group_evidence_by_date(files: Iterable[EvidenceFile]) -> dict[str, list[EvidenceFile]]:
    groups: dict[str, list[EvidenceFile]] = {}
    for item in files:
        key = item.observed_date or "undated"
        groups.setdefault(key, []).append(item)

    return {
        date: _sort_evidence(items)
        for date, items in sorted(groups.items(), key=lambda pair: (pair[0] == "undated", pair[0]))
    }


def filter_case_scan(
    scan: CaseIngestScan,
    *,
    start_date: str = "",
    end_date: str = "",
    include_undated: bool = False,
) -> CaseIngestScan:
    """Return a scan narrowed to a date range.

    Dates use ISO format (YYYY-MM-DD). Files without detected dates are included
    only when requested so a narrow period import does not accidentally pull a
    large unknown bucket into the case.
    """
    start = (start_date or "").strip()
    end = (end_date or "").strip()

    def keep(item: EvidenceFile) -> bool:
        observed = (item.observed_date or "").strip()
        if not observed:
            return include_undated
        if start and observed < start:
            return False
        if end and observed > end:
            return False
        return True

    return CaseIngestScan(
        root=scan.root,
        json_files=tuple(item for item in scan.json_files if keep(item)),
        pcap_files=tuple(item for item in scan.pcap_files if keep(item)),
        skipped_dirs=scan.skipped_dirs,
    )


def _sort_evidence(items: list[EvidenceFile]) -> list[EvidenceFile]:
    return sorted(items, key=lambda item: (item.observed_date or "9999-99-99", str(item.path).casefold()))


def _extract_observed_date(path: Path, root: Path) -> str:
    text_parts = [path.name]
    try:
        text_parts.extend(part for part in path.relative_to(root).parts[:-1])
    except Exception:
        text_parts.extend(path.parts)

    for text in text_parts:
        match = _FULL_DATE_RE.search(text)
        if match:
            return _format_date(match.group(1), match.group(2), match.group(3))

    for text in text_parts:
        match = _YYMMDD_RE.search(text)
        if not match:
            continue
        yy = int(match.group(1))
        year = 2000 + yy
        return _format_date(str(year), match.group(2), match.group(3))

    return ""


def _format_date(year: str, month: str, day: str) -> str:
    try:
        y = int(year)
        m = int(month)
        d = int(day)
        if 2000 <= y <= 2099 and 1 <= m <= 12 and 1 <= d <= 31:
            return f"{y:04d}-{m:02d}-{d:02d}"
    except Exception:
        return ""
    return ""
