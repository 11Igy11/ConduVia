"""Background workers for PCAP analysis and batch ingest."""

from __future__ import annotations

import gc
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from core.db import (
    add_pcap_source,
    file_sha256,
    mark_ingest_item,
    mark_ingest_items_batch,
    save_pcap_period_summary,
)
from core.formatters import human_bytes
from core.import_pause import ImportPauseGate
from core.period_groups import is_range_period_key, period_group_label
from core.pcap_analyzer import (
    PcapSummary,
    analyze_pcap_files_isolated,
    analyze_pcap_isolated,
    analyze_timeout_for_path,
    build_investigator_view,
    merge_pcap_summaries_isolated,
)
from core.pcap_period import aggregate_hash_for_paths, capture_span_note, resolve_period_day


class PcapWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, path: str | list[str], *, label: str = ""):
        super().__init__()
        self.path = path
        self.label = label

    def run(self):
        try:
            if isinstance(self.path, list):
                if len(self.path) == 1:
                    self.finished.emit(analyze_pcap_isolated(self.path[0]))
                else:
                    self.finished.emit(analyze_pcap_files_isolated(self.path, label=self.label))
            else:
                self.finished.emit(analyze_pcap_isolated(self.path))
        except Exception as exc:
            self.error.emit(str(exc))


class PcapBatchWorker(QObject):
    progress = Signal(int, int, int, str)
    finished = Signal(object, int, int)

    def __init__(
        self,
        paths: list[str],
        *,
        project_id: int | None = None,
        auto_save: bool = False,
        day_groups: dict[str, list[str]] | None = None,
        pause_gate: ImportPauseGate | None = None,
    ):
        super().__init__()
        self.paths = [str(path) for path in paths if str(path or "").strip()]
        self.project_id = project_id
        self.auto_save = bool(auto_save)
        self.day_groups = {
            str(day): [str(path) for path in day_paths if str(path or "").strip()]
            for day, day_paths in (day_groups or {}).items()
            if str(day or "").strip() and day != "undated"
        }
        self.pause_gate = pause_gate
        self.stop_requested = False

    def _wait_if_paused(self) -> bool:
        if self.pause_gate is None:
            return True
        return self.pause_gate.wait_if_paused()

    def request_stop(self) -> None:
        self.stop_requested = True

    def run(self) -> None:
        processed = 0
        failed = 0
        last_summary = None

        jobs: list[tuple[str, list[str]]] = []
        if self.day_groups:
            for day, day_paths in sorted(self.day_groups.items(), key=lambda pair: pair[0]):
                jobs.append((day, day_paths))
        else:
            jobs.append(("", self.paths))

        total = sum(len(paths) for _day, paths in jobs)

        for period_day, day_paths in jobs:
            if self.stop_requested or not self._wait_if_paused():
                break
            if not day_paths:
                continue

            needs_merge = bool(period_day) or len(day_paths) > 1
            day_merged: PcapSummary | None = None

            for path in day_paths:
                if self.stop_requested or not self._wait_if_paused():
                    break

                current_name = Path(path).name
                self.progress.emit(processed, total, failed, current_name)
                try:
                    summary = analyze_pcap_isolated(
                        path,
                        timeout=analyze_timeout_for_path(path),
                    )
                    if needs_merge:
                        if day_merged is None:
                            day_merged = summary
                        else:
                            day_merged = merge_pcap_summaries_isolated(
                                [day_merged, summary],
                                timeout=max(analyze_timeout_for_path(path), 1800.0),
                            )
                            summary = None
                    else:
                        day_merged = summary
                    last_summary = day_merged
                    processed += 1
                except Exception as exc:
                    failed += 1
                    processed += 1
                    if self.project_id is not None:
                        try:
                            mark_ingest_item(self.project_id, path, "failed", str(exc))
                        except Exception:
                            pass
                finally:
                    gc.collect()
                self.progress.emit(processed, total, failed, current_name)

            if day_merged is None:
                continue

            if needs_merge:
                label = (
                    period_group_label(
                        period_day,
                        granularity="range" if is_range_period_key(period_day) else "day",
                        file_count=len(day_paths),
                        kind="PCAP",
                    )
                    if period_day
                    else f"{len(day_paths):,} PCAP files"
                )
                self.progress.emit(processed, total, failed, f"Merging {len(day_paths)} files…")
                try:
                    last_summary = day_merged
                    if self.auto_save and self.project_id is not None:
                        self.progress.emit(processed, total, failed, f"Saving {period_day or label}…")
                        self._save_period_summary(day_merged, period_day, day_paths, compact=True)
                except Exception as exc:
                    if self.project_id is not None:
                        for path in day_paths:
                            try:
                                mark_ingest_item(self.project_id, path, "failed", str(exc))
                            except Exception:
                                pass
            elif self.auto_save and self.project_id is not None:
                self._save_file_summary(day_merged, day_paths[0])

        self.finished.emit(last_summary, processed, failed)

    def _save_period_summary(self, summary: PcapSummary, period_day: str, source_paths: list[str], *, compact: bool = False) -> None:
        day = resolve_period_day(
            active_day=period_day,
            file_paths=source_paths,
            first_seen=summary.first_seen,
            last_seen=summary.last_seen,
        )
        digest = aggregate_hash_for_paths(source_paths)
        if compact:
            plain = (
                f"Saved PCAP period with {int(summary.packet_count or 0):,} packets "
                f"({human_bytes(int(summary.wire_bytes or 0), precision=2)})."
            )
        else:
            investigator = build_investigator_view(summary)
            plain = str(investigator.get("plain_summary") or "")
        span = capture_span_note(summary.first_seen, summary.last_seen, period_day=day)
        if span:
            plain = f"{plain}\n{span}"
        save_pcap_period_summary(
            self.project_id,
            period_day=day,
            file_path=summary.file_path or summary.file_name,
            file_sha256_value=digest,
            file_size=summary.file_size,
            file_name=summary.file_name,
            format=summary.format,
            packet_count=summary.packet_count,
            wire_bytes=summary.wire_bytes,
            first_seen=summary.first_seen,
            last_seen=summary.last_seen,
            duration_seconds=summary.duration_seconds,
            likely_device_ip=summary.likely_device_ip,
            summary_text=plain,
        )
        self._mark_paths_done(source_paths)

    def _save_file_summary(self, summary: PcapSummary, source_path: str) -> None:
        digest = file_sha256(source_path)
        day = resolve_period_day(
            file_paths=[source_path],
            first_seen=summary.first_seen,
            last_seen=summary.last_seen,
        )
        investigator = build_investigator_view(summary)
        add_pcap_source(
            self.project_id,
            file_path=source_path,
            file_name=summary.file_name,
            file_sha256_value=digest,
            file_size=summary.file_size,
            format=summary.format,
            packet_count=summary.packet_count,
            wire_bytes=summary.wire_bytes,
            first_seen=summary.first_seen,
            last_seen=summary.last_seen,
            duration_seconds=summary.duration_seconds,
            likely_device_ip=summary.likely_device_ip,
            summary_text=str(investigator.get("plain_summary") or ""),
            period_day=day,
        )
        mark_ingest_item(self.project_id, source_path, "done", "")

    def _mark_paths_done(self, source_paths: list[str]) -> None:
        if self.project_id is None:
            return
        mark_ingest_items_batch(self.project_id, source_paths, "done", "")
