"""Background workers for dataset import, scan, and behavior indexing."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot

from core.case_ingest import scan_case_source
from core.db import mark_ingest_items_batch, upsert_ingest_items
from core.import_pause import ImportPauseGate
from core.loader import load_folder_recursive, load_json_file
from core.parser import extract_dataset_meta
from core.import_pause import ImportPauseGate
from core.project_behavior_index import build_project_behavior_index


class DatasetLoadWorker(QObject):
    finished = Signal(object)
    error = Signal(str, str)
    progress = Signal(int, int, str)

    def __init__(
        self,
        *,
        mode: str,
        path: str,
        previous_path: str = "",
        project_id: int | None = None,
        files: list[str] | None = None,
        pause_gate: ImportPauseGate | None = None,
    ):
        super().__init__()
        self.mode = mode
        self.path = path
        self.previous_path = previous_path
        self.project_id = project_id
        self.files = files or []
        self.pause_gate = pause_gate

    def _wait_if_paused(self) -> bool:
        if self.pause_gate is None:
            return True
        return self.pause_gate.wait_if_paused()

    @Slot()
    def run(self):
        try:
            if not self._wait_if_paused():
                raise RuntimeError("JSON load paused and stopped.")
            previous_flows = self._load_previous_flows()

            if self.mode == "folder":
                files, flows = load_folder_recursive(self.path, debug=False)
                dataset_label = f"Dataset: {self.path}"
                stats_label = f"JSON files: {len(files)} | Total flow records: {len(flows)}"
                current_folder = self.path
            elif self.mode == "files":
                files = [Path(path) for path in self.files if str(path or "").strip()]
                flows = []
                total = len(files)
                if total:
                    self.progress.emit(0, total, "Starting...")
                for idx, fp in enumerate(files):
                    if not self._wait_if_paused():
                        break
                    flows.extend(load_json_file(fp, debug=False))
                    self.progress.emit(idx + 1, total, fp.name)
                dataset_label = f"Dataset selection: {self.path}"
                stats_label = f"JSON files: {len(files)} | Total flow records: {len(flows)}"
                current_folder = self.path
            elif self.mode == "file":
                fp = Path(self.path)
                flows = load_json_file(fp, debug=False)
                files = [fp]
                dataset_label = f"Dataset file: {self.path}"
                stats_label = f"JSON files: 1 | Total flow records: {len(flows)}"
                current_folder = str(fp.parent)
            else:
                raise ValueError(f"Unsupported dataset mode: {self.mode}")

            meta = self._extract_meta(files)
            compare_result = self._build_compare(flows, previous_flows)

            self.finished.emit({
                "mode": self.mode,
                "path": self.path,
                "files": files,
                "flows": flows,
                "compare_result": compare_result,
                "dataset_label": dataset_label,
                "stats_label": stats_label,
                "current_folder": current_folder,
                "project_id": self.project_id,
                "meta": meta,
            })
        except Exception as e:
            title = "Failed to load dataset folder." if self.mode in {"folder", "files"} else "Failed to load JSON file."
            self.error.emit(title, str(e))

    def _load_previous_flows(self) -> list[dict]:
        if not self.previous_path:
            return []

        try:
            prev = Path(self.previous_path)
            if prev.is_file():
                return load_json_file(prev, debug=False)
            if prev.is_dir():
                return []
        except Exception:
            return []

        return []

    def _extract_meta(self, files: list[Path]) -> dict:
        if not files:
            return {}

        try:
            return extract_dataset_meta(files[0])
        except Exception:
            return {}

    def _build_compare(self, flows: list[dict], previous_flows: list[dict]) -> dict | None:
        if not previous_flows:
            return None

        from core.compare import compare_flows, summarize_new_flows

        compare_result = compare_flows(flows, previous_flows)
        compare_result["summary_new"] = summarize_new_flows(compare_result["new"])
        return compare_result


class BehaviorIndexWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, project_id: int):
        super().__init__()
        self.project_id = project_id

    @Slot()
    def run(self):
        try:
            self.finished.emit(build_project_behavior_index(self.project_id))
        except Exception as exc:
            self.error.emit(str(exc))


class CaseScanWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, folder: str, *, pause_gate: ImportPauseGate | None = None):
        super().__init__()
        self.folder = folder
        self.pause_gate = pause_gate

    def _wait_if_paused(self) -> bool:
        if self.pause_gate is None:
            return True
        return self.pause_gate.wait_if_paused()

    @Slot()
    def run(self):
        try:
            if not self._wait_if_paused():
                raise RuntimeError("Folder scan paused and stopped.")
            self.finished.emit(scan_case_source(self.folder))
        except Exception as exc:
            self.error.emit(str(exc))


class FolderIngestWorker(QObject):
    finished = Signal(object)
    error = Signal(str)

    def __init__(
        self,
        project_id: int,
        folder: str,
        scan,
        *,
        pause_gate: ImportPauseGate | None = None,
    ):
        super().__init__()
        self.project_id = project_id
        self.folder = folder
        self.scan = scan
        self.pause_gate = pause_gate

    def _wait_if_paused(self) -> bool:
        if self.pause_gate is None:
            return True
        return self.pause_gate.wait_if_paused()

    @Slot()
    def run(self):
        try:
            if not self._wait_if_paused():
                raise RuntimeError("Evidence indexing paused and stopped.")
            json_files = list(self.scan.json_files or [])
            pcap_files = list(self.scan.pcap_files or [])

            if json_files:
                upsert_ingest_items(
                    self.project_id,
                    self.folder,
                    (
                        {
                            "file_path": str(item.path),
                            "file_name": item.path.name,
                            "file_type": "json",
                            "file_size": item.size,
                            "observed_date": item.observed_date,
                        }
                        for item in json_files
                    ),
                )
                mark_ingest_items_batch(
                    self.project_id,
                    [str(item.path) for item in json_files],
                    "done",
                )

            if pcap_files:
                upsert_ingest_items(
                    self.project_id,
                    self.folder,
                    (
                        {
                            "file_path": str(item.path),
                            "file_name": item.path.name,
                            "file_type": item.kind,
                            "file_size": item.size,
                            "observed_date": item.observed_date,
                        }
                        for item in pcap_files
                    ),
                )

            self.finished.emit(self.scan)
        except Exception as exc:
            self.error.emit(str(exc))
