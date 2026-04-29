from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import QFileDialog

from core.analyzer import top_applications, top_dst_ips, top_protocols, top_src_ips
from core.db import add_dataset_load, get_project, list_recent_datasets, set_project_target
from core.loader import load_folder, load_json_file
from core.parser import extract_dataset_meta
from core.protocols import format_ip_proto


class DatasetLoadWorker(QObject):
    finished = Signal(object)
    error = Signal(str, str)

    def __init__(
        self,
        *,
        mode: str,
        path: str,
        previous_path: str = "",
        project_id: int | None = None,
    ):
        super().__init__()
        self.mode = mode
        self.path = path
        self.previous_path = previous_path
        self.project_id = project_id

    def run(self):
        try:
            previous_flows = self._load_previous_flows()

            if self.mode == "folder":
                files, flows = load_folder(self.path, debug=False)
                dataset_label = f"Dataset: {self.path}"
                stats_label = f"JSON files: {len(files)}   |   Total flow records: {len(flows)}"
                current_folder = self.path
            elif self.mode == "file":
                fp = Path(self.path)
                flows = load_json_file(fp, debug=False)
                files = [fp]
                dataset_label = f"Dataset file: {self.path}"
                stats_label = f"JSON files: 1   |   Total flow records: {len(flows)}"
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
            title = "Failed to load dataset folder." if self.mode == "folder" else "Failed to load JSON file."
            self.error.emit(title, str(e))

    def _load_previous_flows(self) -> list[dict]:
        if not self.previous_path:
            return []

        try:
            prev = Path(self.previous_path)
            if prev.is_file():
                return load_json_file(prev, debug=False)
            if prev.is_dir():
                _files, flows = load_folder(prev, debug=False)
                return flows
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


class DatasetController(QObject):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self._load_thread: QThread | None = None
        self._load_worker: DatasetLoadWorker | None = None

    def _split_ranked_lines(self, items):
        left_lines = []
        right_lines = []

        for i, (name, count) in enumerate(items, start=1):
            left_lines.append(f"{i}. {name}")
            right_lines.append(str(count))

        return "\n".join(left_lines), "\n".join(right_lines)

    def load_dataset_dialog(self):
        if not self._ensure_active_project():
            return

        choice = self.app._choice_dialog(
            title="Open dataset",
            message="What do you want to open?",
            choices=["Folder", "JSON file"],
            width=420,
        )

        if choice == "Folder":
            folder = QFileDialog.getExistingDirectory(self.app, "Select dataset folder")
            if not folder:
                return
            self.load_dataset_path(folder)
            return

        if choice == "JSON file":
            file_path, _ = QFileDialog.getOpenFileName(
                self.app,
                "Select JSON file",
                "",
                "JSON files (*.json)",
            )
            if not file_path:
                return
            self.load_dataset_file(file_path)
            return

    def render_summary(self):
        flows = self.app.flow_controller.get_all()

        if not flows:
            self.app.txt_top_src_left.setText("No flows loaded.")
            self.app.txt_top_src_right.setText("")

            self.app.txt_top_dst_left.setText("No flows loaded.")
            self.app.txt_top_dst_right.setText("")

            self.app.txt_top_proto_left.setText("No flows loaded.")
            self.app.txt_top_proto_right.setText("")

            self.app.txt_top_apps_left.setText("No flows loaded.")
            self.app.txt_top_apps_right.setText("")
            return

        src_items = top_src_ips(flows, limit=5)
        dst_items = top_dst_ips(flows, limit=5)
        proto_items = [(format_ip_proto(proto), c) for proto, c in top_protocols(flows, limit=5)]
        app_items = top_applications(flows, limit=5)

        left, right = self._split_ranked_lines(src_items)
        self.app.txt_top_src_left.setText(left)
        self.app.txt_top_src_right.setText(right)

        left, right = self._split_ranked_lines(dst_items)
        self.app.txt_top_dst_left.setText(left)
        self.app.txt_top_dst_right.setText(right)

        left, right = self._split_ranked_lines(proto_items)
        self.app.txt_top_proto_left.setText(left)
        self.app.txt_top_proto_right.setText(right)

        left, right = self._split_ranked_lines(app_items)
        self.app.txt_top_apps_left.setText(left)
        self.app.txt_top_apps_right.setText(right)

    def load_dataset_path(self, folder: str):
        if not self._ensure_active_project():
            return

        folder = str(folder)
        if not Path(folder).exists():
            self.app._message_dialog("Dataset", "Folder not found.", folder, width=480)
            return

        previous_path = self._get_previous_dataset_path(folder)
        self._start_dataset_load("folder", folder, previous_path)

    def load_dataset_file(self, file_path: str):
        if not self._ensure_active_project():
            return

        file_path = str(file_path)
        fp = Path(file_path)

        if not fp.exists() or not fp.is_file():
            self.app._message_dialog("Dataset", "File not found.", file_path, width=480)
            return

        previous_path = self._get_previous_dataset_path(file_path)
        self._start_dataset_load("file", file_path, previous_path)

    def _get_previous_dataset_path(self, current_path: str) -> str:
        if self.app.current_project_id is None:
            return ""

        recent = list_recent_datasets(self.app.current_project_id, limit=2)
        if not recent:
            return ""

        previous_path = str(recent[0])
        if previous_path == str(current_path):
            return ""

        return previous_path

    def _start_dataset_load(self, mode: str, path: str, previous_path: str = ""):
        if self._load_thread is not None:
            self.app._message_dialog("Dataset", "A dataset is already loading.", width=420)
            return

        self._set_loading(True)

        self._load_thread = QThread()
        self._load_worker = DatasetLoadWorker(
            mode=mode,
            path=path,
            previous_path=previous_path,
            project_id=self.app.current_project_id,
        )

        self._load_worker.moveToThread(self._load_thread)
        self._load_thread.started.connect(self._load_worker.run)
        self._load_worker.finished.connect(self._on_dataset_loaded, Qt.QueuedConnection)
        self._load_worker.error.connect(self._on_dataset_load_error, Qt.QueuedConnection)
        self._load_worker.finished.connect(self._load_thread.quit)
        self._load_worker.error.connect(self._load_thread.quit)
        self._load_worker.finished.connect(self._load_worker.deleteLater)
        self._load_worker.error.connect(self._load_worker.deleteLater)
        self._load_thread.finished.connect(self._load_thread.deleteLater)
        self._load_thread.finished.connect(self._cleanup_load_thread)
        self._load_thread.start()

    def _on_dataset_loaded(self, result: dict):
        if result.get("project_id") != self.app.current_project_id:
            self.app._message_dialog(
                "Dataset",
                "Dataset load finished, but the active project changed. The loaded data was ignored.",
                width=520,
            )
            return

        if not self._confirm_or_bind_project_target(result.get("meta") or {}):
            return

        path = str(result["path"])
        files = result["files"]
        flows = result["flows"]
        compare_result = result.get("compare_result")

        self.app.current_folder = Path(result["current_folder"])
        self.app.flow_controller.page_size = self.app.PAGE_SIZE
        self.app.flow_controller.set_flows(flows)

        if hasattr(self.app, "registry_page"):
            self.app.registry_page.set_dataset(path, files, flows, compare_result=compare_result)

        if hasattr(self.app, "listing_page"):
            self.app.listing_page.set_dataset(path, files, flows, compare_result=compare_result)

        self.app.lbl_path.setText(str(result["dataset_label"]))
        self.app.lbl_stats.setText(str(result["stats_label"]))

        if self.app.current_project_id is not None:
            add_dataset_load(self.app.current_project_id, path)
            self.app.projects_ui_controller.refresh_recent_datasets(self.app.current_project_id)
            self.app.refresh_activity_ui()

        self.render_summary()

        self.app.model.set_flows(self.app.flow_controller.get_loaded())

        self.app.search.setText("")
        self.app.explore_ui_controller.leave_conversation(clear_search=False)

        self.app.explore_ui_controller.update_loaded_label()
        self.app.explore_ui_controller.update_load_more_enabled()

        self.app.tabs.setCurrentIndex(1)
        self.app._flows_expanded = False
        self.app.details_panel.show()
        self.app.btn_expand_flows.setText("Expand Flows")
        self.app.splitter.setSizes([920, 420])
        self.app.explore_ui_controller.update_detail(None)

    def _ensure_active_project(self) -> bool:
        if self.app.current_project_id is not None:
            return True

        self.app._message_dialog(
            "Dataset",
            "Open an active project first.",
            "Datasets are stored and checked against the active project target.",
            width=480,
        )
        return False

    def _dataset_target_from_meta(self, meta: dict) -> tuple[str, str]:
        target_identifier = str(meta.get("target") or "").strip()
        target_type = str(meta.get("targettype") or "").strip()
        return target_identifier, target_type

    def _format_target(self, target_identifier: str, target_type: str) -> str:
        if target_identifier and target_type:
            return f"{target_identifier} ({target_type})"
        return target_identifier or target_type or "-"

    def _target_matches(
        self,
        project_identifier: str,
        project_type: str,
        dataset_identifier: str,
        dataset_type: str,
    ) -> bool:
        same_identifier = project_identifier.strip().casefold() == dataset_identifier.strip().casefold()
        if not same_identifier:
            return False

        if project_type and dataset_type:
            return project_type.strip().casefold() == dataset_type.strip().casefold()

        return True

    def _refresh_selected_project_preview(self, project_id: int) -> None:
        selected_item = self.app.projects_list.currentItem()
        if selected_item and int(selected_item.data(Qt.UserRole)) == project_id:
            self.app.projects_ui_controller.on_project_selected_preview()

    def _confirm_or_bind_project_target(self, meta: dict) -> bool:
        project_id = self.app.current_project_id
        if project_id is None:
            return False

        project = get_project(project_id)
        if not project:
            self.app._message_dialog("Dataset", "Project not found.", width=400)
            return False

        dataset_identifier, dataset_type = self._dataset_target_from_meta(meta)
        project_identifier = (project.target_identifier or "").strip()
        project_type = (project.target_type or "").strip()

        if not dataset_identifier:
            details = (
                f"Project target: {self._format_target(project_identifier, project_type)}\n"
                "Dataset target: -\n\n"
                "ViaNyquist cannot verify whether this dataset belongs to the active project."
            )
            return self.app._confirm_dialog(
                title="Dataset target missing",
                message="Dataset does not contain a target identifier.",
                details=details,
                ok_text="Load anyway",
                cancel_text="Cancel",
                width=520,
            )

        if not project_identifier:
            set_project_target(project_id, dataset_identifier, dataset_type)
            self._refresh_selected_project_preview(project_id)
            return True

        same_identifier = project_identifier.casefold() == dataset_identifier.casefold()
        if same_identifier and not project_type and dataset_type:
            set_project_target(project_id, project_identifier, dataset_type)
            self._refresh_selected_project_preview(project_id)
            return True

        if same_identifier and project_type and not dataset_type:
            details = (
                f"Project target: {self._format_target(project_identifier, project_type)}\n"
                f"Dataset target: {self._format_target(dataset_identifier, dataset_type)}\n\n"
                "The identifier matches, but the dataset does not contain a target type."
            )
            return self.app._confirm_dialog(
                title="Dataset target type missing",
                message="Dataset target type could not be verified.",
                details=details,
                ok_text="Load anyway",
                cancel_text="Cancel",
                width=540,
            )

        if self._target_matches(project_identifier, project_type, dataset_identifier, dataset_type):
            return True

        details = (
            f"Project target: {self._format_target(project_identifier, project_type)}\n"
            f"Dataset target: {self._format_target(dataset_identifier, dataset_type)}\n\n"
            "This may mean the selected dataset belongs to a different target than the active project."
        )
        return self.app._confirm_dialog(
            title="Dataset target mismatch",
            message="Dataset target does not match the active project.",
            details=details,
            ok_text="Load anyway",
            cancel_text="Cancel",
            width=560,
        )

    def _on_dataset_load_error(self, title: str, details: str):
        self.app._message_dialog("Dataset", title, details, width=520)

    def _cleanup_load_thread(self):
        self._load_worker = None
        self._load_thread = None
        self._set_loading(False)

    def _set_loading(self, loading: bool):
        if not hasattr(self.app, "btn_load"):
            return

        self.app.btn_load.setEnabled(not loading)
        self.app.btn_load.setText("Loading..." if loading else "Load dataset")
