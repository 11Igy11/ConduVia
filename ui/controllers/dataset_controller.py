from pathlib import Path

from core.db import add_dataset_load, list_recent_datasets
from core.analyzer import top_src_ips, top_dst_ips, top_applications, top_protocols
from core.protocols import format_ip_proto
from core.loader import load_folder, load_json_file
from PySide6.QtWidgets import QFileDialog

class DatasetController:
    def __init__(self, app):
        self.app = app

    def _split_ranked_lines(self, items):
        left_lines = []
        right_lines = []

        for i, (name, count) in enumerate(items, start=1):
            left_lines.append(f"{i}. {name}")
            right_lines.append(str(count))

        return "\n".join(left_lines), "\n".join(right_lines)
    
    def load_dataset_dialog(self):
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
                "JSON files (*.json)"
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
        folder = str(folder)
        if not Path(folder).exists():
            self.app._message_dialog("Dataset", "Folder not found.", folder, width=480)
            return

        previous_flows = []

        if self.app.current_project_id is not None:
            recent = list_recent_datasets(self.app.current_project_id, limit=2)

            if len(recent) >= 1:
                prev_folder = recent[0]

                # ako je isti folder → ignoriraj
                if str(prev_folder) != str(folder):
                    try:
                        _, previous_flows = load_folder(prev_folder)
                    except Exception:
                        previous_flows = []

        self.app.current_folder = Path(folder)
        files, flows = load_folder(folder, debug=False)
        self.app.flow_controller.page_size = self.app.PAGE_SIZE
        self.app.flow_controller.set_flows(flows)

        from core.compare import compare_flows
        from core.compare import summarize_new_flows

        compare_result = None
        if previous_flows:
            compare_result = compare_flows(flows, previous_flows)

        summary_new = None
        if compare_result:
            summary_new = summarize_new_flows(compare_result["new"])
            compare_result["summary_new"] = summary_new

        if hasattr(self.app, "registry_page"):
            self.app.registry_page.set_dataset(folder, files, flows, compare_result=compare_result)

        if hasattr(self.app, "listing_page"):
            self.app.listing_page.set_dataset(folder, files, flows, compare_result=compare_result)

        self.app.lbl_path.setText(f"Dataset: {folder}")
        self.app.lbl_stats.setText(f"JSON files: {len(files)}   |   Total flow records: {len(flows)}")

        if self.app.current_project_id is not None:
            add_dataset_load(self.app.current_project_id, folder)
            self.app.projects_ui_controller.refresh_recent_datasets(self.app.current_project_id)
            self.app.refresh_activity_ui()

        self.render_summary()

        self.app.model.set_flows(self.app.flow_controller.get_loaded())

        self.app.search.setText("")
        self.app.leave_conversation(clear_search=False)

        self.app.update_loaded_label()
        self.app.update_load_more_enabled()

        self.app.tabs.setCurrentIndex(1)
        self.app._flows_expanded = False
        self.app.details_panel.show()
        self.app.btn_expand_flows.setText("Expand Flows")
        self.app.splitter.setSizes([920, 420])
        self.app.update_detail(None)

    def load_dataset_file(self, file_path: str):
        file_path = str(file_path)
        fp = Path(file_path)

        if not fp.exists() or not fp.is_file():
            self.app._message_dialog("Dataset", "File not found.", file_path, width=480)
            return

        previous_flows = []

        if self.app.current_project_id is not None:
            recent = list_recent_datasets(self.app.current_project_id, limit=2)

            if len(recent) >= 1:
                prev_path = recent[0]

                if str(prev_path) != str(file_path):
                    try:
                        prev_fp = Path(prev_path)
                        if prev_fp.is_file():
                            previous_flows = load_json_file(prev_fp, debug=False)
                        elif prev_fp.is_dir():
                            _, previous_flows = load_folder(prev_fp, debug=False)
                    except Exception:
                        previous_flows = []

        self.app.current_folder = fp.parent
        flows = load_json_file(fp, debug=False)
        files = [fp]
        self.app.flow_controller.page_size = self.app.PAGE_SIZE
        self.app.flow_controller.set_flows(flows)

        from core.compare import compare_flows, summarize_new_flows

        compare_result = None
        if previous_flows:
            compare_result = compare_flows(flows, previous_flows)

        if compare_result:
            summary_new = summarize_new_flows(compare_result["new"])
            compare_result["summary_new"] = summary_new

        if hasattr(self.app, "registry_page"):
            self.app.registry_page.set_dataset(str(fp), files, flows, compare_result=compare_result)

        if hasattr(self.app, "listing_page"):
            self.app.listing_page.set_dataset(str(fp), files, flows, compare_result=compare_result)

        self.app.lbl_path.setText(f"Dataset file: {file_path}")
        self.app.lbl_stats.setText(f"JSON files: 1   |   Total flow records: {len(flows)}")

        if self.app.current_project_id is not None:
            add_dataset_load(self.app.current_project_id, file_path)
            self.app.projects_ui_controller.refresh_recent_datasets(self.app.current_project_id)
            self.app.refresh_activity_ui()

        self.render_summary()

        self.app.model.set_flows(self.app.flow_controller.get_loaded())

        self.app.search.setText("")
        self.app.leave_conversation(clear_search=False)

        self.app.update_loaded_label()
        self.app.update_load_more_enabled()

        self.app.tabs.setCurrentIndex(1)
        self.app._flows_expanded = False
        self.app.details_panel.show()
        self.app.btn_expand_flows.setText("Expand Flows")
        self.app.splitter.setSizes([920, 420])
        self.app.update_detail(None)