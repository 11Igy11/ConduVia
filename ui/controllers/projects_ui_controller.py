from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QListWidgetItem

from core.db import (
    create_project,
    list_projects,
    get_project,
    delete_project,
    list_recent_datasets,
)


class ProjectsUIController:
    def __init__(self, app):
        self.app = app

    def refresh_projects(self):
        self.app.projects_list.clear()
        projects = list_projects()

        for p in projects:
            item = QListWidgetItem(p.name)
            item.setData(Qt.UserRole, p.id)
            self.app.projects_list.addItem(item)

        self.app.projects_info.setText("Select a project to see details.")
        self.app.recent_list.clear()

    def create_project_dialog(self):
        name, ok = self.app._text_input_dialog("New project", "Project name:", width=420)
        if not ok:
            return
        name = (name or "").strip()
        if not name:
            return

        desc, ok2 = self.app._multiline_input_dialog(
            "New project",
            "Description (optional):",
            width=460,
            height=260,
        )
        if not ok2:
            desc = ""

        base = QFileDialog.getExistingDirectory(
            self.app,
            "Select project base folder (optional)"
        )
        base = base or ""

        try:
            pid = create_project(name=name, description=desc, base_folder=base)
        except Exception as e:
            self.app._message_dialog("Error", "Project creation failed.", str(e), width=440)
            return

        self.set_active_project(pid)
        self.refresh_projects()
        self.refresh_recent_datasets(pid)
        self.app.refresh_findings_ui()
        self.app.refresh_notes_ui()

        should_open = self.app._confirm_dialog(
            title="Open dataset",
            message="Project created successfully.",
            details="Do you want to open a dataset now?",
            ok_text="Yes",
            cancel_text="No",
            width=420,
        )

        if should_open:
            self.app.dataset_controller.load_dataset_dialog()
            self.app.go_page(self.app.IDX_EXPLORE, self.app._nav_explore)

    def on_project_selected_preview(self):
        item = self.app.projects_list.currentItem()
        if not item:
            self.app.projects_info.setText("Select a project to see details.")
            self.app.recent_list.clear()
            return

        pid = int(item.data(Qt.UserRole))
        p = get_project(pid)
        if not p:
            return

        info = []
        info.append(f"Name: {p.name}")
        info.append(f"ID: {p.id}")
        info.append(f"Base folder: {p.base_folder or '-'}")
        info.append(f"Created: {p.created_at}")
        info.append(f"Updated: {p.updated_at}")
        info.append("")
        info.append(p.description or "")
        self.app.projects_info.setText("\n".join(info))

        self.refresh_recent_datasets(pid)

    def open_selected_project(self):
        item = self.app.projects_list.currentItem()
        if not item:
            return
        pid = int(item.data(Qt.UserRole))
        self.set_active_project(pid)

    def delete_selected_project(self):
        item = self.app.projects_list.currentItem()
        if not item:
            return

        project_id = int(item.data(Qt.UserRole))
        project = get_project(project_id)
        if not project:
            self.app._message_dialog("Delete project", "Project not found.", width=400)
            return

        confirmed = self.app._confirm_dialog(
            title="Delete project",
            message="Delete selected project?",
            details=(
                f"{project.name} (id={project.id})\n\n"
                "This will permanently delete:\n"
                "• project\n"
                "• loaded datasets\n"
                "• findings\n"
                "• activity log"
            ),
            ok_text="Delete",
            cancel_text="Cancel",
            width=430,
            destructive=True,
        )

        if not confirmed:
            return

        try:
            delete_project(project_id)
        except Exception as e:
            self.app._message_dialog("Delete project failed", str(e), width=440)
            return

        if self.app.current_project_id == project_id:
            self.app.current_project_id = None
            self.app.current_project_name = ""
            self.app.current_folder = None

            self.app.lbl_active_project.setText("Active project: (none)")
            self.app.lbl_project_banner.setText("Project: (none)")

            self.app.lbl_path.setText("No dataset loaded")
            self.app.lbl_stats.setText("")
            self.app.txt_top_src_left.setText("No flows loaded.")
            self.app.txt_top_src_right.setText("")

            self.app.txt_top_dst_left.setText("No flows loaded.")
            self.app.txt_top_dst_right.setText("")

            self.app.txt_top_proto_left.setText("No flows loaded.")
            self.app.txt_top_proto_right.setText("")

            self.app.txt_top_apps_left.setText("No flows loaded.")
            self.app.txt_top_apps_right.setText("")
            self.app.txt_ai_summary.clear()

            self.app.model.set_flows([])
            self.app.leave_conversation(clear_search=True)
            self.app.explore_ui_controller.update_loaded_label()
            self.app.explore_ui_controller.update_load_more_enabled()
            self.app._flows_expanded = False

            if hasattr(self.app, "details_panel"):
                self.app.details_panel.show()
            if hasattr(self.app, "btn_expand_flows"):
                self.app.btn_expand_flows.setText("Expand Flows")

            if hasattr(self.app, "registry_page"):
                self.app.registry_page.set_dataset("", [], [])

            self.app.refresh_findings_ui()
            self.app.refresh_notes_ui()

        self.refresh_projects()

    def set_active_project(self, project_id: int):
        p = get_project(project_id)
        if not p:
            self.app._message_dialog("Project", "Project not found.", width=400)
            return

        self.app.current_project_id = p.id
        self.app.current_project_name = p.name

        self.app.lbl_active_project.setText(f"Active project: {p.name}")
        self.app.lbl_project_banner.setText(f"Project: {p.name}")

        self.refresh_recent_datasets(p.id)
        self.app.refresh_findings_ui()
        self.app.refresh_notes_ui()

    def refresh_recent_datasets(self, project_id: int):
        self.app.recent_list.clear()
        paths = list_recent_datasets(project_id, limit=15)

        if not paths:
            self.app.recent_list.addItem(QListWidgetItem("(no datasets yet)"))
            return

        for fp in paths:
            p = Path(str(fp))

            if p.is_file():
                label = f"[FILE] {p.name}"
            elif p.is_dir():
                label = f"[FOLDER] {p.name}"
            else:
                label = f"[MISSING] {p.name or str(fp)}"

            item = QListWidgetItem(label)
            item.setToolTip(str(fp))
            item.setData(Qt.UserRole, str(fp))
            self.app.recent_list.addItem(item)

    def open_selected_dataset(self):
        item = self.app.recent_list.currentItem()
        if not item:
            return

        fp = item.data(Qt.UserRole)
        if not fp or str(fp).startswith("("):
            return

        p = Path(str(fp))

        if p.is_file():
            self.app.dataset_controller.load_dataset_file(str(p))
        elif p.is_dir():
            self.app.dataset_controller.load_dataset_path(str(p))
        else:
            self.app._message_dialog("Dataset", "Path not found.", str(p), width=460)
            return

        self.app.go_page(self.app.IDX_EXPLORE, self.app._nav_explore)