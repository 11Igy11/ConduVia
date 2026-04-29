from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFileDialog, QListWidgetItem

from core.db import (
    create_project,
    list_projects,
    get_project,
    delete_project,
    list_recent_datasets,
    update_project,
)
from core.workspace import (
    ensure_workspace_structure,
    build_workspace_path,
    move_workspace_folder,
    delete_workspace_folder,
    looks_like_vianyquist_workspace,   
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
        self.app.refresh_activity_ui_for_project(None)

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

        parent_folder = QFileDialog.getExistingDirectory(
            self.app,
            "Select parent folder for project workspace (optional)"
        )
        
        parent_folder = parent_folder or ""

        workspace_folder = ""
        if parent_folder:
            try:
                workspace_folder = str(build_workspace_path(parent_folder, name))
                ensure_workspace_structure(workspace_folder)
            except Exception as e:
                self.app._message_dialog(
                    "Workspace",
                    "Failed to initialize workspace folder.",
                    str(e),
                    width=460,
                )
                return                                                  

        try:
            pid = create_project(name=name, description=desc, base_folder=workspace_folder)
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
        info.append(f"Target: {p.target_identifier or '-'}")
        info.append(f"Target type: {p.target_type or '-'}")
        info.append(f"Workspace folder: {p.base_folder or '-'}")
        info.append(f"Created: {p.created_at}")
        info.append(f"Updated: {p.updated_at}")
        info.append("")
        info.append(p.description or "")
        self.app.projects_info.setText("\n".join(info))

        self.refresh_recent_datasets(pid)
        self.app.refresh_activity_ui_for_project(pid)

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
                "• activity log\n"
                "• workspace folders\n\n"
                "Only ViaNyquist workspace folders for this project will be removed."
            ),
            ok_text="Delete",
            cancel_text="Cancel",
            width=430,
            destructive=True,
        )

        if not confirmed:
            return

        try:
            if project.base_folder and looks_like_vianyquist_workspace(project.base_folder):
                delete_workspace_folder(project.base_folder)

            delete_project(project_id)

        except Exception as e:
            self.app._message_dialog("Delete project failed", str(e), width=440)
            return

        if self.app.current_project_id == project_id:
            self.app.clear_dataset_context()

            self.app.current_project_id = None
            self.app.current_project_name = ""

            self.app.lbl_active_project.setText("Active project: (none)")
            self.app.lbl_project_banner.setText("Project: (none)")

            self.app.refresh_findings_ui()
            self.app.refresh_notes_ui()

        self.refresh_projects()

    def edit_selected_project(self):
        item = self.app.projects_list.currentItem()
        if not item:
            self.app._message_dialog(
                "Edit project",
                "Select a project first.",
                width=400,
            )
            return

        project_id = int(item.data(Qt.UserRole))
        project = get_project(project_id)

        if not project:
            self.app._message_dialog(
                "Edit project",
                "Project not found.",
                width=400,
            )
            return

        # --- Name ---
        name, ok = self.app._text_input_dialog(
            "Edit project",
            "Project name:",
            text=project.name or "",
            width=420,
        )
        if not ok:
            return

        name = (name or "").strip()
        if not name:
            self.app._message_dialog(
                "Edit project",
                "Project name is required.",
                width=400,
            )
            return

        # --- Description ---
        desc, ok2 = self.app._multiline_input_dialog(
            "Edit project",
            "Description (optional):",
            text=project.description or "",
            width=460,
            height=260,
        )
        if not ok2:
            return

        # --- Current workspace / parent ---
        current_workspace = (project.base_folder or "").strip()
        current_parent_folder = str(Path(current_workspace).parent) if current_workspace else ""

        # --- Parent folder change ---
        change_folder = self.app._confirm_dialog(
            title="Edit project",
            message="Do you want to change the parent folder for this project workspace?",
            details=f"Current workspace: {project.base_folder or '-'}",
            ok_text="Change",
            cancel_text="Keep current",
            width=460,
        )

        if change_folder:
            selected_parent = QFileDialog.getExistingDirectory(
                self.app,
                "Select parent folder for project workspace"
            )
            if selected_parent:
                parent_folder = selected_parent
            else:
                parent_folder = current_parent_folder
        else:
            parent_folder = current_parent_folder

        # --- Build target workspace path ---
        new_workspace_folder = ""
        if parent_folder:
            try:
                new_workspace_folder = str(build_workspace_path(parent_folder, name))
            except Exception as e:
                self.app._message_dialog(
                    "Workspace",
                    "Invalid workspace folder configuration.",
                    str(e),
                    width=460,
                )
                return

        # --- Rename / move workspace before DB update ---
        try:
            if current_workspace and new_workspace_folder:
                move_workspace_folder(current_workspace, new_workspace_folder)
            elif not current_workspace and new_workspace_folder:
                ensure_workspace_structure(new_workspace_folder)
            else:
                new_workspace_folder = current_workspace

        except Exception as e:
            self.app._message_dialog(
                "Workspace",
                "Failed to rename/move project workspace folder.",
                str(e),
                width=460,
            )
            return

        # --- Update DB only after successful filesystem operation ---
        try:
            update_project(
                project_id=project.id,
                name=name,
                description=desc,
                base_folder=new_workspace_folder,
            )

        except Exception as e:
            self.app._message_dialog(
                "Edit project",
                "Project update failed.",
                str(e),
                width=440,
            )
            return

        # refresh whole page
        self.refresh_projects()

        # reselect updated item
        for i in range(self.app.projects_list.count()):
            it = self.app.projects_list.item(i)
            if int(it.data(Qt.UserRole)) == project.id:
                self.app.projects_list.setCurrentItem(it)
                break

        # update active project labels if needed
        if self.app.current_project_id == project.id:
            self.app.current_project_name = name
            self.app.lbl_active_project.setText(f"Active project: {name}")
            self.app.lbl_project_banner.setText(f"Project: {name}")

    def set_active_project(self, project_id: int):
        p = get_project(project_id)
        if not p:
            self.app._message_dialog("Project", "Project not found.", width=400)
            return
        
        project_changed = self.app.current_project_id != p.id

        if project_changed:
            self.app.clear_dataset_context()

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

    def open_new_dataset(self):
        if self.app.current_project_id is None:
            self.app._message_dialog(
                "Dataset",
                "Open an active project first.",
                width=420,
            )
            return

        self.app.dataset_controller.load_dataset_dialog()
        self.app.go_page(
            self.app.IDX_EXPLORE,
            self.app._nav_explore
        )

    
