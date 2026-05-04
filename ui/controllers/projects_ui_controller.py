from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QListWidgetItem

from core.db import (
    create_project,
    list_projects,
    get_project,
    delete_project,
    list_recent_datasets,
    update_project,
)
from core.project_identity import project_identifiers_text, subject_display_label
from core.project_profile import build_project_activity_profile
from core.workspace import (
    ensure_workspace_structure,
    build_workspace_path,
    move_workspace_folder,
    delete_workspace_folder,
    looks_like_vianyquist_workspace,   
)
from ui.dialogs import project_details_dialog

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
        self.refresh_case_dashboard(None)
        self.app.refresh_activity_profile_ui()
        self.app.refresh_activity_ui_for_project(None)

    def create_project_dialog(self):
        values, ok = project_details_dialog(
            self.app,
            title="New project",
        )
        if not ok:
            return

        values = values or {}
        name = (values.get("name") or "").strip()
        if not name:
            self.app._message_dialog(
                "New project",
                "Project name is required.",
                width=400,
            )
            return

        desc = values.get("description", "")
        parent_folder = values.get("parent_folder", "")

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
            pid = create_project(
                name=name,
                description=desc,
                base_folder=workspace_folder,
                subject_first_name=values.get("first_name", ""),
                subject_last_name=values.get("last_name", ""),
                subject_oib=values.get("oib", ""),
                subject_msisdn=values.get("msisdn", ""),
                subject_imsi=values.get("imsi", ""),
                subject_imei=values.get("imei", ""),
                subject_ip=values.get("ip", ""),
                subject_extra_identifiers=values.get("extra_identifiers", ""),
            )
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
            opened = self.app.dataset_controller.load_dataset_dialog()
            if opened == "json":
                self.app.go_page(self.app.IDX_EXPLORE, self.app._nav_explore)

    def on_project_selected_preview(self):
        item = self.app.projects_list.currentItem()
        if not item:
            self.app.projects_info.setText("Select a project to see details.")
            self.app.recent_list.clear()
            self.refresh_case_dashboard(None)
            return

        pid = int(item.data(Qt.UserRole))
        p = get_project(pid)
        if not p:
            return

        info = []
        info.append("Selected project")
        info.append("")
        info.append(f"Name: {p.name}")
        info.append(f"ID: {p.id}")
        info.append(f"Subject: {subject_display_label(p)}")
        info.append(f"Identifiers: {project_identifiers_text(p)}")
        if p.subject_oib:
            info.append(f"OIB: {p.subject_oib}")
        if p.subject_ip:
            info.append(f"Known IP: {p.subject_ip}")
        info.append("")
        if p.description:
            info.append("Description:")
            info.append(p.description)
            info.append("")
        if p.target_identifier or p.target_type:
            info.append(f"Legacy target fallback: {p.target_type or '-'} / {p.target_identifier or '-'}")
        info.append("")
        info.append(f"Workspace: {p.base_folder or '-'}")
        info.append(f"Created / updated: {p.created_at} / {p.updated_at}")
        self.app.projects_info.setText("\n".join(info))

        self.refresh_recent_datasets(pid)
        self.app.refresh_activity_ui_for_project(pid)
        self.refresh_case_dashboard(pid)

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
            self.app.refresh_activity_profile_ui()

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

        current_workspace = (project.base_folder or "").strip()
        current_parent_folder = str(Path(current_workspace).parent) if current_workspace else ""

        values, ok = project_details_dialog(
            self.app,
            title="Edit project",
            project=project,
            parent_folder=current_parent_folder,
        )
        if not ok:
            return

        values = values or {}
        name = (values.get("name") or "").strip()
        if not name:
            self.app._message_dialog(
                "Edit project",
                "Project name is required.",
                width=400,
            )
            return

        desc = values.get("description", "")
        parent_folder = values.get("parent_folder", "") or current_parent_folder

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
                subject_first_name=values.get("first_name", ""),
                subject_last_name=values.get("last_name", ""),
                subject_oib=values.get("oib", ""),
                subject_msisdn=values.get("msisdn", ""),
                subject_imsi=values.get("imsi", ""),
                subject_imei=values.get("imei", ""),
                subject_ip=values.get("ip", ""),
                subject_extra_identifiers=values.get("extra_identifiers", ""),
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
            self.app.refresh_activity_profile_ui()

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
        self.refresh_case_dashboard(p.id)
        self.app.refresh_findings_ui()
        self.app.refresh_notes_ui()
        self.app.refresh_activity_profile_ui()

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

    def refresh_case_dashboard(self, project_id: int | None):
        if not hasattr(self.app, "lbl_case_dashboard_title"):
            return

        if project_id is None:
            self.app.lbl_case_dashboard_title.setText("Case Dashboard")
            self.app.lbl_case_dashboard_subject.setText("Select a project to see case context.")
            for idx, title in enumerate(("Datasets", "PCAP", "Findings", "Device IPs")):
                self.app.case_metric_cards[idx].setText(f"{title}: 0")
            self.app.lbl_case_dashboard_warnings.setText("")
            return

        project = get_project(project_id)
        if not project:
            self.refresh_case_dashboard(None)
            return

        profile = build_project_activity_profile(project_id)
        active_suffix = "active" if self.app.current_project_id == project_id else "selected"
        self.app.lbl_case_dashboard_title.setText(f"Case Dashboard: {project.name} ({active_suffix})")
        self.app.lbl_case_dashboard_subject.setText(
            f"Subject: {subject_display_label(project)}\n"
            f"Known identifiers: {project_identifiers_text(project)}"
        )

        values = [
            ("Datasets", profile.get("dataset_count", 0)),
            ("PCAP", profile.get("pcap_count", 0)),
            ("Findings", profile.get("finding_count", 0)),
            ("Device IPs", len(profile.get("pcap_device_ips") or {})),
        ]
        for idx, (title, value) in enumerate(values):
            self.app.case_metric_cards[idx].setText(f"{title}: {value}")

        warnings = self._case_dashboard_warnings(project, profile)
        self.app.lbl_case_dashboard_warnings.setText(
            "Review: " + " | ".join(warnings) if warnings else "Review: no immediate project consistency warnings."
        )

    def _case_dashboard_warnings(self, project, profile: dict) -> list[str]:
        warnings: list[str] = []
        if project_identifiers_text(project) == "-":
            warnings.append("add known identifiers")
        if not profile.get("dataset_count"):
            warnings.append("no JSON datasets saved")
        if not profile.get("pcap_count"):
            warnings.append("no PCAP sources saved")

        pcap_ips = profile.get("pcap_device_ips") or {}
        if len(pcap_ips) > 1:
            warnings.append("multiple PCAP device IPs observed")

        known_ip = (project.subject_ip or "").strip()
        if known_ip and pcap_ips and known_ip not in pcap_ips:
            warnings.append("known project IP differs from saved PCAP device IPs")

        return warnings

    def activity_label(self, event_type: str, message: str = "") -> str:
        labels = {
            "dataset_loaded": "Dataset loaded",
            "pcap_saved": "PCAP saved",
            "pcap_notes_added": "PCAP notes added",
            "finding_created": "Finding created",
            "finding_updated": "Finding updated",
            "finding_deleted": "Finding deleted",
        }
        label = labels.get(event_type, event_type.replace("_", " ").title())
        detail = Path(message).name if message else ""
        if detail:
            return f"{label}: {detail}"
        return label

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

        opened = self.app.dataset_controller.load_dataset_dialog()
        if opened == "json":
            self.app.go_page(
                self.app.IDX_EXPLORE,
                self.app._nav_explore
            )

    
