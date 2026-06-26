from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QListWidgetItem

from core.analysis_limits import MAX_EVIDENCE_SNAPSHOT_ITEMS, MAX_RECENT_UI_ROWS
from core.db import (
    create_project,
    list_projects,
    get_project,
    delete_project,
    get_project_notes,
    list_recent_datasets,
    list_pcap_sources,
    list_activity,
    list_findings,
    touch_project,
    update_project,
)
from core.formatters import format_duration_compact_ms, format_pcap_datetime, human_bytes
from core.project_identity import project_identifiers_text, repair_stored_imsi_identifiers, subject_display_label, target_display_label
from core.project_evidence import build_project_evidence_snapshot
from core.project_datasets import list_project_json_dataset_files
from core.project_profile import build_project_activity_profile, format_project_activity_profile
from core.workspace import (
    ensure_workspace_structure,
    build_workspace_path,
    move_workspace_folder,
    delete_workspace_folder,
    looks_like_vianyquist_workspace,   
    write_project_notes_backup,
    write_project_workspace_manifest,
)
from ui.dialogs import project_details_dialog

class ProjectsUIController:
    def __init__(self, app):
        self.app = app

    def refresh_projects(self, *, reset_active: bool = False):
        if reset_active:
            self._clear_active_project()

        self.app.projects_list.clear()
        projects = list_projects()

        for p in projects:
            item = QListWidgetItem(p.name)
            item.setData(Qt.UserRole, p.id)
            self.app.projects_list.addItem(item)

        self.app.projects_info.setText("Select a project to see details.")
        self.app.project_recent_json_rows = []
        self.app.project_recent_json_total_count = 0
        self.app.project_recent_pcap_rows = []
        self.app.project_activity_rows = []
        if self.app.current_project_id is not None and not get_project(self.app.current_project_id):
            self._clear_active_project()
        self._refresh_project_launcher_cards()
        self.refresh_case_dashboard()
        self.app.refresh_activity_profile_ui()
        self.app.notes_controller.refresh_activity_ui_for_project(None)

    def _clear_active_project(self) -> None:
        if self.app.current_project_id is None:
            return

        self.app.dataset_controller.clear_context()
        self.app.current_project_id = None
        self.app.current_project_name = ""
        self.app.lbl_project_banner.setText("Project: (none)")
        self.app.findings_controller.refresh_ui()
        self.app.notes_controller.refresh_ui()
        self.app.refresh_activity_profile_ui()

    def _short_text(self, value: str, limit: int = 180) -> str:
        text = (value or "").strip()
        if len(text) <= limit:
            return text
        return text[: max(0, limit - 3)] + "..."

    def _persist_case_metadata(self, project_id: int, values: dict) -> None:
        from core.case_metadata import apply_manual_case_fields, load_case_metadata, save_case_metadata

        metadata = load_case_metadata(project_id)
        metadata = apply_manual_case_fields(
            metadata,
            klasa=str(values.get("klasa") or ""),
            urbroj=str(values.get("urbroj") or ""),
            order_validity_bt=str(values.get("order_validity_bt") or ""),
            order_validity_et=str(values.get("order_validity_et") or ""),
        )
        save_case_metadata(project_id, metadata)

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
                subject_ip="",
                subject_extra_identifiers=values.get("extra_identifiers", ""),
            )
        except Exception as e:
            self.app._message_dialog("Error", "Project creation failed.", str(e), width=440)
            return

        self._persist_case_metadata(pid, values)
        from core.db import add_activity

        add_activity(pid, "project_created", name)
        self.set_active_project(pid)
        self.sync_project_workspace(pid)
        self.refresh_projects()
        self.refresh_recent_datasets(pid)
        self.app.findings_controller.refresh_ui()
        self.app.notes_controller.refresh_ui()

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
                self.app.go_to_json_tab(0)

    def on_project_selected_preview(self):
        item = self.app.projects_list.currentItem()
        if not item:
            self.app.projects_info.setText("Select a project to see details.")
            self.app.project_recent_json_rows = []
            self.app.project_recent_pcap_rows = []
            self.app.project_activity_rows = []
            self._refresh_project_launcher_cards()
            self.refresh_case_dashboard()
            return

        pid = int(item.data(Qt.UserRole))
        p = get_project(pid)
        if not p:
            return

        from core.case_metadata import (
            format_active_order_validity,
            format_klasa_all,
            format_order_validity_history,
            format_urbroj_all,
            load_case_metadata,
        )

        metadata = load_case_metadata(pid)
        klasa_all = format_klasa_all(metadata)
        urbroj_all = format_urbroj_all(metadata)
        validity_active = format_active_order_validity(metadata)
        validity_history = format_order_validity_history(metadata)

        info = []
        info.append(f"ID: {p.id}")
        info.append(f"Subject: {subject_display_label(p)}")
        info.append(f"Identifiers: {project_identifiers_text(p)}")
        info.append(f"Klasa (all): {klasa_all}")
        info.append(f"Urbroj (all): {urbroj_all}")
        info.append(f"Order validity (active): {validity_active}")
        if validity_history:
            info.append(f"Earlier validity periods: {validity_history}")
        if p.subject_oib:
            info.append(f"OIB: {p.subject_oib}")
        info.append("")
        if p.description:
            info.append("Description:")
            info.append(p.description)
            info.append("")
        if p.target_identifier or p.target_type:
            info.append(f"Legacy target fallback: {target_display_label(p)}")
        info.append("")
        info.append(f"Workspace: {p.base_folder or '-'}")
        info.append(f"Created / updated: {p.created_at} / {p.updated_at}")
        self.app.projects_info.setText("\n".join(info))

        self.refresh_recent_datasets(pid)
        self.app.notes_controller.refresh_activity_ui_for_project(pid)
        self.refresh_case_dashboard()

    def open_selected_project(self):
        item = self.app.projects_list.currentItem()
        if not item:
            return
        pid = int(item.data(Qt.UserRole))
        self.set_active_project(pid)
        self.refresh_projects()
        for idx in range(self.app.projects_list.count()):
            refreshed_item = self.app.projects_list.item(idx)
            if int(refreshed_item.data(Qt.UserRole)) == pid:
                self.app.projects_list.setCurrentItem(refreshed_item)
                break
        self.on_project_selected_preview()

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
            self._clear_active_project()
            self.refresh_case_dashboard()

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
                subject_ip="",
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

        self._persist_case_metadata(project.id, values)
        from core.db import add_activity

        meta_bits = []
        klasa = str(values.get("klasa") or "").strip()
        urbroj = str(values.get("urbroj") or "").strip()
        if klasa:
            meta_bits.append(f"Klasa={klasa}")
        if urbroj:
            meta_bits.append(f"Urbroj={urbroj}")
        detail = name
        if meta_bits:
            detail = f"{name} ({'; '.join(meta_bits)})"
        add_activity(project.id, "project_edited", detail)
        self.refresh_recent_datasets(project.id)

        # refresh whole page
        self.sync_project_workspace(project.id)
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
            self.app.lbl_project_banner.setText(f"Project: {name}")
            self.refresh_case_dashboard()
            self.app.refresh_activity_profile_ui()

    def set_active_project(self, project_id: int):
        touch_project(project_id)
        p = get_project(project_id)
        if not p:
            self.app._message_dialog("Project", "Project not found.", width=400)
            return

        repair_stored_imsi_identifiers(project_id)
        p = get_project(project_id)
        if not p:
            return
        project_changed = self.app.current_project_id != p.id

        if project_changed:
            self.app.dataset_controller.clear_context()
            if hasattr(self.app, "activity_profile_page"):
                self.app.activity_profile_page.invalidate_project_cache()
        elif self.app.flow_controller.get_all():
            # Re-activating the same project must not keep stale loaded JSON/PCAP tables.
            self.app.dataset_controller.clear_context()

        self.app.current_project_id = p.id
        self.app.current_project_name = p.name

        self.app.lbl_project_banner.setText(f"Project: {p.name}")
        self.refresh_case_dashboard()

        if hasattr(self.app, "dataset_controller"):
            controller = self.app.dataset_controller
            QTimer.singleShot(0, lambda pid=p.id: controller.deferred_sync_project_periods(pid))

        self.app.findings_controller.refresh_ui()
        self.app.notes_controller.refresh_ui(refresh_profile=False)

        QTimer.singleShot(0, lambda pid=p.id: self._complete_project_activation(pid))

    def _complete_project_activation(self, project_id: int) -> None:
        if self.app.current_project_id != project_id:
            return

        self.refresh_recent_datasets(project_id)
        self.refresh_case_dashboard()
        QTimer.singleShot(150, lambda pid=project_id: self._deferred_profile_refresh(pid))
        if hasattr(self.app, "dataset_controller"):
            self.app.dataset_controller.refresh_project_behavior_index(project_id)
        QTimer.singleShot(250, lambda pid=project_id: self._deferred_project_workspace_sync(pid))

    def _deferred_profile_refresh(self, project_id: int) -> None:
        if self.app.current_project_id != project_id:
            return
        if hasattr(self.app, "refresh_activity_profile_ui"):
            self.app.refresh_activity_profile_ui()

    def _deferred_project_workspace_sync(self, project_id: int) -> None:
        if self.app.current_project_id != project_id:
            return
        self.sync_project_workspace(project_id)

    def sync_project_workspace(self, project_id: int | None) -> None:
        if project_id is None:
            return

        project = get_project(project_id)
        if not project or not (project.base_folder or "").strip():
            return

        json_rows = [
            row for row in list_project_json_dataset_files(project_id, limit=MAX_EVIDENCE_SNAPSHOT_ITEMS)
            if row.get("status") == "Available"
        ]
        json_datasets = [str(row.get("path") or "") for row in json_rows if row.get("path")]
        pcap_sources = []
        for source in list_pcap_sources(project_id, limit=MAX_EVIDENCE_SNAPSHOT_ITEMS):
            pieces = [source.file_name or Path(source.file_path).name]
            if source.file_path:
                pieces.append(source.file_path)
            if source.file_sha256:
                pieces.append(f"sha256={source.file_sha256}")
            pcap_sources.append(" | ".join(piece for piece in pieces if piece))

        profile = build_project_activity_profile(project_id)
        activity_lines = self._workspace_activity_lines(project_id)
        finding_lines = self._workspace_finding_lines(project_id)
        case_snapshot = self._workspace_case_snapshot(
            project=project,
            profile=profile,
            json_count=len(json_datasets),
            pcap_count=len(pcap_sources),
            finding_count=len(finding_lines),
            activity_count=len(activity_lines),
        )

        write_project_notes_backup(project.base_folder, get_project_notes(project_id))
        write_project_workspace_manifest(
            project.base_folder,
            project_name=project.name,
            project_id=project.id,
            subject=subject_display_label(project),
            identifiers=project_identifiers_text(project),
            json_datasets=json_datasets,
            pcap_sources=pcap_sources,
            findings=finding_lines,
            activity=activity_lines,
            profile_report=format_project_activity_profile(profile),
            case_snapshot=case_snapshot,
        )

    def _workspace_activity_lines(self, project_id: int) -> list[str]:
        lines: list[str] = []
        for row in list_activity(project_id, limit=1000):
            created_at = str(row["created_at"] or "")
            event_type = str(row["event_type"] or "")
            message = str(row["message"] or "")
            label = self.activity_label(event_type, message)
            lines.append(f"{created_at} | {event_type or '-'} | {label}")
        return lines

    def _workspace_finding_lines(self, project_id: int) -> list[str]:
        lines: list[str] = []
        for row in list_findings(project_id, limit=1000):
            title = str(row["title"] or "Untitled finding")
            status = str(row["status"] or "-")
            tags = str(row["tags"] or "-")
            protocol = str(row["protocol"] or "-")
            app_name = str(row["application_name"] or "-")
            host = str(row["requested_server_name"] or "-")
            src = self._endpoint_text(row["src_ip"], row["src_port"])
            dst = self._endpoint_text(row["dst_ip"], row["dst_port"])
            volume = human_bytes(row["bidirectional_bytes"], precision=2)
            packets = row["bidirectional_packets"] if row["bidirectional_packets"] is not None else "-"
            duration = format_duration_compact_ms(row["bidirectional_duration_ms"]) or "-"
            note = str(row["note"] or "").strip()

            parts = [
                f"#{row['id']} | {status} | {title}",
                f"Tags: {tags}",
                f"Flow: {src} -> {dst} | {protocol} | {app_name} | Host/SNI: {host}",
                f"Volume: {volume} | Packets: {packets} | Duration: {duration}",
            ]
            if note:
                parts.extend(["Note:", note])
            lines.append("\n".join(parts))
        return lines

    def _workspace_case_snapshot(
        self,
        *,
        project,
        profile: dict,
        json_count: int,
        pcap_count: int,
        finding_count: int,
        activity_count: int,
    ) -> str:
        lines = [
            "ViaNyquist beta case snapshot",
            "",
            f"Project: {project.name}",
            f"Project ID: {project.id}",
            f"Subject: {subject_display_label(project)}",
            f"Known identifiers: {project_identifiers_text(project)}",
            "",
            f"Unique JSON datasets: {json_count}",
            f"Unique PCAP sources: {pcap_count}",
            f"Findings: {finding_count}",
            f"Activity events: {activity_count}",
        ]

        capture_range = profile.get("capture_range") or {}
        if capture_range.get("start") or capture_range.get("end"):
            lines.append(
                "Observed PCAP capture range: "
                f"{format_pcap_datetime(capture_range.get('start')) or '-'} to "
                f"{format_pcap_datetime(capture_range.get('end')) or '-'}"
            )

        pcap_ips = profile.get("pcap_device_ips") or {}
        if pcap_ips:
            ip_text = ", ".join(f"{ip} ({count})" for ip, count in pcap_ips.items())
            lines.append(f"Observed PCAP device IPs: {ip_text}")

        warnings = self._case_dashboard_warnings(project, profile)
        if warnings:
            lines.append("")
            lines.append("Consistency warnings: " + " | ".join(warnings))
        return "\n".join(lines)

    def _endpoint_text(self, ip_value, port_value) -> str:
        ip = str(ip_value or "-")
        port = str(port_value or "").strip()
        return f"{ip}:{port}" if port else ip

    def refresh_recent_datasets(self, project_id: int):
        evidence = build_project_evidence_snapshot(project_id, limit=MAX_EVIDENCE_SNAPSHOT_ITEMS)
        json_evidence = evidence["json"]
        pcap_evidence = evidence["pcap"]

        self.app.project_recent_json_total_count = int(json_evidence.get("count") or 0)
        self.app.project_recent_json_rows = list(json_evidence.get("json_day_rows") or [])[:MAX_RECENT_UI_ROWS]
        self.app.project_recent_pcap_rows = list(pcap_evidence.get("recent_day_rows") or [])[:MAX_RECENT_UI_ROWS]

        activity_rows = list_activity(project_id, limit=MAX_RECENT_UI_ROWS)
        self.app.project_activity_rows = []
        for row in activity_rows:
            event = self.activity_label(str(row["event_type"] or ""), str(row["message"] or ""))
            self.app.project_activity_rows.append({
                "created_at": str(row["created_at"] or ""),
                "event": event,
                "detail": str(row["message"] or ""),
            })

        self._refresh_project_launcher_cards()

    def _refresh_project_launcher_cards(self) -> None:
        json_rows = getattr(self.app, "project_recent_json_rows", []) or []
        json_count = int(getattr(self.app, "project_recent_json_total_count", 0) or 0)
        if not json_count:
            json_count = sum(
                int(row.get("file_count") or 1)
                for row in json_rows
                if row.get("status") == "Available"
            )
        pcap_count = len(getattr(self.app, "project_recent_pcap_rows", []) or [])
        activity_count = len(getattr(self.app, "project_activity_rows", []) or [])

        if hasattr(self.app, "lbl_recent_json_count"):
            self.app.lbl_recent_json_count.setText(f"{json_count:,} JSON files")
            if json_count and json_rows:
                newest = self._short_text(json_rows[0].get("name") or "-")
                self.app.lbl_recent_json_detail.setText(f"Most recent: {newest}")
            elif json_count:
                self.app.lbl_recent_json_detail.setText(f"{json_count:,} JSON files indexed")
            else:
                self.app.lbl_recent_json_detail.setText("No JSON files saved for this project.")

        if hasattr(self.app, "lbl_recent_pcap_count"):
            pcap_rows = getattr(self.app, "project_recent_pcap_rows", []) or []
            self.app.lbl_recent_pcap_count.setText(f"{pcap_count:,} PCAP days")
            if pcap_count and pcap_rows:
                newest = self._short_text(pcap_rows[0].get("name") or "-")
                self.app.lbl_recent_pcap_detail.setText(f"Most recent: {newest}")
            elif pcap_count:
                self.app.lbl_recent_pcap_detail.setText(f"{pcap_count:,} PCAP days saved")
            else:
                self.app.lbl_recent_pcap_detail.setText("No PCAP days saved for this project.")

        if hasattr(self.app, "lbl_recent_activity_count"):
            activity_rows = getattr(self.app, "project_activity_rows", []) or []
            self.app.lbl_recent_activity_count.setText(f"{activity_count:,} events")
            if activity_count and activity_rows:
                newest = self._short_text(activity_rows[0].get("event") or "-")
                self.app.lbl_recent_activity_detail.setText(f"Latest: {newest}")
            elif activity_count:
                self.app.lbl_recent_activity_detail.setText(f"{activity_count:,} recent events")
            else:
                self.app.lbl_recent_activity_detail.setText("No project activity yet.")

    def refresh_case_dashboard(self) -> None:
        if not hasattr(self.app, "lbl_case_dashboard_title"):
            return

        self._refresh_active_case_header()
        self._update_selection_panel()

    def _refresh_active_case_header(self) -> None:
        pid = self.app.current_project_id
        if pid is None:
            self.app.lbl_case_dashboard_title.setText("Active case: (none)")
            self.app.lbl_case_dashboard_subject.setText(
                "Open a project as the active case to work with JSON, PCAP and notes."
            )
            return

        project = get_project(pid)
        if not project:
            self.app.lbl_case_dashboard_title.setText("Active case: (none)")
            self.app.lbl_case_dashboard_subject.setText("The active project could not be loaded.")
            return

        self.app.lbl_case_dashboard_title.setText(f"Active case: {project.name}")
        description = (project.description or "").strip()
        if description:
            self.app.lbl_case_dashboard_subject.setText(description)
            self.app.lbl_case_dashboard_subject.show()
        else:
            self.app.lbl_case_dashboard_subject.clear()
            self.app.lbl_case_dashboard_subject.hide()

    def _update_selection_panel(self) -> None:
        if not hasattr(self.app, "lbl_project_selection_title"):
            return

        active_id = self.app.current_project_id
        item = self.app.projects_list.currentItem()
        if item is None and active_id is not None:
            for idx in range(self.app.projects_list.count()):
                candidate = self.app.projects_list.item(idx)
                if int(candidate.data(Qt.UserRole)) == int(active_id):
                    item = candidate
                    break

        if not item:
            if active_id is not None:
                project = get_project(active_id)
                if project:
                    self._fill_project_selection_panel(project, active=True)
                    return
            self.app.lbl_project_selection_title.setText("Select a project")
            self.app.lbl_project_selection_state.hide()
            self.app.btn_open_project.setEnabled(False)
            self.app.btn_edit_project.setEnabled(False)
            self.app.btn_delete_project.setEnabled(False)
            return

        pid = int(item.data(Qt.UserRole))
        project = get_project(pid)
        if not project:
            return

        self._fill_project_selection_panel(project, active=(self.app.current_project_id == pid))

    def _fill_project_selection_panel(self, project, *, active: bool) -> None:
        from core.case_metadata import (
            format_active_order_validity,
            format_klasa_all,
            format_order_validity_history,
            format_urbroj_all,
            load_case_metadata,
        )

        metadata = load_case_metadata(project.id)
        klasa_all = format_klasa_all(metadata)
        urbroj_all = format_urbroj_all(metadata)
        validity_active = format_active_order_validity(metadata)
        validity_history = format_order_validity_history(metadata)
        info = [
            f"ID: {project.id}",
            f"Subject: {subject_display_label(project)}",
            f"Identifiers: {project_identifiers_text(project)}",
            f"Klasa (all): {klasa_all}",
            f"Urbroj (all): {urbroj_all}",
            f"Order validity (active): {validity_active}",
        ]
        if validity_history:
            info.append(f"Earlier validity periods: {validity_history}")
        if project.subject_oib:
            info.append(f"OIB: {project.subject_oib}")
        info.append("")
        if project.description:
            info.extend(["Description:", project.description, ""])
        if project.target_identifier or project.target_type:
            info.append(f"Legacy target fallback: {target_display_label(project)}")
        info.extend(["", f"Workspace: {project.base_folder or '-'}", f"Created / updated: {project.created_at} / {project.updated_at}"])
        self.app.projects_info.setText("\n".join(info))
        self.app.lbl_project_selection_title.setText(project.name)
        self.app.btn_edit_project.setEnabled(True)
        self.app.btn_delete_project.setEnabled(True)
        if active:
            self.app.lbl_project_selection_state.setText("Active case")
            self.app.lbl_project_selection_state.show()
            self.app.btn_open_project.setEnabled(False)
        else:
            self.app.lbl_project_selection_state.setText("Preview")
            self.app.lbl_project_selection_state.show()
            self.app.btn_open_project.setEnabled(True)

    def _case_dashboard_warnings(self, project, profile: dict) -> list[str]:
        warnings: list[str] = []
        if project_identifiers_text(project) == "-":
            warnings.append("add known identifiers")
        if not profile.get("dataset_count"):
            warnings.append("no JSON datasets saved")
        if not profile.get("pcap_day_count"):
            warnings.append("no PCAP days saved")

        return warnings

    def activity_label(self, event_type: str, message: str = "") -> str:
        labels = {
            "dataset_loaded": "JSON dataset loaded",
            "pcap_saved": "PCAP saved",
            "pcap_notes_added": "PCAP notes added",
            "finding_created": "Finding created",
            "finding_updated": "Finding updated",
            "finding_deleted": "Finding deleted",
            "case_metadata_mismatch": "Case metadata warning",
            "pcap_batch_finished": "PCAP batch finished",
            "repository_hit": "Repository hit",
            "project_created": "Project created",
            "project_edited": "Project edited",
            "import_period_selected": "Period selected",
            "ai_summary_generated": "AI summary generated",
        }
        label = labels.get(event_type, event_type.replace("_", " ").title())
        detail = Path(message).name if message else ""
        if detail:
            return f"{label}: {detail}"
        return label

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
            self.app.go_to_json_tab(0)
        elif opened == "pcap":
            self.app.go_page(self.app.IDX_PCAP, self.app._nav_pcap)

    
