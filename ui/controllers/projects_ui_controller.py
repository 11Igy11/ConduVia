from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QListWidgetItem

from core.db import (
    create_project,
    list_projects,
    get_project,
    delete_project,
    get_project_notes,
    list_recent_datasets,
    list_pcap_sources,
    list_ingest_items,
    list_activity,
    list_findings,
    touch_project,
    update_project,
)
from core.formatters import format_duration_compact_ms, format_pcap_datetime, human_bytes
from core.project_identity import project_identifiers_text, subject_display_label
from core.project_datasets import count_project_json_datasets, list_project_json_dataset_files
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

    def refresh_projects(self):
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
        self._refresh_project_launcher_cards()
        self.refresh_case_dashboard(None)
        self.app.refresh_activity_profile_ui()
        self.app.refresh_activity_ui_for_project(None)

    def _short_text(self, value: str, limit: int = 54) -> str:
        text = (value or "").strip()
        if len(text) <= limit:
            return text
        return text[: max(0, limit - 3)] + "..."

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
        self.sync_project_workspace(pid)
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
                self.app.go_to_json_tab(0)

    def on_project_selected_preview(self):
        item = self.app.projects_list.currentItem()
        if not item:
            self.app.projects_info.setText("Select a project to see details.")
            self.app.project_recent_json_rows = []
            self.app.project_recent_pcap_rows = []
            self.app.project_activity_rows = []
            self._refresh_project_launcher_cards()
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
            self.app.lbl_active_project.setText(f"Active project: {name}")
            self.app.lbl_project_banner.setText(f"Project: {name}")
            self.app.refresh_activity_profile_ui()

    def set_active_project(self, project_id: int):
        touch_project(project_id)
        p = get_project(project_id)
        if not p:
            self.app._message_dialog("Project", "Project not found.", width=400)
            return
        
        project_changed = self.app.current_project_id != p.id

        if project_changed:
            self.app.clear_dataset_context()
            if hasattr(self.app, "activity_profile_page"):
                self.app.activity_profile_page.invalidate_project_cache()

        self.app.current_project_id = p.id
        self.app.current_project_name = p.name

        self.app.lbl_active_project.setText(f"Active project: {p.name}")
        self.app.lbl_project_banner.setText(f"Project: {p.name}")

        self.refresh_recent_datasets(p.id)
        self.refresh_case_dashboard(p.id)
        self.app.refresh_findings_ui()
        self.app.refresh_notes_ui()
        self.app.refresh_activity_profile_ui()
        self.sync_project_workspace(p.id)
        if hasattr(self.app, "dataset_controller"):
            self.app.dataset_controller.refresh_project_behavior_index(p.id)

    def sync_project_workspace(self, project_id: int | None) -> None:
        if project_id is None:
            return

        project = get_project(project_id)
        if not project or not (project.base_folder or "").strip():
            return

        json_rows = [
            row for row in list_project_json_dataset_files(project_id, limit=500)
            if row.get("status") == "Available"
        ]
        json_datasets = [str(row.get("path") or "") for row in json_rows if row.get("path")]
        pcap_sources = []
        for source in list_pcap_sources(project_id, limit=500):
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
        self.app.project_recent_json_total_count = count_project_json_datasets(project_id, limit=50000)
        self.app.project_recent_json_rows = list_project_json_dataset_files(project_id, limit=50000)[:100]

        self.app.project_recent_pcap_rows = self._project_pcap_day_rows(project_id)

        activity_rows = list_activity(project_id, limit=500)
        self.app.project_activity_rows = []
        for row in activity_rows:
            event = self.activity_label(str(row["event_type"] or ""), str(row["message"] or ""))
            self.app.project_activity_rows.append({
                "created_at": str(row["created_at"] or ""),
                "event": event,
                "detail": str(row["message"] or ""),
            })

        self._refresh_project_launcher_cards()

    def _project_pcap_day_rows(self, project_id: int) -> list[dict]:
        ingest_days: dict[str, list[str]] = {}
        for item in list_ingest_items(project_id, file_type="pcap", status="done", limit=50000):
            day = str(item.observed_date or "").strip() or self._date_from_name(item.file_name) or "undated"
            ingest_days.setdefault(day, [])
            if item.file_path and Path(item.file_path).is_file() and item.file_path not in ingest_days[day]:
                ingest_days[day].append(item.file_path)

        source_days: dict[str, dict] = {}
        for source in list_pcap_sources(project_id, limit=50000):
            day = self._date_from_pcap_source(source) or self._date_from_name(source.file_name) or "undated"
            row = source_days.setdefault(day, {
                "packet_count": 0,
                "wire_bytes": 0,
                "first_seen": "",
                "last_seen": "",
                "device_ips": {},
                "paths": [],
                "source_count": 0,
            })
            row["source_count"] += 1
            row["packet_count"] += int(source.packet_count or 0)
            row["wire_bytes"] += int(source.wire_bytes or 0)
            row["first_seen"] = self._min_text_time(row["first_seen"], source.first_seen)
            row["last_seen"] = self._max_text_time(row["last_seen"], source.last_seen)
            if source.likely_device_ip:
                row["device_ips"][source.likely_device_ip] = row["device_ips"].get(source.likely_device_ip, 0) + 1
            if source.file_path and Path(source.file_path).is_file() and source.file_path not in row["paths"]:
                row["paths"].append(source.file_path)

        all_days = set(ingest_days) | set(source_days)
        rows: list[dict] = []
        for day in sorted(all_days, reverse=True):
            data = source_days.get(day, {})
            paths = list(ingest_days.get(day) or []) + list(data.get("paths") or [])
            seen_paths: set[str] = set()
            paths = [
                path
                for path in paths
                if path and Path(path).is_file() and not (path in seen_paths or seen_paths.add(path))
            ]
            file_count = len(paths) or int(data.get("source_count") or 0) or 1
            device_ips = data.get("device_ips") or {}
            device_ip = "-"
            if device_ips:
                device_ip = sorted(device_ips.items(), key=lambda item: (-item[1], item[0]))[0][0]
            period = " - ".join(
                value
                for value in (
                    format_pcap_datetime(data.get("first_seen", "")),
                    format_pcap_datetime(data.get("last_seen", "")),
                )
                if value
            )
            rows.append({
                "name": f"{self._display_day(day)} ({file_count:,} PCAP files)",
                "file_count": file_count,
                "packets": f"{int(data.get('packet_count') or 0):,}",
                "volume": human_bytes(int(data.get("wire_bytes") or 0), precision=2),
                "device_ip": device_ip,
                "period": period or "-",
                "path": paths[0] if len(paths) == 1 else "",
                "paths": paths,
                "day": day,
            })
        return rows[:500]

    def _date_from_pcap_source(self, source) -> str:
        raw = str(source.first_seen or source.last_seen or "").strip()
        if len(raw) >= 10 and raw[4] == "-" and raw[7] == "-":
            return raw[:10]
        return ""

    def _date_from_name(self, value: str) -> str:
        text = str(value or "")
        for token in text.replace("\\", "_").replace("/", "_").split("_"):
            if len(token) >= 8 and token[:8].isdigit():
                raw = token[:8]
                return f"{raw[:4]}-{raw[4:6]}-{raw[6:8]}"
        return ""

    def _display_day(self, day: str) -> str:
        if day == "undated":
            return "Undated"
        if len(day) == 10 and day[4] == "-" and day[7] == "-":
            return f"{day[8:10]}/{day[5:7]}/{day[:4]}"
        return day

    def _min_text_time(self, current: str, candidate: str) -> str:
        if not candidate:
            return current or ""
        if not current:
            return candidate
        return min(str(current), str(candidate))

    def _max_text_time(self, current: str, candidate: str) -> str:
        if not candidate:
            return current or ""
        if not current:
            return candidate
        return max(str(current), str(candidate))

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
            self.app.lbl_recent_json_count.setText(f"{json_count:,} JSON datasets")
            if json_count:
                newest_row = next((row for row in json_rows if row.get("status") == "Available"), json_rows[0])
                newest = self._short_text(newest_row.get("name") or "-")
                self.app.lbl_recent_json_detail.setText(f"Most recent: {newest}")
            else:
                self.app.lbl_recent_json_detail.setText("No JSON datasets saved for this project.")

        if hasattr(self.app, "lbl_recent_pcap_count"):
            self.app.lbl_recent_pcap_count.setText(f"{pcap_count:,} PCAP days")
            if pcap_count:
                newest = self._short_text(self.app.project_recent_pcap_rows[0].get("name") or "-")
                self.app.lbl_recent_pcap_detail.setText(f"Most recent: {newest}")
            else:
                self.app.lbl_recent_pcap_detail.setText("No PCAP days saved for this project.")

        if hasattr(self.app, "lbl_recent_activity_count"):
            self.app.lbl_recent_activity_count.setText(f"{activity_count:,} events")
            if activity_count:
                newest = self._short_text(self.app.project_activity_rows[0].get("event") or "-")
                self.app.lbl_recent_activity_detail.setText(f"Latest: {newest}")
            else:
                self.app.lbl_recent_activity_detail.setText("No project activity yet.")

    def refresh_case_dashboard(self, project_id: int | None):
        if not hasattr(self.app, "lbl_case_dashboard_title"):
            return

        if project_id is None:
            self.app.lbl_case_dashboard_title.setText("Case Dashboard")
            self.app.lbl_case_dashboard_subject.setText("Select a project to see case context.")
            for idx, title in enumerate(("JSON Datasets", "PCAP Days", "Findings", "Device IPs")):
                self.app.case_metric_cards[idx].setText(f"{title}: 0")
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
            ("JSON Datasets", profile.get("dataset_count", 0)),
            ("PCAP Days", profile.get("pcap_day_count", 0)),
            ("Findings", profile.get("finding_count", 0)),
            ("Device IPs", len(profile.get("pcap_device_ips") or {})),
        ]
        for idx, (title, value) in enumerate(values):
            self.app.case_metric_cards[idx].setText(f"{title}: {value}")

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

    
