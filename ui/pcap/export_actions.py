from __future__ import annotations

import hashlib
import os
import re
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QTableView

from core.db import (
    add_activity,
    file_sha256,
    get_project,
    mark_ingest_item,
    save_pcap_period_summary,
    upsert_ingest_items,
)
from core.exporters.pcap_exporter import export_pcap_summary_html
from core.exporters.pcap_metadata_exporter import export_pcap_dns_csv, export_pcap_tls_csv
from core.formatters import format_pcap_datetime, human_bytes
from core.osint.public_ips import collect_public_ips_from_pcap_summary, merge_public_ips_into_profile
from core.pcap_analyzer import build_investigator_view
from core.pcap_period import aggregate_hash_for_paths, capture_span_note, resolve_period_day
from core.workspace import workspace_export_path
from ui.expand_dialogs import open_dict_rows_expand_dialog, open_dict_table_expand_dialog
from ui.table_export import append_table_export_footer


class PcapExportMixin:
    """PCAP table expand dialogs, summary export, project save, and notes blocks."""

    def _open_table_dialog(self, title: str, source_table: QTableView) -> None:
        open_dict_table_expand_dialog(
            self,
            title=title,
            source_table=source_table,
            on_empty=self._info,
            append_export_footer=lambda footer, table: self._append_export_footer(
                footer, title=title, table=table
            ),
        )

    def _append_export_footer(self, footer: QHBoxLayout, *, title: str, table: QTableView) -> None:
        append_table_export_footer(
            self,
            footer,
            title=title,
            table=table,
            project_id=self._current_project_id(),
            category="pcap",
            source_label=self.lbl_file.text() or "",
        )

    def _open_rows_dialog(self, title: str, columns: list[tuple[str, str]], rows: list[dict[str, Any]]) -> None:
        open_dict_rows_expand_dialog(
            self,
            title=title,
            columns=columns,
            rows=rows,
            on_empty=self._info,
            append_export_footer=lambda footer, table: self._append_export_footer(
                footer, title=title, table=table
            ),
            hint_text=(
                "Click an indicator above to inspect the underlying rows. "
                "Sort columns or right-click to copy values."
            ),
        )

    def _format_pcap_time(self, value: Any) -> str:
        text = format_pcap_datetime(value)
        return text or "-"

    def _format_pcap_range(self, start: Any, end: Any) -> str:
        return f"{self._format_pcap_time(start)} - {self._format_pcap_time(end)}"

    def _export_full_metadata(self, kind: str) -> None:
        if not getattr(self, "summary", None):
            self._info("PCAP export", "Open a PCAP file first.")
            return

        project = get_project(self._current_project_id()) if self._current_project_id() is not None else None
        default_name = f"pcap_{kind}_full_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        default_path = (
            str(workspace_export_path(project.base_folder, default_name, category="pcap"))
            if project and project.base_folder
            else default_name
        )

        file_path, _selected = QFileDialog.getSaveFileName(
            self,
            f"Export full {kind.upper()} metadata",
            default_path,
            "CSV files (*.csv)",
        )
        if not file_path:
            return

        try:
            if kind == "dns":
                row_count = export_pcap_dns_csv(file_path, self.summary)
                label = "DNS queries"
            elif kind == "tls":
                row_count = export_pcap_tls_csv(file_path, self.summary)
                label = "TLS SNI hosts"
            else:
                raise ValueError(f"Unsupported metadata export: {kind}")
            self._info(
                "PCAP export",
                f"Exported {row_count:,} {label}.",
                f"File:\n{file_path}",
            )
        except Exception as exc:
            self._error("PCAP export failed", str(exc))

    def _open_metadata_export_menu(self) -> None:
        from ui.export_menu import popup_labeled_menu

        popup_labeled_menu(
            self.btn_export_metadata,
            [
                ("Export DNS CSV", lambda: self._export_full_metadata("dns")),
                ("Export TLS CSV", lambda: self._export_full_metadata("tls")),
            ],
        )

    def export_summary(self):
        if not self.summary:
            self._info("PCAP export", "Open a PCAP file first.")
            return

        default_name = Path(self.summary.file_name).with_suffix(".pcap-summary.html").name
        project = get_project(self._current_project_id()) if self._current_project_id() is not None else None
        default_path = (
            str(workspace_export_path(project.base_folder, default_name, category="pcap"))
            if project and project.base_folder
            else default_name
        )
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export PCAP summary",
            default_path,
            "HTML files (*.html)",
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".html"):
            file_path += ".html"

        try:
            export_pcap_summary_html(
                file_path,
                self.summary,
                project=project,
                project_name=getattr(self.app, "current_project_name", "") or "",
            )
            webbrowser.open(Path(file_path).resolve().as_uri())
        except Exception as exc:
            self._error("PCAP export failed", str(exc))

    def save_to_project(self):
        if not self.btn_save_project.isEnabled() or self._current_period_already_saved():
            return
        self._save_current_to_project(show_dialog=True, check_device=True)

    def _save_current_to_project(
        self,
        *,
        show_dialog: bool = True,
        check_device: bool = True,
        refresh_ui: bool = True,
    ) -> bool:
        if not self.summary:
            if show_dialog:
                self._info("PCAP", "Open a PCAP file first.")
            return False

        if self._current_period_already_saved():
            self._sync_save_period_button(saved=True)
            return False

        project_id = self._current_project_id()
        if project_id is None:
            if show_dialog:
                self._info(
                    "PCAP",
                    "Open an active project first.",
                    "PCAP analyses must be tied to a project before they can be used in notes or future activity profiles.",
                )
            return False
        if not self._ensure_project_workspace():
            return False

        if check_device and not self._confirm_project_device_match(project_id):
            return False

        try:
            source_paths = list(getattr(self.summary, "source_paths", None) or [])
            if not source_paths and getattr(self.summary, "file_path", ""):
                source_paths = [self.summary.file_path]
            source_count = len(source_paths)
            investigator = build_investigator_view(self.summary)
            plain = str(investigator.get("plain_summary") or "")
            period_day = resolve_period_day(
                active_day=self._pcap_active_day,
                file_paths=source_paths,
                first_seen=self.summary.first_seen,
                last_seen=self.summary.last_seen,
            )
            span = capture_span_note(self.summary.first_seen, self.summary.last_seen, period_day=period_day)
            if span:
                plain = f"{plain}\n{span}"

            if source_count > 1:
                digest = aggregate_hash_for_paths(source_paths)
                saved_path = self.summary.file_path or self.summary.file_name
                saved_name = self.summary.file_name or f"{source_count:,} PCAP files"
                source_id = save_pcap_period_summary(
                    project_id,
                    period_day=period_day,
                    file_path=saved_path,
                    file_name=saved_name,
                    file_sha256_value=digest,
                    file_size=self.summary.file_size,
                    format=self.summary.format,
                    packet_count=self.summary.packet_count,
                    wire_bytes=self.summary.wire_bytes,
                    first_seen=self.summary.first_seen,
                    last_seen=self.summary.last_seen,
                    duration_seconds=self.summary.duration_seconds,
                    likely_device_ip=self.summary.likely_device_ip,
                    summary_text=plain,
                )
            else:
                saved_path = self.summary.file_path
                saved_name = self.summary.file_name
                digest = file_sha256(saved_path)
                source_id = save_pcap_period_summary(
                    project_id,
                    period_day=period_day or resolve_period_day(file_paths=[saved_path], first_seen=self.summary.first_seen),
                    file_path=saved_path,
                    file_name=saved_name,
                    file_sha256_value=digest,
                    file_size=self.summary.file_size,
                    format=self.summary.format,
                    packet_count=self.summary.packet_count,
                    wire_bytes=self.summary.wire_bytes,
                    first_seen=self.summary.first_seen,
                    last_seen=self.summary.last_seen,
                    duration_seconds=self.summary.duration_seconds,
                    likely_device_ip=self.summary.likely_device_ip,
                    summary_text=plain,
                )
            self._mark_saved_source_paths_done(project_id, source_paths)
            bound_project_ip = self._bind_project_device_ip_if_empty(project_id)
            merge_public_ips_into_profile(
                project_id,
                collect_public_ips_from_pcap_summary(self.summary),
                source="pcap",
            )
        except Exception as exc:
            if show_dialog:
                self._error("PCAP", "Failed to save PCAP analysis to project.", str(exc))
            return False

        self._saved_source_id = source_id
        self._sync_save_period_button(saved=True, hide=not show_dialog)
        if refresh_ui:
            self._refresh_project_after_batch()
        details = [f"Source id: {source_id}"]
        if bound_project_ip:
            details.append(f"Project known IP was set to: {bound_project_ip}")
        if show_dialog:
            self._info("PCAP", "PCAP analysis saved to active project.", "\n".join(details))
        if not refresh_ui:
            self._refresh_activity()
        return True

    def _aggregate_source_hash(self, source_paths: list[str]) -> str:
        digest = hashlib.sha256()
        for raw_path in sorted(str(path) for path in source_paths if str(path or "").strip()):
            path = Path(raw_path)
            try:
                stat = path.stat()
                marker = f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}"
            except Exception:
                marker = f"{raw_path}|missing"
            digest.update(marker.encode("utf-8", errors="replace"))
            digest.update(b"\n")
        return "aggregate:" + digest.hexdigest()

    def _mark_saved_source_paths_done(self, project_id: int, source_paths: list[str]) -> None:
        paths = [Path(str(path)) for path in source_paths if str(path or "").strip()]
        rows = []
        for path in paths:
            try:
                file_size = path.stat().st_size if path.is_file() else 0
            except Exception:
                file_size = 0
            rows.append({
                "file_path": str(path),
                "file_name": path.name,
                "file_type": "pcap",
                "file_size": file_size,
                "observed_date": self._observed_date_for_source_path(path),
            })

        if not rows:
            return

        source_root = self._common_source_root(paths)
        upsert_ingest_items(project_id, source_root, rows)
        for row in rows:
            mark_ingest_item(project_id, row["file_path"], "done", "")

    def _common_source_root(self, paths: list[Path]) -> str:
        parents = [str(path.parent) for path in paths]
        if not parents:
            return ""
        try:
            return str(Path(os.path.commonpath(parents)))
        except Exception:
            return parents[0]

    def _observed_date_for_source_path(self, path: Path) -> str:
        text = str(path)
        match = re.search(r"(20\d{6})", text)
        if match:
            raw = match.group(1)
            return f"{raw[:4]}-{raw[4:6]}-{raw[6:8]}"
        first_seen = str(getattr(self.summary, "first_seen", "") or "")
        if len(first_seen) >= 10 and first_seen[4] == "-" and first_seen[7] == "-":
            return first_seen[:10]
        return ""

    def add_summary_to_notes(self):
        if not self.summary:
            self._info("Notes", "Open a PCAP file first.")
            return

        project_id = self._current_project_id()
        if project_id is None:
            self._info("Notes", "Open an active project first.")
            return

        block = self._make_notes_block()
        if not block:
            return

        try:
            if hasattr(self.app, "notes_page"):
                self.app.notes_page.append_block(block)
            else:
                existing = self.app.txt_notes.toPlainText() or ""
                if existing.strip():
                    if not existing.endswith("\n"):
                        existing += "\n"
                    new_text = existing + "\n" + block
                else:
                    new_text = block
                self.app.txt_notes.setPlainText(new_text)
            self.app._notes_dirty = True
            self.app.notes_controller.flush()
            add_activity(project_id, "pcap_notes_added", self.summary.file_name)
            self._refresh_activity()
        except Exception as exc:
            self._error("Notes", "Failed to add PCAP summary to notes.", str(exc))
            return

        if hasattr(self.app, "go_to_notes"):
            self.app.go_to_notes()
        self._info("Notes", "PCAP summary added to project notes.")

    def _make_notes_block(self) -> str:
        if not self.summary:
            return ""

        investigator = build_investigator_view(self.summary)
        ts = datetime.now().strftime("%d.%m.%Y. %H:%M:%S")
        lines = [
            f"[PCAP summary added: {ts}]",
            f"File: {self.summary.file_name}",
            f"Source: {self.summary.file_path}",
            f"Device IP: {self.summary.likely_device_ip or '-'}",
            f"Capture period: {self._format_pcap_range(self.summary.first_seen, self.summary.last_seen)}",
            f"Packets: {self.summary.packet_count:,}",
            f"Volume: {human_bytes(self.summary.wire_bytes, precision=2)}",
            "",
            str(investigator.get("plain_summary") or ""),
            "",
            "Key points:",
        ]
        for point in investigator.get("key_points") or []:
            lines.append(f"- {point}")
        if self.summary.communication_rows:
            lines.extend([
                "",
                "Communication highlights:",
            ])
            for row in self.summary.communication_rows or []:
                lines.append(
                    f"- {row.get('service')}: {row.get('activity_type')} "
                    f"({row.get('confidence')} confidence) - {row.get('evidence')}"
                )
        lines.extend([
            "",
            "Artifact categories:",
        ])
        for row in self._artifact_category_counts():
            lines.append(f"- {row['category']}: {row['count']}")
        lines.extend([
            "",
            "Limitations:",
        ])
        for item in investigator.get("limitations") or []:
            lines.append(f"- {item}")
        lines.append("-" * 60)
        return "\n".join(lines) + "\n"

    def _artifact_category_counts(self) -> list[dict[str, Any]]:
        if not self.summary:
            return []
        counts: dict[str, int] = {}
        for artifact in self.summary.artifacts or []:
            category = str(artifact.get("category") or "Other")
            counts[category] = counts.get(category, 0) + 1
        return [
            {"category": category, "count": count}
            for category, count in sorted(counts.items())
        ]
