from __future__ import annotations

from core.import_pause import ImportPauseGate
from ui.import_progress_dialog import ImportProgressDialog, ImportProgressView


class ImportProgressMixin:
    """Unified non-modal import progress dialog with pause/hide."""

    def _init_import_progress_state(self) -> None:
        self._import_pause_gate = ImportPauseGate()
        self._import_session_active = False
        self._import_progress_dialog: ImportProgressDialog | None = None
        self._import_progress_hidden = False
        self._import_folder_path = ""
        self._import_json_note = ""
        self._import_pcap_note = ""
        self._import_cancel_requested = False
        self._import_session_registered = False
        self._import_session_paths: list[str] = []

    def import_session_active(self) -> bool:
        return bool(getattr(self, "_import_session_active", False))

    def import_pause_gate(self) -> ImportPauseGate:
        return self._import_pause_gate

    def begin_import_session(self, folder: str, project_name: str = "") -> None:
        self._import_session_active = True
        self._import_progress_hidden = False
        self._import_folder_path = str(folder or "")
        self._import_json_note = ""
        self._import_pcap_note = ""
        self._import_cancel_requested = False
        self._import_session_registered = False
        self._import_session_paths = []
        self._import_phase = "Preparing imported evidence..."
        self._import_detail = ""
        self._import_current = 0
        self._import_total = 0
        self._import_indeterminate = True
        self._import_pause_gate.reset()
        self._ensure_import_progress_dialog()
        self._refresh_import_progress_dialog()
        self._sync_import_progress_chrome()

    def end_import_session(self) -> None:
        if not self.import_session_active():
            self._close_import_progress_dialog()
            return
        self._import_session_active = False
        self._import_pause_gate.abort()
        self._close_import_progress_dialog()
        self._sync_import_progress_chrome()

    def update_import_progress(
        self,
        *,
        phase: str | None = None,
        detail: str = "",
        current: int | None = None,
        total: int | None = None,
        indeterminate: bool | None = None,
        json_note: str | None = None,
        pcap_note: str | None = None,
    ) -> None:
        if not self.import_session_active():
            return
        self._refresh_import_progress_dialog(
            phase=phase,
            detail=detail,
            current=current,
            total=total,
            indeterminate=indeterminate,
            json_note=json_note,
            pcap_note=pcap_note,
        )

    def route_json_load_progress(
        self,
        current: int,
        total: int,
        file_name: str,
        *,
        period_label: str = "",
    ) -> bool:
        if not self.import_session_active():
            return False
        detail = file_name or period_label or "Loading JSON files..."
        if total > 1:
            detail = f"{current} / {total} — {detail}"
        self.update_import_progress(
            phase="Loading JSON flows",
            detail=detail,
            current=current,
            total=total,
            indeterminate=total <= 1,
        )
        return True

    def route_pcap_batch_progress(
        self,
        processed: int,
        total: int,
        *,
        failed: int = 0,
        current_file: str = "",
    ) -> bool:
        if not self.import_session_active():
            return False
        detail = current_file or "Analyzing PCAP files..."
        if total > 0:
            detail = f"{processed} / {total} — {detail}"
        if failed:
            detail = f"{detail} ({failed:,} failed)"
        self.update_import_progress(
            phase="PCAP analysis",
            detail=detail,
            current=processed,
            total=total,
            indeterminate=total <= 1,
        )
        return True

    def toggle_import_pause(self) -> None:
        if not self.import_session_active():
            return
        if self._import_pause_gate.is_aborted():
            return
        if self._import_pause_gate.is_paused():
            self._import_pause_gate.resume()
        else:
            self._import_pause_gate.pause()
        self._refresh_import_progress_dialog()

    def cancel_import_session(self) -> None:
        if not self.import_session_active():
            return
        if not self.app._confirm_dialog(
            title="Cancel import",
            message="Stop the import and remove evidence indexed in this session?",
            details=(
                "Files registered from this folder import will be removed from the project "
                "(ingest index, dataset registration, and PCAP summaries for those files)."
            ),
            ok_text="Cancel import",
            cancel_text="Keep importing",
            width=560,
        ):
            return

        self._import_cancel_requested = True
        self._import_pause_gate.abort()
        self._stop_import_workers()

        project_id = getattr(self.app, "current_project_id", None)
        folder = str(getattr(self, "_import_folder_path", "") or "")
        if project_id is not None and self._import_session_registered and folder:
            from core.db import rollback_project_import

            rollback_project_import(
                int(project_id),
                folder,
                file_paths=list(self._import_session_paths),
            )
            if hasattr(self, "_invalidate_ingest_day_groups_cache"):
                self._invalidate_ingest_day_groups_cache()
            if hasattr(self.app, "projects_ui_controller"):
                self.app.projects_ui_controller.refresh_recent_datasets(project_id)
                self.app.projects_ui_controller.refresh_case_dashboard()
            if hasattr(self.app, "refresh_activity_profile_ui"):
                self.app.refresh_activity_profile_ui()

        self._import_plan = None
        if hasattr(self, "_reset_import_finalize_state"):
            self._reset_import_finalize_state()
        if hasattr(self, "reset_dataset_views"):
            self.reset_dataset_views(preserve_import_session=False)
        else:
            self.end_import_session()
        self.app._message_dialog("Import evidence", "Import was cancelled.", width=420)

    def _stop_import_workers(self) -> None:
        if hasattr(self, "shutdown_background_tasks"):
            self.shutdown_background_tasks()
        pcap_page = getattr(self.app, "pcap_page", None)
        if pcap_page is None:
            return
        batch_runner = getattr(pcap_page, "_batch_runner", None)
        if batch_runner is not None and batch_runner.is_running():
            batch_runner.stop()
        from ui.thread_utils import stop_qthread

        stop_qthread(getattr(pcap_page, "_thread", None))
        pcap_page._thread = None
        pcap_page._worker = None

    def hide_import_progress_dialog(self) -> None:
        if self._import_progress_dialog is not None:
            self._import_progress_dialog.hide()
        self._import_progress_hidden = True
        self._sync_import_progress_chrome()

    def show_import_progress_dialog(self) -> None:
        if not self.import_session_active():
            return
        self._ensure_import_progress_dialog()
        self._import_progress_hidden = False
        if self._import_progress_dialog is not None:
            self._import_progress_dialog.show()
            self._import_progress_dialog.raise_()
            self._import_progress_dialog.activateWindow()
        self._sync_import_progress_chrome()

    def _ensure_import_progress_dialog(self) -> None:
        if self._import_progress_dialog is not None:
            if not self._import_progress_hidden:
                self._import_progress_dialog.show()
            return
        dialog = ImportProgressDialog(self.app)
        dialog.hide_requested.connect(self.hide_import_progress_dialog)
        dialog.pause_toggled.connect(self.toggle_import_pause)
        dialog.cancel_requested.connect(self.cancel_import_session)
        self._import_progress_dialog = dialog
        if not self._import_progress_hidden:
            dialog.show()

    def _close_import_progress_dialog(self) -> None:
        dialog = self._import_progress_dialog
        self._import_progress_dialog = None
        self._import_progress_hidden = False
        if dialog is not None:
            dialog.hide()
            dialog.deleteLater()

    def _refresh_import_progress_dialog(
        self,
        *,
        phase: str | None = None,
        detail: str | None = None,
        current: int | None = None,
        total: int | None = None,
        indeterminate: bool | None = None,
        json_note: str | None = None,
        pcap_note: str | None = None,
    ) -> None:
        if not self.import_session_active():
            return
        if phase is not None:
            self._import_phase = str(phase)
        if detail is not None:
            self._import_detail = str(detail)
        if current is not None:
            self._import_current = int(current)
        if total is not None:
            self._import_total = int(total)
        if indeterminate is not None:
            self._import_indeterminate = bool(indeterminate)
        if json_note is not None:
            self._import_json_note = str(json_note)
        if pcap_note is not None:
            self._import_pcap_note = str(pcap_note)

        dialog = self._import_progress_dialog
        if dialog is None:
            return

        view = ImportProgressView(
            project_name=getattr(self.app, "current_project_name", "") or "",
            folder_path=self._import_folder_path,
            phase=getattr(self, "_import_phase", "Import in progress..."),
            detail=getattr(self, "_import_detail", ""),
            json_note=self._import_json_note,
            pcap_note=self._import_pcap_note,
            current=getattr(self, "_import_current", 0),
            total=getattr(self, "_import_total", 0),
            indeterminate=getattr(self, "_import_indeterminate", True),
            paused=self._import_pause_gate.is_paused(),
        )
        dialog.apply_view(view)
        self._sync_import_progress_chrome()

    def _sync_import_progress_chrome(self) -> None:
        active = self.import_session_active()
        hidden = bool(getattr(self, "_import_progress_hidden", False))
        btn = getattr(self.app, "btn_show_import_progress", None)
        if btn is not None:
            btn.setVisible(active and hidden)
            if active:
                btn.setText("Show import progress")
        sidebar_btn = getattr(self.app, "btn_import_progress", None)
        if sidebar_btn is not None:
            sidebar_btn.setVisible(active)
            if active:
                phase = str(getattr(self, "_import_phase", "") or "Import in progress").strip()
                short = phase if len(phase) <= 14 else f"{phase[:11]}…"
                sidebar_btn.setText(short or "Import…")
