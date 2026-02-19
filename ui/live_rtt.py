# ui/live_rtt.py
from __future__ import annotations

from PySide6.QtCore import QProcessEnvironment
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QMessageBox


@dataclass
class LiveRTTStatus:
    running: bool
    ui_up: bool
    has_session: bool
    server_running: bool
    client_running: bool


class LiveRTT(QObject):
    """
    ConduVia launcher for device-activity-tracker (server + client).

    UX/Procedure:
    - Dialog with actions:
        * Start (Reuse session)  -> no popups
        * Start (New login)      -> confirm + reset auth + restart server
        * Open dashboard
        * Stop
    - Stop kills process tree (Windows) to avoid zombie node/npm.

    Reliability:
    - Browser opens ONLY from readiness poll, once per request.
    - Debounce for the sidebar button; dialog actions bypass debounce (force=True).
    """

    def __init__(
        self,
        parent: QObject | None = None,
        qr_timeout_ms: int = 10_000,
        click_debounce_ms: int = 1200,
        ready_poll_ms: int = 450,
    ):
        super().__init__(parent)

        self.qr_timeout_ms = int(qr_timeout_ms)
        self.click_debounce_ms = int(click_debounce_ms)

        # ConduVia root: .../Conduvia
        self.project_dir = Path(__file__).resolve().parent.parent
        self.tracker_dir = self.project_dir / "modules" / "device-activity-tracker"
        self.client_dir = self.tracker_dir / "client"
        self.auth_dir = self.tracker_dir / "auth_info_baileys"

        self.ui_url = "http://localhost:3000"
        self.ui_host = "127.0.0.1"
        self.ui_port = 3000

        self.server_proc: QProcess | None = None
        self.client_proc: QProcess | None = None

        # gating/state
        self._last_click_ts = 0.0
        self._request_id = 0
        self._opened_for_request = -1
        self._open_requested = False
        self._start_mode = "reuse"  # "reuse" | "new"

        # readiness poll
        self._ready_timer = QTimer(self)
        self._ready_timer.setInterval(int(ready_poll_ms))
        self._ready_timer.timeout.connect(self._on_ready_poll)

        # NEW login info timeout (not for reuse)
        self._newlogin_timer = QTimer(self)
        self._newlogin_timer.setSingleShot(True)
        self._newlogin_timer.timeout.connect(self._on_newlogin_timeout)

    # ============================================================
    # Public API
    # ============================================================

    def show_dialog(self) -> None:
        """Small action dialog for Live RTT."""
        # Debounce only the sidebar click that opens the dialog.
        if not self._debounce_ok():
            return

        parent_widget = self._parent_widget()
        status = self.get_status()

        info = [
            "Status:",
            f"- UI: {'UP' if status.ui_up else 'DOWN'}",
            f"- Server: {'RUNNING' if status.server_running else 'STOPPED'}",
            f"- Client: {'RUNNING' if status.client_running else 'STOPPED'}",
            f"- Session: {'FOUND' if status.has_session else 'NOT FOUND'}",
        ]

        msg = QMessageBox(parent_widget)
        msg.setWindowTitle("Live RTT")
        msg.setIcon(QMessageBox.Question)
        msg.setText("Choose an action:")
        msg.setInformativeText("\n".join(info))

        btn_start_reuse = msg.addButton("Start (Reuse session)", QMessageBox.AcceptRole)
        btn_start_new = msg.addButton("Start (New login)", QMessageBox.ActionRole)
        btn_open = msg.addButton("Open dashboard", QMessageBox.ActionRole)
        btn_stop = msg.addButton("Stop", QMessageBox.DestructiveRole)
        msg.addButton("Cancel", QMessageBox.RejectRole)

        msg.exec()
        clicked = msg.clickedButton()

        # IMPORTANT: no early returns between these ifs
        if clicked == btn_start_reuse:
            self.action_start_reuse(force=True)
        elif clicked == btn_start_new:
            self.action_start_new_login(force=True)
        elif clicked == btn_open:
            self.action_open_dashboard(force=True)
        elif clicked == btn_stop:
            self.action_stop(force=True)

    def action_start_reuse(self, force: bool = False) -> None:
        """Start tracker if needed and open dashboard. No popups."""
        if not self._debounce_ok(force=force):
            return

        self._start_mode = "reuse"
        self._request_id += 1
        self._open_requested = True

        self._validate_paths()

        if not self._is_ui_up():
            self._ensure_running(start_client=True)

        self._start_ready_poll()
        self._newlogin_timer.stop()

    def action_start_new_login(self, force: bool = False) -> None:
        """Reset session and restart server (explicit user action)."""
        if not self._debounce_ok(force=force):
            return

        self._validate_paths()

        parent_widget = self._parent_widget()
        confirm = QMessageBox.question(
            parent_widget,
            "Live RTT",
            "New login will reset the current WhatsApp session.\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        self._start_mode = "new"
        self._request_id += 1
        self._open_requested = True

        # Ensure client is running
        if not self._proc_running(self.client_proc):
            self.client_proc = self._start_client()

        # Restart server with clean auth
        self._terminate_process_tree(self.server_proc)
        self.server_proc = None
        self._reset_auth_dir()
        self.server_proc = self._start_server()

        self._start_ready_poll()

        # info timeout only for new login flow
        self._newlogin_timer.stop()
        self._newlogin_timer.start(self.qr_timeout_ms)

    def action_open_dashboard(self, force: bool = False) -> None:
        """Open dashboard (even if already running)."""
        if not self._debounce_ok(force=force):
            return
        QDesktopServices.openUrl(QUrl(self.ui_url))

    def action_stop(self, force: bool = False) -> None:
        """Stop server & client."""
        if not self._debounce_ok(force=force):
            return

        self._open_requested = False
        self._ready_timer.stop()
        self._newlogin_timer.stop()

        self._terminate_process_tree(self.client_proc)
        self._terminate_process_tree(self.server_proc)

        self.client_proc = None
        self.server_proc = None

    # compatibility (your app used .open / .stop earlier)
    def open(self) -> None:
        self.show_dialog()

    def stop(self) -> None:
        self.action_stop(force=True)

    def get_status(self) -> LiveRTTStatus:
        ui_up = self._is_ui_up()
        srun = self._proc_running(self.server_proc)
        crun = self._proc_running(self.client_proc)
        return LiveRTTStatus(
            running=(srun or crun),
            ui_up=ui_up,
            has_session=self._auth_exists_and_nonempty(),
            server_running=srun,
            client_running=crun,
        )

    # ============================================================
    # Internals
    # ============================================================

    def _debounce_ok(self, force: bool = False) -> bool:
        if force:
            return True
        now = time.time() * 1000.0
        if (now - self._last_click_ts) < self.click_debounce_ms:
            return False
        self._last_click_ts = now
        return True

    def _validate_paths(self) -> None:
        if not self.tracker_dir.exists():
            raise FileNotFoundError(f"Tracker folder not found: {self.tracker_dir}")
        if not (self.tracker_dir / "src" / "server.ts").exists():
            raise FileNotFoundError(f"Missing server.ts at: {self.tracker_dir / 'src' / 'server.ts'}")
        if not self.client_dir.exists():
            raise FileNotFoundError(f"Client folder not found: {self.client_dir}")
        if not (self.client_dir / "package.json").exists():
            raise FileNotFoundError(f"Missing client/package.json at: {self.client_dir / 'package.json'}")

    def _parent_widget(self):
        p = self.parent()
        return p if (p is not None and hasattr(p, "winId")) else None

    def _is_ui_up(self) -> bool:
        try:
            with socket.create_connection((self.ui_host, self.ui_port), timeout=0.25):
                return True
        except Exception:
            return False

    def _start_ready_poll(self) -> None:
        if not self._ready_timer.isActive():
            self._ready_timer.start()

    def _on_ready_poll(self) -> None:
        # Browser opens ONLY here, once per request_id
        if self._open_requested and self._is_ui_up():
            if self._opened_for_request != self._request_id:
                self._opened_for_request = self._request_id
                QDesktopServices.openUrl(QUrl(self.ui_url))
            self._ready_timer.stop()

    def _on_newlogin_timeout(self) -> None:
        # Only relevant for NEW login flow
        if self._start_mode != "new":
            return
        if self._auth_exists_and_nonempty():
            return

        parent_widget = self._parent_widget()
        msg = QMessageBox(parent_widget)
        msg.setWindowTitle("Live RTT")
        msg.setIcon(QMessageBox.Information)
        msg.setText("QR code was not detected within the expected time.")
        msg.setInformativeText("You can open the dashboard again, or reset the session.")

        btn_open = msg.addButton("Open dashboard", QMessageBox.AcceptRole)
        btn_reset = msg.addButton("Reset session", QMessageBox.DestructiveRole)
        msg.addButton("Close", QMessageBox.RejectRole)

        msg.exec()
        clicked = msg.clickedButton()

        if clicked == btn_open:
            self.action_open_dashboard(force=True)
            # give it another window
            self._newlogin_timer.start(self.qr_timeout_ms)
        elif clicked == btn_reset:
            self.action_start_new_login(force=True)

    def _proc_running(self, p: QProcess | None) -> bool:
        return p is not None and p.state() != QProcess.NotRunning

    def _ensure_running(self, start_client: bool = True) -> None:
        if not self._proc_running(self.server_proc):
            self.server_proc = self._start_server()
        if start_client and not self._proc_running(self.client_proc):
            self.client_proc = self._start_client()

    def _start_server(self) -> QProcess:
        npx = "npx.cmd" if os.name == "nt" else "npx"
        p = QProcess(self)
        p.setWorkingDirectory(str(self.tracker_dir))
        p.setProgram(npx)
        p.setArguments(["tsx", "src/server.ts"])
        p.start()
        return p

    def _start_client(self) -> QProcess:
        npm = "npm.cmd" if os.name == "nt" else "npm"
        p = QProcess(self)
        p.setWorkingDirectory(str(self.client_dir))
        p.setProgram(npm)
        p.setArguments(["start"])

    #  React dev server does not open browser
        env = QProcessEnvironment.systemEnvironment()
        env.insert("BROWSER", "none")
        p.setProcessEnvironment(env)

        p.start()
        return p


    def _terminate_process_tree(self, p: QProcess | None) -> None:
        if p is None or p.state() == QProcess.NotRunning:
            return

        pid = int(p.processId()) if p.processId() else 0

        p.terminate()
        p.waitForFinished(1500)

        if p.state() != QProcess.NotRunning and os.name == "nt" and pid:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:
                pass
            p.waitForFinished(1500)

        if p.state() != QProcess.NotRunning:
            p.kill()
            p.waitForFinished(1500)

    def _auth_exists_and_nonempty(self) -> bool:
        if not self.auth_dir.exists() or not self.auth_dir.is_dir():
            return False
        try:
            return any(self.auth_dir.iterdir())
        except Exception:
            return False

    def _reset_auth_dir(self) -> None:
        if self.auth_dir.exists():
            shutil.rmtree(self.auth_dir, ignore_errors=True)
