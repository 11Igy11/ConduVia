from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from ui.buttons import make_dialog_button


@dataclass
class ImportProgressView:
    project_name: str = ""
    folder_path: str = ""
    phase: str = "Preparing import..."
    detail: str = ""
    json_note: str = ""
    pcap_note: str = ""
    current: int = 0
    total: int = 0
    indeterminate: bool = True
    paused: bool = False


class ImportProgressDialog(QDialog):
    hide_requested = Signal()
    pause_toggled = Signal()
    cancel_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Import evidence")
        self.setWindowModality(Qt.NonModal)
        self.setMinimumWidth(520)
        self.setMinimumHeight(260)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        self.lbl_project = QLabel("Project: (none)")
        self.lbl_project.setObjectName("HeaderProjectLabel")
        self.lbl_folder = QLabel("")
        self.lbl_folder.setObjectName("Muted")
        self.lbl_folder.setWordWrap(True)

        self.lbl_phase = QLabel("Preparing import...")
        self.lbl_phase.setWordWrap(True)

        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(12)

        self.lbl_detail = QLabel("")
        self.lbl_detail.setObjectName("Muted")
        self.lbl_detail.setWordWrap(True)

        self.lbl_json_note = QLabel("")
        self.lbl_json_note.setObjectName("Muted")
        self.lbl_json_note.setWordWrap(True)

        self.lbl_pcap_note = QLabel("")
        self.lbl_pcap_note.setObjectName("Muted")
        self.lbl_pcap_note.setWordWrap(True)

        root.addWidget(self.lbl_project)
        root.addWidget(self.lbl_folder)
        root.addWidget(self.lbl_phase)
        root.addWidget(self.progress)
        root.addWidget(self.lbl_detail)
        root.addWidget(self.lbl_json_note)
        root.addWidget(self.lbl_pcap_note)
        root.addStretch(1)

        footer = QHBoxLayout()
        footer.addStretch(1)
        self.btn_cancel = make_dialog_button("Cancel import")
        self.btn_pause = make_dialog_button("Pause")
        self.btn_hide = make_dialog_button("Hide")
        footer.addWidget(self.btn_cancel)
        footer.addWidget(self.btn_pause)
        footer.addWidget(self.btn_hide)
        root.addLayout(footer)

        self.btn_cancel.clicked.connect(self.cancel_requested.emit)

        self.btn_hide.clicked.connect(self.hide_requested.emit)
        self.btn_pause.clicked.connect(self.pause_toggled.emit)

    def apply_view(self, view: ImportProgressView) -> None:
        project = (view.project_name or "").strip() or "(none)"
        self.lbl_project.setText(f"Project: {project}")
        folder = (view.folder_path or "").strip()
        self.lbl_folder.setText(f"Folder: {folder}" if folder else "")
        self.lbl_folder.setVisible(bool(folder))

        phase = (view.phase or "").strip() or "Import in progress..."
        if view.paused:
            phase = f"{phase} (paused)"
        self.lbl_phase.setText(phase)

        detail = (view.detail or "").strip()
        self.lbl_detail.setText(detail)
        self.lbl_detail.setVisible(bool(detail))

        json_note = (view.json_note or "").strip()
        self.lbl_json_note.setText(json_note)
        self.lbl_json_note.setVisible(bool(json_note))

        pcap_note = (view.pcap_note or "").strip()
        self.lbl_pcap_note.setText(pcap_note)
        self.lbl_pcap_note.setVisible(bool(pcap_note))

        if view.indeterminate or view.total <= 0:
            self.progress.setRange(0, 0)
        else:
            total = max(1, int(view.total))
            current = max(0, min(int(view.current), total))
            self.progress.setRange(0, total)
            self.progress.setValue(current)

        self.btn_pause.setText("Resume" if view.paused else "Pause")
