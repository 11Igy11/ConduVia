from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
    QFileDialog,
)

from core.ai.assistant_service import AISettings
from core.db import get_app_settings, set_app_setting
from core.osint.settings import OsintSettings
from ui.buttons import make_action_button, make_dialog_button

SETTINGS_FIELD_HEIGHT = 28
SETTINGS_FIELD_MAX_WIDTH = 360
SETTINGS_PANEL_MAX_WIDTH = 520


def _settings_line_edit(*, placeholder: str = "", password: bool = False, narrow: bool = False) -> QLineEdit:
    edit = QLineEdit()
    edit.setObjectName("SettingsField")
    edit.setPlaceholderText(placeholder)
    edit.setFixedHeight(SETTINGS_FIELD_HEIGHT)
    edit.setMaximumWidth(SETTINGS_FIELD_MAX_WIDTH if not narrow else 120)
    edit.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
    if password:
        edit.setEchoMode(QLineEdit.Password)
    return edit


def _settings_combo_box(*, narrow: bool = False) -> QComboBox:
    combo = QComboBox()
    combo.setObjectName("SettingsField")
    combo.setFixedHeight(SETTINGS_FIELD_HEIGHT)
    combo.setMaximumWidth(120 if narrow else SETTINGS_FIELD_MAX_WIDTH)
    combo.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
    return combo


def _field_group(label_text: str, field: QWidget) -> QWidget:
    host = QWidget()
    layout = QVBoxLayout(host)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(4)
    label = QLabel(label_text)
    label.setObjectName("SettingsFieldLabel")
    label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    layout.addWidget(label)
    layout.addWidget(field)
    return host


def _settings_panel(title: str) -> tuple[QFrame, QVBoxLayout]:
    panel = QFrame()
    panel.setObjectName("ProfilePanel")
    panel.setMaximumWidth(SETTINGS_PANEL_MAX_WIDTH)
    layout = QVBoxLayout(panel)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(12)
    panel_title = QLabel(title)
    panel_title.setObjectName("ProfilePanelTitle")
    layout.addWidget(panel_title)
    return panel, layout


class SettingsPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        outer.addWidget(scroll)

        content = QWidget()
        root = QVBoxLayout(content)
        root.setContentsMargins(24, 0, 24, 16)
        root.setSpacing(16)
        scroll.setWidget(content)

        header = QFrame()
        header.setObjectName("ProfileHero")
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(22, 18, 22, 18)
        title = QLabel("Settings")
        title.setObjectName("ProfileTitle")
        subtitle = QLabel("Application-wide configuration for AI, OSINT and appearance.")
        subtitle.setObjectName("ProfileSubtitle")
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        root.addWidget(header)

        body_row = QHBoxLayout()
        body_row.setSpacing(20)
        body_row.setAlignment(Qt.AlignTop)

        left_col = QVBoxLayout()
        left_col.setSpacing(14)
        left_col.setAlignment(Qt.AlignTop)

        ai_panel, ai_layout = _settings_panel("AI")
        self.edit_ai_url = _settings_line_edit(placeholder="http://localhost:11434")
        self.edit_ai_model = _settings_line_edit(placeholder="llama3")
        self.edit_ai_timeout = _settings_line_edit(placeholder="600", narrow=True)
        ai_layout.addWidget(_field_group("Base URL", self.edit_ai_url))
        ai_layout.addWidget(_field_group("Model", self.edit_ai_model))
        ai_layout.addWidget(_field_group("Timeout (seconds)", self.edit_ai_timeout))
        left_col.addWidget(ai_panel)

        theme_panel, theme_layout = _settings_panel("Appearance")
        self.cmb_theme = _settings_combo_box(narrow=True)
        self.cmb_theme.addItem("Dark", "dark")
        self.cmb_theme.addItem("Light", "light")
        theme_layout.addWidget(_field_group("Theme", self.cmb_theme))
        left_col.addWidget(theme_panel)
        left_col.addStretch(1)

        right_col = QVBoxLayout()
        right_col.setSpacing(14)
        right_col.setAlignment(Qt.AlignTop)

        osint_panel, osint_layout = _settings_panel("OSINT")
        self.edit_vt_key = _settings_line_edit(placeholder="VirusTotal API key", password=True)
        self.edit_shodan_key = _settings_line_edit(placeholder="Shodan API key", password=True)
        osint_layout.addWidget(_field_group("VirusTotal API key", self.edit_vt_key))
        osint_layout.addWidget(_field_group("Shodan API key", self.edit_shodan_key))
        self.btn_import_tac = make_action_button("Import TAC CSV…")
        self.btn_import_tac.setFixedHeight(SETTINGS_FIELD_HEIGHT)
        osint_layout.addWidget(_field_group("IMEI TAC database", self.btn_import_tac))
        self.lbl_tac_status = QLabel("")
        self.lbl_tac_status.setObjectName("ProfileSubtitle")
        self.lbl_tac_status.setWordWrap(True)
        osint_layout.addWidget(self.lbl_tac_status)
        self.btn_import_tac.clicked.connect(self.import_tac_csv)
        right_col.addWidget(osint_panel)

        repository_panel = QFrame()
        repository_panel.setObjectName("ProfilePanel")
        repository_layout = QVBoxLayout(repository_panel)
        repository_layout.setContentsMargins(16, 14, 16, 14)
        repository_layout.setSpacing(12)
        repository_title = QLabel("Repository")
        repository_title.setObjectName("ProfilePanelTitle")
        repository_layout.addWidget(repository_title)
        leaks_hint = QLabel(
            "Import datasets (.txt / .csv / .tsv / .docx) and search them from OSINT → Repository."
        )
        leaks_hint.setObjectName("ProfileSubtitle")
        leaks_hint.setWordWrap(True)
        repository_layout.addWidget(leaks_hint)

        self.list_leak_datasets = QListWidget()
        self.list_leak_datasets.setMinimumHeight(150)
        self.list_leak_datasets.setMaximumHeight(220)
        repository_layout.addWidget(self.list_leak_datasets)

        leaks_buttons = QHBoxLayout()
        leaks_buttons.setSpacing(8)
        self.btn_import_leak = make_action_button("Import dataset…")
        self.btn_delete_leak = make_action_button("Delete selected", destructive=True, toolbar=True)
        self.btn_open_leaks_viewer = make_action_button("Open Repository")
        for button in (self.btn_import_leak, self.btn_delete_leak, self.btn_open_leaks_viewer):
            button.setFixedHeight(SETTINGS_FIELD_HEIGHT)
        leaks_buttons.addWidget(self.btn_import_leak)
        leaks_buttons.addWidget(self.btn_delete_leak)
        leaks_buttons.addStretch(1)
        leaks_buttons.addWidget(self.btn_open_leaks_viewer)
        repository_layout.addLayout(leaks_buttons)

        self.lbl_leak_status = QLabel("")
        self.lbl_leak_status.setObjectName("ProfileSubtitle")
        self.lbl_leak_status.setWordWrap(True)
        repository_layout.addWidget(self.lbl_leak_status)

        self.btn_import_leak.clicked.connect(self.import_leak_dataset)
        self.btn_delete_leak.clicked.connect(self.delete_leak_dataset)
        self.btn_open_leaks_viewer.clicked.connect(self.open_leaks_viewer)
        right_col.addWidget(repository_panel, 1)

        body_row.addLayout(left_col, 0)
        body_row.addLayout(right_col, 1)
        root.addLayout(body_row)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        self.btn_save_ai = make_dialog_button("Save settings")
        self.btn_reload = make_dialog_button("Reload settings")
        self.btn_save_ai.setFixedHeight(SETTINGS_FIELD_HEIGHT)
        self.btn_reload.setFixedHeight(SETTINGS_FIELD_HEIGHT)
        button_row.addWidget(self.btn_save_ai)
        button_row.addWidget(self.btn_reload)
        root.addLayout(button_row)

        self.lbl_status = QLabel("")
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setObjectName("ProfileSubtitle")
        root.addWidget(self.lbl_status)

        self.btn_save_ai.clicked.connect(self.save_ai_settings)
        self.btn_reload.clicked.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        settings = self.app.ai_service.settings
        self.edit_ai_url.setText(settings.base_url or "")
        self.edit_ai_model.setText(settings.model or "")
        self.edit_ai_timeout.setText(str(settings.timeout_seconds or 600))
        theme = (get_app_settings().get("ui.theme", "dark") or "dark").strip().lower()
        theme_idx = self.cmb_theme.findData(theme if theme in {"dark", "light"} else "dark")
        self.cmb_theme.setCurrentIndex(theme_idx if theme_idx >= 0 else 0)
        osint = OsintSettings.from_mapping(get_app_settings())
        self.edit_vt_key.setText(osint.virustotal_api_key or "")
        self.edit_shodan_key.setText(osint.shodan_api_key or "")
        self._refresh_tac_status()
        self._refresh_leak_datasets()
        self.lbl_status.setText("Current settings loaded.")

    def _refresh_leak_datasets(self) -> None:
        from core.leaks.db import list_datasets

        self.list_leak_datasets.clear()
        try:
            datasets = list_datasets()
        except Exception as exc:
            self.lbl_leak_status.setText(f"Cannot load datasets: {exc}")
            return
        if not datasets:
            self.lbl_leak_status.setText("No datasets imported.")
            return
        for row in datasets:
            count = int(row["record_count"] or 0)
            note = (row["source_note"] or "").strip()
            label = f"{row['name']} — {count:,} records"
            if note:
                label += f"  ·  {note}"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, int(row["id"]))
            self.list_leak_datasets.addItem(item)
        self.lbl_leak_status.setText(f"{len(datasets)} dataset(s) imported.")

    def import_leak_dataset(self) -> None:
        from ui.leaks_import_dialog import LeaksImportDialog

        dialog = LeaksImportDialog(self)
        dialog.exec()
        self._refresh_leak_datasets()
        if dialog.imported_dataset_id:
            self.lbl_leak_status.setText("Dataset imported.")

    def delete_leak_dataset(self) -> None:
        from core.leaks.db import delete_dataset

        item = self.list_leak_datasets.currentItem()
        if item is None:
            self.lbl_leak_status.setText("Select a dataset to delete.")
            return
        dataset_id = int(item.data(Qt.UserRole))
        if hasattr(self.app, "_confirm_dialog"):
            ok = self.app._confirm_dialog(
                "Delete dataset",
                "Delete the selected dataset and all its records?",
                ok_text="Delete",
                cancel_text="Cancel",
                destructive=True,
            )
            if not ok:
                return
        delete_dataset(dataset_id)
        self._refresh_leak_datasets()
        self.lbl_leak_status.setText("Dataset deleted.")

    def open_leaks_viewer(self) -> None:
        if hasattr(self.app, "open_leaks_viewer"):
            self.app.open_leaks_viewer()

    def _refresh_tac_status(self) -> None:
        from core.osint.tac_store import tac_entry_count, tac_import_source

        source = tac_import_source()
        count = tac_entry_count()
        if source:
            self.lbl_tac_status.setText(f"{count:,} TAC entries loaded.")
        else:
            self.lbl_tac_status.setText(f"{count:,} TAC entries loaded (bundled database).")

    def import_tac_csv(self) -> None:
        from core.osint.tac_store import import_tac_csv

        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import TAC CSV",
            "",
            "CSV files (*.csv);;All files (*.*)",
        )
        if not path:
            return
        count, message = import_tac_csv(path)
        self._refresh_tac_status()
        self.lbl_status.setText(message if count else f"TAC import failed: {message}")

    def save_ai_settings(self) -> None:
        try:
            timeout = int((self.edit_ai_timeout.text() or "").strip() or "600")
        except Exception:
            timeout = 600

        values = {
            "base_url": (self.edit_ai_url.text() or "").strip() or "http://localhost:11434",
            "model": (self.edit_ai_model.text() or "").strip() or "llama3",
            "timeout_seconds": max(1, timeout),
        }

        self.app.ai_service.update_settings(AISettings(**values))
        for key, value in self.app.ai_service.settings.to_mapping().items():
            set_app_setting(key, value)
        theme = str(self.cmb_theme.currentData() or "dark")
        set_app_setting("ui.theme", theme)
        osint = OsintSettings(
            virustotal_api_key=(self.edit_vt_key.text() or "").strip(),
            shodan_api_key=(self.edit_shodan_key.text() or "").strip(),
        )
        for key, value in osint.to_mapping().items():
            set_app_setting(key, value)
        if hasattr(self.app, "apply_theme"):
            self.app.apply_theme(theme)

        self.lbl_status.setText(
            f"Saved. Base URL: {values['base_url']} | Model: {values['model']} | "
            f"Timeout: {values['timeout_seconds']} seconds | "
            f"Theme: {self.cmb_theme.currentText()} | OSINT keys: "
            f"VT={'set' if osint.virustotal_api_key else 'empty'}, "
            f"Shodan={'set' if osint.shodan_api_key else 'empty'}"
        )
