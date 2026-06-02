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
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
    QFileDialog,
)

from core.ai.assistant_service import AISettings
from core.db import get_app_settings, set_app_setting
from core.osint.settings import OsintSettings
from core.output_language import normalize_output_language

SETTINGS_LABEL_WIDTH = 170
SETTINGS_FIELD_WIDTH = 360
SETTINGS_COMPACT_WIDTH = 140
SETTINGS_FIELD_HEIGHT = 36


def _settings_line_edit(*, placeholder: str = "", password: bool = False, compact: bool = False) -> QLineEdit:
    edit = QLineEdit()
    edit.setObjectName("SettingsField")
    edit.setPlaceholderText(placeholder)
    width = SETTINGS_COMPACT_WIDTH if compact else SETTINGS_FIELD_WIDTH
    edit.setFixedSize(width, SETTINGS_FIELD_HEIGHT)
    edit.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    if password:
        edit.setEchoMode(QLineEdit.Password)
    return edit


def _settings_combo_box(*, compact: bool = False) -> QComboBox:
    combo = QComboBox()
    combo.setObjectName("SettingsField")
    width = SETTINGS_COMPACT_WIDTH if compact else SETTINGS_FIELD_WIDTH
    combo.setFixedSize(width, SETTINGS_FIELD_HEIGHT)
    combo.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    return combo


def _settings_form_row(label_text: str, field: QWidget) -> QHBoxLayout:
    row = QHBoxLayout()
    row.setSpacing(12)
    label = QLabel(label_text)
    label.setMinimumWidth(SETTINGS_LABEL_WIDTH)
    label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
    row.addWidget(label)
    row.addWidget(field)
    row.addStretch(1)
    return row


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
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(18)
        scroll.setWidget(content)

        header = QFrame()
        header.setObjectName("ProfileHero")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(22, 18, 22, 18)

        title_col = QVBoxLayout()
        title = QLabel("Settings")
        title.setObjectName("ProfileTitle")
        subtitle = QLabel("Application-wide configuration for AI, OSINT and appearance.")
        subtitle.setObjectName("ProfileSubtitle")
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        header_layout.addLayout(title_col, 1)
        root.addWidget(header)

        ai_panel = QFrame()
        ai_panel.setObjectName("ProfilePanel")
        ai_layout = QVBoxLayout(ai_panel)
        ai_layout.setContentsMargins(22, 18, 22, 18)
        ai_layout.setSpacing(12)

        ai_title = QLabel("AI")
        ai_title.setObjectName("ProfilePanelTitle")
        ai_layout.addWidget(ai_title)

        self.edit_ai_url = _settings_line_edit(placeholder="http://localhost:11434")
        self.edit_ai_model = _settings_line_edit(placeholder="llama3")
        self.edit_ai_timeout = _settings_line_edit(placeholder="600", compact=True)

        for label, field in (
            ("Base URL", self.edit_ai_url),
            ("Model", self.edit_ai_model),
            ("Timeout seconds", self.edit_ai_timeout),
        ):
            ai_layout.addLayout(_settings_form_row(label, field))

        root.addWidget(ai_panel)

        language_panel = QFrame()
        language_panel.setObjectName("ProfilePanel")
        language_layout = QVBoxLayout(language_panel)
        language_layout.setContentsMargins(22, 18, 22, 18)
        language_layout.setSpacing(12)

        language_title = QLabel("Language")
        language_title.setObjectName("ProfilePanelTitle")
        language_layout.addWidget(language_title)

        self.cmb_output_language = _settings_combo_box(compact=True)
        self.cmb_output_language.addItem("Croatian", "hr")
        self.cmb_output_language.addItem("English", "en")
        language_layout.addLayout(_settings_form_row("Report / AI language", self.cmb_output_language))

        root.addWidget(language_panel)

        theme_panel = QFrame()
        theme_panel.setObjectName("ProfilePanel")
        theme_layout = QVBoxLayout(theme_panel)
        theme_layout.setContentsMargins(22, 18, 22, 18)
        theme_layout.setSpacing(12)

        theme_title = QLabel("Appearance")
        theme_title.setObjectName("ProfilePanelTitle")
        theme_layout.addWidget(theme_title)

        self.cmb_theme = _settings_combo_box(compact=True)
        self.cmb_theme.addItem("Dark", "dark")
        self.cmb_theme.addItem("Light", "light")
        theme_layout.addLayout(_settings_form_row("Theme", self.cmb_theme))

        root.addWidget(theme_panel)

        osint_panel = QFrame()
        osint_panel.setObjectName("ProfilePanel")
        osint_layout = QVBoxLayout(osint_panel)
        osint_layout.setContentsMargins(22, 18, 22, 18)
        osint_layout.setSpacing(12)

        osint_title = QLabel("OSINT")
        osint_title.setObjectName("ProfilePanelTitle")
        osint_layout.addWidget(osint_title)

        self.edit_vt_key = _settings_line_edit(placeholder="VirusTotal API key", password=True)
        self.edit_shodan_key = _settings_line_edit(placeholder="Shodan API key", password=True)

        for label, field in (
            ("VirusTotal API key", self.edit_vt_key),
            ("Shodan API key", self.edit_shodan_key),
        ):
            osint_layout.addLayout(_settings_form_row(label, field))

        self.btn_import_tac = QPushButton("Import TAC CSV…")
        self.btn_import_tac.setFixedHeight(SETTINGS_FIELD_HEIGHT)
        self.lbl_tac_status = QLabel("")
        self.lbl_tac_status.setObjectName("ProfileSubtitle")
        self.lbl_tac_status.setWordWrap(True)
        osint_layout.addLayout(_settings_form_row("IMEI TAC database", self.btn_import_tac))
        osint_layout.addWidget(self.lbl_tac_status)
        self.btn_import_tac.clicked.connect(self.import_tac_csv)

        root.addWidget(osint_panel)

        leaks_panel = QFrame()
        leaks_panel.setObjectName("ProfilePanel")
        leaks_layout = QVBoxLayout(leaks_panel)
        leaks_layout.setContentsMargins(22, 18, 22, 18)
        leaks_layout.setSpacing(12)

        leaks_title = QLabel("Repository")
        leaks_title.setObjectName("ProfilePanelTitle")
        leaks_layout.addWidget(leaks_title)

        leaks_hint = QLabel(
            "Import or manually create datasets (.txt / .csv / .tsv / .docx). Search and edit "
            "them in the OSINT module via the 'Repository' button. Data is stored locally."
        )
        leaks_hint.setObjectName("ProfileSubtitle")
        leaks_hint.setWordWrap(True)
        leaks_layout.addWidget(leaks_hint)

        self.list_leak_datasets = QListWidget()
        self.list_leak_datasets.setMinimumHeight(140)
        leaks_layout.addWidget(self.list_leak_datasets)

        leaks_buttons = QHBoxLayout()
        self.btn_import_leak = QPushButton("Import dataset…")
        self.btn_delete_leak = QPushButton("Delete selected")
        self.btn_open_leaks_viewer = QPushButton("Open Repository")
        leaks_buttons.addWidget(self.btn_import_leak)
        leaks_buttons.addWidget(self.btn_delete_leak)
        leaks_buttons.addStretch(1)
        leaks_buttons.addWidget(self.btn_open_leaks_viewer)
        leaks_layout.addLayout(leaks_buttons)

        self.lbl_leak_status = QLabel("")
        self.lbl_leak_status.setObjectName("ProfileSubtitle")
        self.lbl_leak_status.setWordWrap(True)
        leaks_layout.addWidget(self.lbl_leak_status)

        self.btn_import_leak.clicked.connect(self.import_leak_dataset)
        self.btn_delete_leak.clicked.connect(self.delete_leak_dataset)
        self.btn_open_leaks_viewer.clicked.connect(self.open_leaks_viewer)

        root.addWidget(leaks_panel)

        button_row = QHBoxLayout()
        button_row.setContentsMargins(22, 0, 22, 0)
        button_row.addStretch(1)
        self.btn_save_ai = QPushButton("Save settings")
        self.btn_reload = QPushButton("Reload settings")
        self.btn_save_ai.setFixedWidth(150)
        self.btn_reload.setFixedWidth(150)
        button_row.addWidget(self.btn_save_ai)
        button_row.addWidget(self.btn_reload)
        root.addLayout(button_row)

        self.lbl_status = QLabel("")
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setObjectName("ProfileSubtitle")
        root.addWidget(self.lbl_status)

        root.addStretch(1)

        self.btn_save_ai.clicked.connect(self.save_ai_settings)
        self.btn_reload.clicked.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        settings = self.app.ai_service.settings
        self.edit_ai_url.setText(settings.base_url or "")
        self.edit_ai_model.setText(settings.model or "")
        self.edit_ai_timeout.setText(str(settings.timeout_seconds or 600))
        language = normalize_output_language(getattr(settings, "output_language", "hr"))
        idx = self.cmb_output_language.findData(language)
        self.cmb_output_language.setCurrentIndex(idx if idx >= 0 else 0)
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
            self.lbl_tac_status.setText(f"{count:,} TAC entries loaded. Last import: {source}")
        else:
            self.lbl_tac_status.setText(f"{count:,} TAC entries loaded (bundled database only).")

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
            "output_language": normalize_output_language(str(self.cmb_output_language.currentData() or "hr")),
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
            f"Timeout: {values['timeout_seconds']} seconds | Language: {self.cmb_output_language.currentText()} | "
            f"Theme: {self.cmb_theme.currentText()} | OSINT keys: "
            f"VT={'set' if osint.virustotal_api_key else 'empty'}, "
            f"Shodan={'set' if osint.shodan_api_key else 'empty'}"
        )
