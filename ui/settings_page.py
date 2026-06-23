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
from ui.buttons import make_action_button
from ui.ui_metrics import DIALOG_FIELD_HEIGHT

SETTINGS_COLUMNS_GAP = 14


def _settings_button(text: str, *, destructive: bool = False) -> QPushButton:
    button = make_action_button(text, destructive=destructive, toolbar=True, tight=True)
    button.setFixedHeight(DIALOG_FIELD_HEIGHT)
    return button


def _settings_line_edit(*, placeholder: str = "", password: bool = False, narrow: bool = False) -> QLineEdit:
    edit = QLineEdit()
    edit.setObjectName("SettingsField")
    edit.setPlaceholderText(placeholder)
    edit.setFixedHeight(DIALOG_FIELD_HEIGHT)
    if narrow:
        edit.setMaximumWidth(120)
        edit.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    else:
        edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    if password:
        edit.setEchoMode(QLineEdit.Password)
    return edit


def _settings_combo_box(*, narrow: bool = False) -> QComboBox:
    combo = QComboBox()
    combo.setObjectName("SettingsField")
    combo.setFixedHeight(DIALOG_FIELD_HEIGHT)
    if narrow:
        combo.setMaximumWidth(120)
        combo.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    else:
        combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    return combo


def _field_group(label_text: str, field: QWidget) -> QWidget:
    host = QWidget()
    host.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    layout = QVBoxLayout(host)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(4)
    label = QLabel(label_text)
    label.setObjectName("DialogFieldLabel")
    label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    layout.addWidget(label)
    layout.addWidget(field)
    return host


def _settings_panel(title: str) -> tuple[QFrame, QVBoxLayout]:
    panel = QFrame()
    panel.setObjectName("ProfilePanel")
    panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
    layout = QVBoxLayout(panel)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(10)
    panel_title = QLabel(title)
    panel_title.setObjectName("ProfilePanelTitle")
    layout.addWidget(panel_title)
    return panel, layout


def _settings_divider() -> QFrame:
    line = QFrame()
    line.setObjectName("SettingsSectionRule")
    line.setFrameShape(QFrame.HLine)
    line.setFrameShadow(QFrame.Plain)
    line.setFixedHeight(1)
    line.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    return line


class SettingsPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.setObjectName("SettingsPage")
        self.app = app

        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        outer.addWidget(scroll)

        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(0, 0, 0, 12)
        root.setSpacing(12)
        scroll.setWidget(page)

        header = QFrame()
        header.setObjectName("ExploreHeaderCard")
        header.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(10, 8, 10, 8)
        header_layout.setSpacing(4)

        title_row = QHBoxLayout()
        title_row.setSpacing(8)
        title = QLabel("Settings")
        title.setObjectName("HeaderProjectLabel")
        self.btn_save_ai = _settings_button("Save")
        self.btn_reload = _settings_button("Reload")
        title_row.addWidget(title)
        title_row.addStretch(1)
        title_row.addWidget(self.btn_save_ai)
        title_row.addWidget(self.btn_reload)
        header_layout.addLayout(title_row)

        subtitle = QLabel("Application-wide configuration for AI, OSINT and appearance.")
        subtitle.setObjectName("ProfileSubtitle")
        subtitle.setWordWrap(True)
        header_layout.addWidget(subtitle)

        self.lbl_status = QLabel("")
        self.lbl_status.setWordWrap(True)
        self.lbl_status.setObjectName("ProfileSubtitle")
        header_layout.addWidget(self.lbl_status)
        root.addWidget(header)

        ai_panel, ai_layout = _settings_panel("AI")
        self.edit_ai_url = _settings_line_edit(placeholder="http://localhost:11434")
        self.edit_ai_model = _settings_line_edit(placeholder="llama3")
        self.edit_ai_timeout = _settings_line_edit(placeholder="600", narrow=True)
        ai_layout.addWidget(_field_group("Base URL", self.edit_ai_url))
        ai_layout.addWidget(_field_group("Model", self.edit_ai_model))
        ai_layout.addWidget(_field_group("Timeout (seconds)", self.edit_ai_timeout))

        theme_panel, theme_layout = _settings_panel("Appearance")
        self.cmb_theme = _settings_combo_box(narrow=True)
        self.cmb_theme.addItem("Dark", "dark")
        self.cmb_theme.addItem("Light", "light")
        theme_layout.addWidget(_field_group("Theme", self.cmb_theme))

        osint_panel, osint_layout = _settings_panel("OSINT")
        self.edit_vt_key = _settings_line_edit(placeholder="VirusTotal API key", password=True)
        self.edit_shodan_key = _settings_line_edit(placeholder="Shodan API key", password=True)
        osint_layout.addWidget(_field_group("VirusTotal API key", self.edit_vt_key))
        osint_layout.addWidget(_field_group("Shodan API key", self.edit_shodan_key))

        tac_panel, tac_layout = _settings_panel("IMEI TAC database")
        self.btn_import_tac = _settings_button("Import TAC CSV…")
        tac_layout.addWidget(self.btn_import_tac)
        self.lbl_tac_status = QLabel("")
        self.lbl_tac_status.setObjectName("ProfileSubtitle")
        self.lbl_tac_status.setWordWrap(True)
        tac_layout.addWidget(self.lbl_tac_status)
        self.btn_import_tac.clicked.connect(self.import_tac_csv)

        left_column = QWidget()
        left_column.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        left_layout = QVBoxLayout(left_column)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(12)
        left_layout.addWidget(ai_panel)
        left_layout.addWidget(tac_panel)
        left_layout.addStretch(1)

        right_column = QWidget()
        right_column.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        right_layout = QVBoxLayout(right_column)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(12)
        right_layout.addWidget(theme_panel)
        right_layout.addWidget(osint_panel)
        right_layout.addStretch(1)

        columns_row = QHBoxLayout()
        columns_row.setSpacing(SETTINGS_COLUMNS_GAP)
        columns_row.addWidget(left_column, 1, Qt.AlignTop)
        columns_row.addWidget(right_column, 1, Qt.AlignTop)
        root.addLayout(columns_row)
        root.addWidget(_settings_divider())

        repository_panel, repository_layout = _settings_panel("Repository")
        repository_panel.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        leaks_hint = QLabel(
            "Import datasets (.txt / .csv / .tsv / .docx) and search them from OSINT → Repository."
        )
        leaks_hint.setObjectName("ProfileSubtitle")
        leaks_hint.setWordWrap(True)
        repository_layout.addWidget(leaks_hint)

        self.list_leak_datasets = QListWidget()
        self.list_leak_datasets.setMinimumHeight(140)
        self.list_leak_datasets.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        repository_layout.addWidget(self.list_leak_datasets)

        leaks_buttons = QHBoxLayout()
        leaks_buttons.setSpacing(8)
        self.btn_import_leak = _settings_button("Import dataset…")
        self.btn_delete_leak = _settings_button("Delete selected", destructive=True)
        self.btn_open_leaks_viewer = _settings_button("Open Repository")
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
        root.addWidget(repository_panel)

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
