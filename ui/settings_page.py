from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QComboBox,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from core.ai.assistant_service import AISettings
from core.db import get_app_settings, set_app_setting
from core.output_language import normalize_output_language


class SettingsPage(QWidget):
    def __init__(self, app):
        super().__init__()
        self.app = app

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(18)

        header = QFrame()
        header.setObjectName("ProfileHero")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(22, 18, 22, 18)

        title_col = QVBoxLayout()
        title = QLabel("Settings")
        title.setObjectName("ProfileTitle")
        subtitle = QLabel("Application-wide configuration for AI and future case defaults.")
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

        self.edit_ai_url = QLineEdit()
        self.edit_ai_url.setPlaceholderText("http://localhost:11434")
        self.edit_ai_model = QLineEdit()
        self.edit_ai_model.setPlaceholderText("llama3")
        self.edit_ai_timeout = QLineEdit()
        self.edit_ai_timeout.setPlaceholderText("600")
        standard_width = 360
        compact_width = 130
        self.edit_ai_url.setFixedWidth(standard_width)
        self.edit_ai_model.setFixedWidth(standard_width)
        self.edit_ai_timeout.setFixedWidth(compact_width)

        for label, edit in (
            ("Base URL", self.edit_ai_url),
            ("Model", self.edit_ai_model),
            ("Timeout seconds", self.edit_ai_timeout),
        ):
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setMinimumWidth(150)
            row.addWidget(lbl)
            row.addWidget(edit)
            row.addStretch(1)
            ai_layout.addLayout(row)

        root.addWidget(ai_panel)

        language_panel = QFrame()
        language_panel.setObjectName("ProfilePanel")
        language_layout = QVBoxLayout(language_panel)
        language_layout.setContentsMargins(22, 18, 22, 18)
        language_layout.setSpacing(12)

        language_title = QLabel("Language")
        language_title.setObjectName("ProfilePanelTitle")
        language_layout.addWidget(language_title)

        self.cmb_output_language = QComboBox()
        self.cmb_output_language.addItem("Croatian", "hr")
        self.cmb_output_language.addItem("English", "en")
        self.cmb_output_language.setFixedWidth(compact_width)

        language_row = QHBoxLayout()
        language_label = QLabel("Report / AI language")
        language_label.setMinimumWidth(150)
        language_row.addWidget(language_label)
        language_row.addWidget(self.cmb_output_language)
        language_row.addStretch(1)
        language_layout.addLayout(language_row)

        root.addWidget(language_panel)

        theme_panel = QFrame()
        theme_panel.setObjectName("ProfilePanel")
        theme_layout = QVBoxLayout(theme_panel)
        theme_layout.setContentsMargins(22, 18, 22, 18)
        theme_layout.setSpacing(12)

        theme_title = QLabel("Appearance")
        theme_title.setObjectName("ProfilePanelTitle")
        theme_layout.addWidget(theme_title)

        self.cmb_theme = QComboBox()
        self.cmb_theme.addItem("Dark", "dark")
        self.cmb_theme.addItem("Light", "light")
        self.cmb_theme.setFixedWidth(compact_width)

        theme_row = QHBoxLayout()
        theme_label = QLabel("Theme")
        theme_label.setMinimumWidth(150)
        theme_row.addWidget(theme_label)
        theme_row.addWidget(self.cmb_theme)
        theme_row.addStretch(1)
        theme_layout.addLayout(theme_row)

        root.addWidget(theme_panel)

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
        self.lbl_status.setText("Current AI settings loaded.")

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
        if hasattr(self.app, "apply_theme"):
            self.app.apply_theme(theme)

        self.lbl_status.setText(
            f"Saved. Base URL: {values['base_url']} | Model: {values['model']} | "
            f"Timeout: {values['timeout_seconds']} seconds | Language: {self.cmb_output_language.currentText()} | "
            f"Theme: {self.cmb_theme.currentText()}"
        )
