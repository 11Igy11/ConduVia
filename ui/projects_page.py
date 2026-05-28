from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QSizePolicy,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ui.project_rows_dialog import (
    open_json_dataset_row,
    open_pcap_dataset_row,
    open_project_rows_dialog,
)

if TYPE_CHECKING:
    from ui.app import App

PROJECT_ACTION_HEIGHT = 32
PROJECT_ACTION_FONT_PX = 12


def _apply_action_font(widget, *, pixel_size: int = PROJECT_ACTION_FONT_PX) -> None:
    font = QFont(widget.font())
    font.setPixelSize(pixel_size)
    widget.setFont(font)


def _compact_button(text: str, *, primary: bool = False, object_name: str = "") -> QPushButton:
    button = QPushButton(text)
    if object_name:
        button.setObjectName(object_name)
    else:
        button.setObjectName("PrimaryButton" if primary else "CompactButton")
    button.setFixedHeight(PROJECT_ACTION_HEIGHT)
    button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    _apply_action_font(button)
    return button


def _compact_tool_button(text: str, *, primary: bool = False) -> QToolButton:
    button = QToolButton()
    button.setText(text)
    button.setObjectName("PrimaryToolButton" if primary else "CompactToolButton")
    button.setFixedSize(PROJECT_ACTION_HEIGHT, PROJECT_ACTION_HEIGHT)
    _apply_action_font(button, pixel_size=14)
    return button


def project_launcher_card(
    title: str,
    description: str,
    count_label: QLabel,
    detail_label: QLabel,
    buttons: list[QPushButton],
) -> QFrame:
    card = QFrame()
    card.setObjectName("Card")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(12, 12, 12, 16)
    layout.setSpacing(8)

    lbl_title = QLabel(title)
    lbl_title.setObjectName("SectionTitle")
    lbl_title.setTextInteractionFlags(Qt.TextSelectableByMouse)
    lbl_description = QLabel(description)
    lbl_description.setObjectName("Muted")
    lbl_description.setWordWrap(False)
    lbl_description.setMaximumHeight(24)
    lbl_description.setTextInteractionFlags(Qt.TextSelectableByMouse)

    layout.addWidget(lbl_title)
    layout.addWidget(lbl_description)
    layout.addWidget(count_label)
    detail_label.setWordWrap(False)
    detail_label.setMaximumHeight(24)
    layout.addWidget(detail_label)
    layout.addStretch(1)

    button_row = QHBoxLayout()
    button_row.setContentsMargins(0, 4, 0, 0)
    button_row.addStretch()
    for button in buttons:
        button_row.addWidget(button)
    layout.addLayout(button_row)
    return card


def build_projects_page(app: App) -> QWidget:
    projects_page = QWidget()
    projects_layout = QVBoxLayout(projects_page)
    projects_layout.setContentsMargins(10, 8, 10, 16)
    projects_layout.setSpacing(8)

    app.case_dashboard = QFrame()
    app.case_dashboard.setObjectName("CaseDashboardCompact")
    app.case_dashboard.setMaximumHeight(72)
    dashboard_layout = QVBoxLayout(app.case_dashboard)
    dashboard_layout.setContentsMargins(10, 6, 10, 6)
    dashboard_layout.setSpacing(2)

    app.lbl_case_dashboard_title = QLabel("Active case: (none)")
    app.lbl_case_dashboard_title.setObjectName("CaseDashboardTitle")
    app.lbl_case_dashboard_subject = QLabel("Open a project as the active case to work with JSON, PCAP and notes.")
    app.lbl_case_dashboard_subject.setWordWrap(True)
    app.lbl_case_dashboard_subject.setObjectName("Muted")

    dashboard_header = QHBoxLayout()
    dashboard_header.setSpacing(10)

    app.lbl_case_dashboard_logo = QLabel()
    app.lbl_case_dashboard_logo.setObjectName("CaseDashboardLogo")
    app.lbl_case_dashboard_logo.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    app.lbl_case_dashboard_logo.setFixedSize(44, 32)
    logo_path = Path(__file__).resolve().parent.parent / "assets" / "ViaNyquist.png"
    logo_pixmap = QPixmap(str(logo_path))
    if not logo_pixmap.isNull():
        app.lbl_case_dashboard_logo.setPixmap(
            logo_pixmap.scaled(
                app.lbl_case_dashboard_logo.size(),
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
        )

    dashboard_text = QVBoxLayout()
    dashboard_text.setSpacing(2)
    dashboard_text.addWidget(app.lbl_case_dashboard_title)
    dashboard_text.addWidget(app.lbl_case_dashboard_subject)

    dashboard_header.addWidget(app.lbl_case_dashboard_logo)
    dashboard_header.addLayout(dashboard_text, 1)
    dashboard_layout.addLayout(dashboard_header)

    projects_layout.addWidget(app.case_dashboard)

    app.btn_new_project = _compact_button("+ New", primary=True)
    app.btn_new_project.setToolTip("Create a new project")

    app.btn_edit_project = _compact_button("Edit", primary=True)
    app.btn_edit_project.setToolTip("Edit selected project")
    app.btn_edit_project.setEnabled(False)

    app.btn_delete_project = _compact_button("Delete", primary=True)
    app.btn_delete_project.setToolTip("Delete selected project")
    app.btn_delete_project.setEnabled(False)

    app.btn_refresh_projects = _compact_tool_button("↻", primary=True)
    app.btn_refresh_projects.setToolTip("Refresh project list")

    app.projects_list = QListWidget()

    list_toolbar = QHBoxLayout()
    list_toolbar.setSpacing(6)
    lbl_projects = QLabel("Projects")
    lbl_projects.setObjectName("SectionTitle")
    list_toolbar.addWidget(lbl_projects)
    list_toolbar.addStretch()
    list_toolbar.addWidget(app.btn_new_project)
    list_toolbar.addWidget(app.btn_edit_project)
    list_toolbar.addWidget(app.btn_delete_project)
    list_toolbar.addWidget(app.btn_refresh_projects)

    left_col = QVBoxLayout()
    left_col.setSpacing(6)
    left_col.addLayout(list_toolbar)
    left_col.addWidget(app.projects_list, 1)

    app.lbl_project_selection_title = QLabel("Select a project")
    app.lbl_project_selection_title.setObjectName("SectionTitle")
    app.lbl_project_selection_state = QLabel("")
    app.lbl_project_selection_state.setObjectName("ProjectSelectionBadge")
    app.lbl_project_selection_state.hide()

    app.btn_open_project = _compact_button("Set active", object_name="SetActiveButton")
    app.btn_open_project.setToolTip("Open selected project as the active case")
    app.btn_open_project.setEnabled(False)

    app.projects_info = QTextEdit()
    app.projects_info.setReadOnly(True)
    app.projects_info.setPlaceholderText("Select a project to see details.")

    selection_title_row = QHBoxLayout()
    selection_title_row.setSpacing(8)
    selection_title_row.addWidget(app.lbl_project_selection_title, 1)
    selection_title_row.addWidget(app.lbl_project_selection_state)
    selection_title_row.addWidget(app.btn_open_project)

    app.project_selection_panel = QFrame()
    app.project_selection_panel.setObjectName("Card")
    selection_layout = QVBoxLayout(app.project_selection_panel)
    selection_layout.setContentsMargins(10, 8, 10, 10)
    selection_layout.setSpacing(6)
    selection_layout.addLayout(selection_title_row)
    selection_layout.addWidget(app.projects_info, 1)

    right_col = QVBoxLayout()
    right_col.setSpacing(6)
    lbl_selected = QLabel("Selected project")
    lbl_selected.setObjectName("SectionTitle")
    right_col.addWidget(lbl_selected)
    right_col.addWidget(app.project_selection_panel, 1)

    middle_row = QHBoxLayout()
    middle_row.setSpacing(10)
    middle_row.addLayout(left_col, 2)
    middle_row.addLayout(right_col, 3)
    projects_layout.addLayout(middle_row, 1)

    app.project_recent_json_rows: list[dict[str, Any]] = []
    app.project_recent_pcap_rows: list[dict[str, Any]] = []
    app.project_activity_rows: list[dict[str, Any]] = []

    app.btn_expand_json_datasets = _compact_button("Open JSON list")
    app.btn_expand_pcap_datasets = _compact_button("Open PCAP list")
    app.btn_expand_project_activity = _compact_button("Open activity log")

    app.btn_expand_json_datasets.clicked.connect(
        lambda: open_project_rows_dialog(
            app,
            "Recent JSON datasets",
            [
                ("status", "Status"),
                ("name", "Name"),
                ("kind", "Kind"),
                ("path", "Path"),
            ],
            app.project_recent_json_rows,
            on_double_click=lambda row, dialog: open_json_dataset_row(app, row, dialog),
        )
    )
    app.btn_expand_pcap_datasets.clicked.connect(
        lambda: open_project_rows_dialog(
            app,
            "Recent PCAP days",
            [
                ("name", "Name"),
                ("file_count", "Files"),
                ("packets", "Packets"),
                ("volume", "Volume"),
                ("device_ip", "Device IP"),
                ("period", "Period"),
            ],
            app.project_recent_pcap_rows,
            on_double_click=lambda row, dialog: open_pcap_dataset_row(app, row, dialog),
        )
    )
    app.btn_expand_project_activity.clicked.connect(
        lambda: open_project_rows_dialog(
            app,
            "Recent activity",
            [
                ("event", "Event"),
                ("created_at", "Time"),
                ("detail", "Detail"),
            ],
            app.project_activity_rows,
        )
    )

    app.lbl_recent_json_count = QLabel("0 JSON datasets")
    app.lbl_recent_json_count.setObjectName("ProfileMetric")
    app.lbl_recent_json_detail = QLabel("No JSON datasets saved for this project.")
    app.lbl_recent_json_detail.setObjectName("Muted")
    app.lbl_recent_json_detail.setWordWrap(True)

    app.lbl_recent_pcap_count = QLabel("0 PCAP days")
    app.lbl_recent_pcap_count.setObjectName("ProfileMetric")
    app.lbl_recent_pcap_detail = QLabel("No PCAP days saved for this project.")
    app.lbl_recent_pcap_detail.setObjectName("Muted")
    app.lbl_recent_pcap_detail.setWordWrap(True)

    app.lbl_recent_activity_count = QLabel("0 events")
    app.lbl_recent_activity_count.setObjectName("ProfileMetric")
    app.lbl_recent_activity_detail = QLabel("No project activity yet.")
    app.lbl_recent_activity_detail.setObjectName("Muted")
    app.lbl_recent_activity_detail.setWordWrap(True)

    bottom_grid = QGridLayout()
    bottom_grid.setSpacing(10)
    bottom_grid.addWidget(
        project_launcher_card(
            "Recent JSON datasets",
            "Unique JSON files or folders saved to the active project.",
            app.lbl_recent_json_count,
            app.lbl_recent_json_detail,
            [app.btn_expand_json_datasets],
        ),
        0,
        0,
    )
    bottom_grid.addWidget(
        project_launcher_card(
            "Recent PCAP days",
            "Unique PCAP capture days saved to the active project.",
            app.lbl_recent_pcap_count,
            app.lbl_recent_pcap_detail,
            [app.btn_expand_pcap_datasets],
        ),
        0,
        1,
    )
    bottom_grid.addWidget(
        project_launcher_card(
            "Recent activity",
            "Central project activity log for datasets, PCAP sources, findings and notes.",
            app.lbl_recent_activity_count,
            app.lbl_recent_activity_detail,
            [app.btn_expand_project_activity],
        ),
        0,
        2,
    )
    bottom_grid.setColumnStretch(0, 1)
    bottom_grid.setColumnStretch(1, 1)
    bottom_grid.setColumnStretch(2, 1)

    projects_layout.addLayout(bottom_grid, 1)
    return projects_page
