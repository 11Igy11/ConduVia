from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QFrame, QPushButton, QVBoxLayout

if TYPE_CHECKING:
    from ui.app import App


def build_sidebar(app: App) -> QFrame:
    sidebar_frame = QFrame()
    sidebar_frame.setObjectName("SidebarFrame")
    sidebar_frame.setFixedWidth(220)
    sidebar = QVBoxLayout(sidebar_frame)
    sidebar.setContentsMargins(0, 0, 12, 0)
    sidebar.setSpacing(8)

    app.btn_nav_projects = QPushButton("Projects")
    app.btn_nav_json = QPushButton("JSON")
    app.btn_nav_pcap = QPushButton("PCAP")
    app.btn_nav_osint = QPushButton("OSINT")
    app.btn_nav_ai = QPushButton("AI output")
    app.btn_nav_notes = QPushButton("Notes")
    app.btn_nav_profile = QPushButton("Profile")
    app.btn_global_refresh = QPushButton("Refresh")
    app.btn_nav_settings = QPushButton("Settings")
    app.btn_nav_help = QPushButton("Help")

    for b in (
        app.btn_nav_projects,
        app.btn_nav_json,
        app.btn_nav_pcap,
        app.btn_nav_osint,
        app.btn_nav_ai,
        app.btn_nav_notes,
        app.btn_nav_profile,
        app.btn_global_refresh,
        app.btn_nav_settings,
        app.btn_nav_help,
    ):
        b.setObjectName("NavButton")
        b.setFixedHeight(40)
    app.btn_global_refresh.setToolTip(
        "Refresh projects, notes, findings, profile, PCAP view and settings."
    )

    app._nav_projects = app.btn_nav_projects
    app._nav_profile = app.btn_nav_profile
    app._nav_notes = app.btn_nav_notes
    app._nav_ai = app.btn_nav_ai
    app._nav_json = app.btn_nav_json
    app._nav_explore = app.btn_nav_json
    app._nav_registry = app.btn_nav_json
    app._nav_listing = app.btn_nav_json
    app._nav_pcap = app.btn_nav_pcap
    app._nav_osint = app.btn_nav_osint
    app._nav_settings = app.btn_nav_settings
    app._nav_buttons = (
        app._nav_projects,
        app._nav_json,
        app._nav_pcap,
        app._nav_osint,
        app._nav_ai,
        app._nav_notes,
        app._nav_profile,
        app._nav_settings,
    )

    sidebar.addWidget(app.btn_nav_projects)
    sidebar.addWidget(app.btn_nav_json)
    sidebar.addWidget(app.btn_nav_pcap)
    sidebar.addWidget(app.btn_nav_osint)
    sidebar.addWidget(app.btn_nav_ai)
    sidebar.addWidget(app.btn_nav_notes)
    sidebar.addWidget(app.btn_nav_profile)
    sidebar.addStretch()
    sidebar.addWidget(app.btn_global_refresh)
    sidebar.addWidget(app.btn_nav_settings)
    sidebar.addWidget(app.btn_nav_help)

    return sidebar_frame


def wire_navigation(app: App) -> None:
    app.btn_nav_projects.clicked.connect(
        lambda: app.go_page(app.IDX_PROJECTS, app._nav_projects)
    )
    app.btn_nav_profile.clicked.connect(
        lambda: app.go_page(app.IDX_PROFILE, app._nav_profile)
    )
    app.btn_nav_notes.clicked.connect(app.go_to_notes)
    app.btn_nav_ai.clicked.connect(app.go_to_ai)
    app.btn_nav_json.clicked.connect(lambda: app.go_to_json_tab(0))
    app.btn_global_refresh.clicked.connect(app.refresh_all_views)
    app.btn_nav_pcap.clicked.connect(lambda: app.go_page(app.IDX_PCAP, app._nav_pcap))
    app.btn_nav_osint.clicked.connect(lambda: app.go_page(app.IDX_OSINT, app._nav_osint))
    app.btn_nav_settings.clicked.connect(
        lambda: app.go_page(app.IDX_SETTINGS, app._nav_settings)
    )
    app.btn_nav_help.clicked.connect(app.open_user_manual)
