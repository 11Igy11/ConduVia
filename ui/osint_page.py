from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget


def build_osint_page() -> QWidget:
    page = QWidget()
    root = QVBoxLayout(page)
    root.setContentsMargins(10, 10, 10, 10)
    root.setSpacing(14)

    header = QFrame()
    header.setObjectName("ProfileHero")
    header_layout = QVBoxLayout(header)
    header_layout.setContentsMargins(18, 16, 18, 16)
    header_layout.setSpacing(8)

    title = QLabel("OSINT")
    title.setObjectName("ProfileTitle")
    subtitle = QLabel(
        "Under construction. This module will later collect open-source profile signals for the active case."
    )
    subtitle.setObjectName("ProfileSubtitle")
    subtitle.setWordWrap(True)

    header_layout.addWidget(title)
    header_layout.addWidget(subtitle)
    root.addWidget(header)

    panel = QFrame()
    panel.setObjectName("ProfilePanel")
    panel_layout = QVBoxLayout(panel)
    panel_layout.setContentsMargins(18, 16, 18, 16)
    panel_layout.setSpacing(10)

    panel_title = QLabel("Planned module")
    panel_title.setObjectName("ProfilePanelTitle")
    body = QLabel(
        "OSINT will be a separate workspace for social network, messaging-app and public-source indicators. "
        "For beta, this page is only a navigation placeholder so the final module has a reserved place in the application."
    )
    body.setObjectName("Muted")
    body.setWordWrap(True)
    body.setTextInteractionFlags(Qt.TextSelectableByMouse)

    panel_layout.addWidget(panel_title)
    panel_layout.addWidget(body)
    root.addWidget(panel)
    root.addStretch()
    return page
