from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QTextEdit, QVBoxLayout, QWidget

from ui.buttons import make_action_button

if TYPE_CHECKING:
    from ui.app import App


def build_ai_hub_page(app: App) -> QWidget:
    ai_page = QWidget()
    ai_root = QVBoxLayout(ai_page)
    ai_root.setContentsMargins(10, 10, 10, 10)
    ai_root.setSpacing(10)

    ai_header = QFrame()
    ai_header.setObjectName("ExploreHeaderCard")
    ai_header_layout = QVBoxLayout(ai_header)
    ai_header_layout.setContentsMargins(10, 6, 10, 6)
    ai_header_layout.setSpacing(4)

    ai_title_row = QHBoxLayout()
    app.lbl_ai_hub_title = QLabel("AI Summary")
    app.lbl_ai_hub_title.setObjectName("HeaderProjectLabel")
    app.btn_ai_hub_add_notes = make_action_button("Add to Notes", enabled=False)
    ai_title_row.addWidget(app.lbl_ai_hub_title)
    ai_title_row.addStretch()
    ai_title_row.addWidget(app.btn_ai_hub_add_notes)

    app.lbl_ai_hub_context = QLabel(
        "Generate an AI result from JSON, PCAP or Profile to see it here."
    )
    app.lbl_ai_hub_context.setObjectName("Muted")
    app.lbl_ai_hub_context.setWordWrap(True)

    ai_header_layout.addLayout(ai_title_row)
    ai_header_layout.addWidget(app.lbl_ai_hub_context)
    ai_root.addWidget(ai_header)

    app.txt_ai_hub = QTextEdit()
    app.txt_ai_hub.setReadOnly(True)
    app.txt_ai_hub.setPlaceholderText(
        "The latest AI-generated explanation or summary will appear here."
    )
    ai_root.addWidget(app.txt_ai_hub, 1)

    app.btn_ai_hub_add_notes.clicked.connect(app.add_ai_hub_to_notes)
    return ai_page
