from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from PySide6.QtWidgets import QLabel, QPushButton, QTextEdit


@dataclass
class AIOutputState:
    source: str = "AI"
    title: str = "No AI output yet"
    text: str = ""


def make_ai_note_block(text: str) -> str:
    body = (text or "").strip()
    if not body:
        return ""

    from ui.notes_format import format_notes_html_block

    ts = datetime.now().strftime("%d.%m.%Y. %H:%M:%S")
    return format_notes_html_block(
        source=f"AI output · {ts}",
        title="AI summary",
        body=body,
    )


def build_ai_output_state(source: str, title: str, text: str) -> AIOutputState:
    return AIOutputState(
        source=(source or "AI").strip(),
        title=(title or "AI Summary").strip(),
        text=text or "",
    )


def render_ai_output_hub(
    *,
    state: AIOutputState,
    project_name: str = "",
    title_label: QLabel | None = None,
    context_label: QLabel | None = None,
    text_edit: QTextEdit | None = None,
    add_notes_button: QPushButton | None = None,
) -> None:
    if title_label is not None:
        title_label.setText(state.title)

    if context_label is not None:
        context = f"Source: {state.source}"
        if project_name:
            context += f" | Project: {project_name}"
        context_label.setText(context)

    if text_edit is not None:
        text_edit.setPlainText(state.text)

    if add_notes_button is not None:
        add_notes_button.setEnabled(bool(state.text.strip()))
