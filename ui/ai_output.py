from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QLabel, QPushButton, QTextEdit

if TYPE_CHECKING:
    from ui.app import App


@dataclass
class AIOutputState:
    source: str = "AI"
    title: str = "No AI output yet"
    text: str = ""


def ai_output_preview(text: str, limit: int = 120) -> str:
    compact = " ".join((text or "").split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 1]}…"


def format_ai_output_timestamp(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "-"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).strftime("%d.%m.%Y. %H:%M")
        except ValueError:
            continue
    return raw


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


def open_ai_history_dialog(app: App) -> None:
    from core.db import list_ai_outputs
    from ui.project_rows_dialog import open_project_rows_dialog

    project_id = getattr(app, "current_project_id", None)
    if project_id is None:
        app._message_dialog("AI history", "Select a project first.", width=420)
        return

    records = list_ai_outputs(int(project_id), limit=100)
    if not records:
        app._message_dialog(
            "AI history",
            "No saved AI outputs for this project yet.\n\n"
            "Generate a summary from JSON, PCAP, or Profile to build history.",
            width=480,
        )
        return

    rows = []
    for record in records:
        rows.append(
            {
                "id": int(record["id"]),
                "created_at": format_ai_output_timestamp(str(record.get("created_at") or "")),
                "source": str(record.get("source") or ""),
                "title": str(record.get("title") or ""),
                "preview": ai_output_preview(str(record.get("body_text") or "")),
            }
        )

    def _open_row(row: dict, dialog) -> None:
        output_id = int(row.get("id") or 0)
        if output_id:
            app.load_ai_output_record(output_id)
            dialog.accept()

    open_project_rows_dialog(
        app,
        "AI output history",
        [
            ("created_at", "When"),
            ("source", "Source"),
            ("title", "Title"),
            ("preview", "Preview"),
        ],
        rows,
        on_double_click=_open_row,
        show_export=True,
        export_category="json",
        export_source_label="AI history",
    )
