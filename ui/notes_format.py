from __future__ import annotations

import html
import re
from datetime import datetime


def format_notes_html_block(*, source: str, title: str, body: str) -> str:
    safe_source = html.escape((source or "Note").strip())
    safe_title = html.escape((title or "Note").strip())
    safe_body = html.escape((body or "").strip()).replace("\n", "<br/>")
    return (
        '<div style="margin: 18px 0 10px 0;">'
        f'<p style="color:#94a3b8;font-size:11px;margin:0 0 8px 0;">{safe_source}</p>'
        f'<p style="text-align:center;font-weight:700;font-size:13px;margin:0 0 10px 0;">{safe_title}</p>'
        f'<p style="text-align:justify;margin:0;line-height:1.45;">{safe_body}</p>'
        "</div>"
        '<hr style="border:none;border-top:1px solid #475569;margin:14px 0 4px 0;" />'
    )


def plain_block_to_html(block: str) -> str:
    text = (block or "").strip()
    if not text:
        return ""
    if text.lstrip().lower().startswith("<"):
        return text

    header_match = re.match(r"^\[(?P<label>[^\]]+)\]\s*$", text.splitlines()[0] if text else "")
    if header_match:
        lines = text.splitlines()
        label = header_match.group("label").strip()
        body_lines = lines[1:]
        while body_lines and not body_lines[-1].strip():
            body_lines.pop()
        if body_lines and set(body_lines[-1].strip()) <= {"-"}:
            body_lines.pop()
        body = "\n".join(body_lines).strip()
        return format_notes_html_block(source=label, title=label, body=body)

    ts = datetime.now().strftime("%d.%m.%Y. %H:%M:%S")
    return format_notes_html_block(source=f"Note · {ts}", title="Note", body=text)
