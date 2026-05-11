from __future__ import annotations

import html
from pathlib import Path

from core.exporters.template_utils import load_template, render_template


def export_table_html(file_path: str, title: str, headers: list[str], rows: list[list[str]], *, lang: str = "en") -> None:
    head = "".join(f"<th>{html.escape(str(header))}</th>" for header in headers)
    body = "\n".join(
        "<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in row) + "</tr>"
        for row in rows
    )
    rendered = render_template(
        load_template("table_export.html"),
        {
            "LANG": lang,
            "TITLE": html.escape(title),
            "ROW_COUNT": len(rows),
            "TABLE_HEADERS": head,
            "TABLE_ROWS": body,
        },
        escape_values=False,
    )
    Path(file_path).write_text(rendered, encoding="utf-8")
