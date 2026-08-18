from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from core.db import Project
from core.exporters.case_context import build_case_context, case_context_table_html
from core.exporters.template_utils import load_template, render_template


def export_table_html(
    file_path: str,
    title: str,
    headers: list[str],
    rows: list[list[str]],
    *,
    project: Project | None = None,
    project_name: str = "",
    source_label: str = "",
) -> None:
    text = _report_text()
    case_context = build_case_context(project, project_name=project_name)

    table_headers = "".join(f"<th>{html.escape(str(header))}</th>" for header in headers)
    table_rows = "\n".join(
        "<tr>"
        + "".join(f"<td>{html.escape(str(value))}</td>" for value in row)
        + "</tr>"
        for row in rows
    )

    rendered = render_template(
        load_template("table_export.html"),
        {
            "LANG": "en",
            "TITLE": title or text["title"],
            "REPORT_TITLE": title or text["table_title"],
            "EXPORTED_LABEL": text["exported"],
            "EXPORTED_AT": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
            "SOURCE_LABEL": text["source"],
            "SOURCE": source_label or "—",
            "ROWS_LABEL": text["rows"],
            "ROWS_COUNT": len(rows),
            "COLUMNS_LABEL": text["columns"],
            "COLUMNS_COUNT": len(headers),
            "CASE_TABLE": case_context_table_html(case_context),
            "TABLE_TITLE": text["table_title"],
            "TABLE_HEADERS": table_headers,
            "TABLE_ROWS": table_rows,
            "GENERATED_BY_LABEL": text["generated_by"],
        },
        escape_values=False,
    )
    Path(file_path).write_text(rendered, encoding="utf-8")


def _report_text() -> dict[str, str]:
    return {
        "title": "Table Export",
        "exported": "Exported",
        "source": "Source",
        "rows": "Rows",
        "columns": "Columns",
        "table_title": "Table data",
        "generated_by": "Prepared",
    }
