from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from core.db import Project
from core.exporters.case_context import build_case_context, case_context_table_html
from core.exporters.html_blocks import format_export_source_label, header_value
from core.exporters.template_utils import load_export_template, render_template


def export_table_html(
    file_path: str,
    title: str,
    headers: list[str],
    rows: list[list[str]],
    *,
    project: Project | None = None,
    project_name: str = "",
    source_label: str = "",
    period: str = "",
) -> None:
    text = _report_text()
    case_context = build_case_context(project, project_name=project_name)
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    report_title = title or text["table_title"]
    project_label = html.escape(project_name or case_context.get("project") or "Project")
    period_value = header_value(period, case_context.get("order_validity"))
    source_value = header_value(format_export_source_label(source_label), source_label)

    table_headers = "".join(f"<th>{html.escape(str(header))}</th>" for header in headers)
    table_rows = "\n".join(
        "<tr>"
        + "".join(f"<td>{html.escape(str(value))}</td>" for value in row)
        + "</tr>"
        for row in rows
    )

    rendered = render_template(
        load_export_template("table_export.html"),
        {
            "LANG": "en",
            "TITLE": report_title,
            "DOCUMENT_TYPE": text["document_type"],
            "REPORT_TITLE": html.escape(report_title),
            "PERIOD_LABEL": text["period"],
            "PERIOD": html.escape(period_value),
            "EXPORTED_LABEL": text["exported"],
            "EXPORTED_AT": generated_at,
            "SOURCE_LABEL": text["source"],
            "SOURCE": html.escape(source_value),
            "SCOPE_LABEL": text["scope"],
            "SCOPE": html.escape(f"{len(rows):,} {text['rows'].casefold()} · {len(headers)} {text['columns'].casefold()}"),
            "CASE_CONTEXT_LABEL": text["case_context"],
            "CASE_TABLE": case_context_table_html(case_context),
            "TABLE_TITLE": text["table_title"],
            "TABLE_HEADERS": table_headers,
            "TABLE_ROWS": table_rows,
            "PROJECT_NAME": project_label,
            "PREPARED_LABEL": text["prepared"],
        },
        escape_values=False,
    )
    Path(file_path).write_text(rendered, encoding="utf-8")


def _report_text() -> dict[str, str]:
    return {
        "document_type": "Table",
        "exported": "Exported",
        "source": "Source",
        "period": "Period",
        "scope": "Scope",
        "rows": "Rows",
        "columns": "Columns",
        "case_context": "Case context",
        "table_title": "Table data",
        "prepared": "Prepared",
    }
