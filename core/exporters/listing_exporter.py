from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from core.db import Project
from core.exporters.case_context import (
    build_case_context,
    case_context_table_html,
    case_export_metadata_rows,
)
from core.exporters.html_blocks import header_value, period_label_from_meta
from core.exporters.tabular_export import export_tabular_csv, export_tabular_excel
from core.exporters.template_utils import load_export_template, render_template


def export_listing_csv(
    file_path: str,
    headers: list[str],
    rows: list[list[str]],
    *,
    project: Project | None = None,
    project_name: str = "",
    dataset_meta: dict | None = None,
) -> None:
    case_context = build_case_context(project, project_name=project_name, dataset_meta=dataset_meta)
    export_tabular_csv(
        file_path,
        headers,
        rows,
        metadata_rows=case_export_metadata_rows(case_context),
    )


def export_listing_excel(
    file_path: str,
    headers: list[str],
    rows: list[list[str]],
    *,
    sheet_title: str = "Data",
    project: Project | None = None,
    project_name: str = "",
    dataset_meta: dict | None = None,
) -> None:
    case_context = build_case_context(project, project_name=project_name, dataset_meta=dataset_meta)
    export_tabular_excel(
        file_path,
        headers,
        rows,
        sheet_title=sheet_title,
        metadata_rows=case_export_metadata_rows(case_context),
    )


def export_listing_html(
    file_path: str,
    headers: list[str],
    rows: list[list[str]],
    dataset: str,
    view_mode: str,
    files_count: int,
    meta: dict | None = None,
    project: Project | None = None,
    project_name: str = "",
    period: str = "",
) -> None:
    path = Path(file_path)
    text = _report_text()
    meta = meta or {}
    case_context = build_case_context(project, project_name=project_name, dataset_meta=meta)
    dataset_name = Path(dataset).name if dataset else "(no dataset)"
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    period_value = header_value(period, period_label_from_meta(meta), case_context.get("order_validity"))
    project_label = html.escape(project_name or case_context.get("project") or "Project")

    table_headers = "".join(f"<th>{html.escape(str(header))}</th>" for header in headers)
    table_rows = "\n".join(
        "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>"
        for row in rows
    )

    rendered = render_template(
        load_export_template("listing_export.html"),
        {
            "LANG": "en",
            "TITLE": text["title"],
            "DOCUMENT_TYPE": text["document_type"],
            "REPORT_TITLE": text["title"],
            "PERIOD_LABEL": text["period"],
            "PERIOD": html.escape(period_value),
            "EXPORTED_LABEL": text["exported"],
            "EXPORTED_AT": generated_at,
            "SOURCE_LABEL": text["dataset"],
            "SOURCE": html.escape(dataset_name),
            "SCOPE_LABEL": text["scope"],
            "SCOPE": html.escape(
                f"{len(rows):,} rows · {len(headers)} columns · {files_count} {text['json_files'].casefold()} · {view_mode or '—'}"
            ),
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
    path.write_text(rendered, encoding="utf-8")


def _report_text() -> dict[str, str]:
    return {
        "title": "Listing Report",
        "document_type": "Listing",
        "dataset": "Dataset",
        "exported": "Exported",
        "period": "Period",
        "scope": "Scope",
        "case_context": "Case context",
        "json_files": "JSON files",
        "table_title": "Listing Data",
        "prepared": "Prepared",
    }
