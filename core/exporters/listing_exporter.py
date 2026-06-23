from __future__ import annotations

import html
import base64
from datetime import datetime
from pathlib import Path

from core.db import Project
from core.exporters.case_context import (
    build_case_context,
    case_context_table_html,
    case_export_metadata_rows,
)
from core.exporters.tabular_export import export_tabular_csv, export_tabular_excel


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


def _load_listing_html_template() -> str:
    project_root = Path(__file__).resolve().parents[2]
    template_path = project_root / "templates" / "listing_export.html"
    return template_path.read_text(encoding="utf-8")


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
) -> None:
    path = Path(file_path)
    text = _report_text()

    meta = meta or {}
    case_context = build_case_context(project, project_name=project_name, dataset_meta=meta)
    dataset_name = Path(dataset).name if dataset else "(no dataset)"
    project_root = Path(__file__).resolve().parents[2]
    logo_path = project_root / "assets" / "ViaNyquist.png"

    logo_data_uri = ""
    if logo_path.exists():
        logo_b64 = base64.b64encode(logo_path.read_bytes()).decode("ascii")
        logo_data_uri = f"data:image/png;base64,{logo_b64}"

    template = _load_listing_html_template()

    table_headers = "".join(
        f"<th>{html.escape(str(header))}</th>"
        for header in headers
    )

    table_rows_parts = []
    for row in rows:
        cells = "".join(
            f"<td>{html.escape(str(cell))}</td>"
            for cell in row
        )
        table_rows_parts.append(f"<tr>{cells}</tr>")

    table_rows = "\n".join(table_rows_parts)

    rendered = (
        template
        .replace("{{LANG}}", "en")
        .replace("{{TITLE}}", html.escape(text["title"]))
        .replace("{{REPORT_TITLE}}", html.escape(text["title"]))
        .replace("{{LOGO}}", html.escape(logo_data_uri))
        .replace("{{DATASET}}", html.escape(dataset_name))
        .replace("{{DATASET_LABEL}}", html.escape(text["dataset"]))
        .replace("{{EXPORTED_AT}}", datetime.now().strftime("%d.%m.%Y %H:%M:%S"))
        .replace("{{EXPORTED_LABEL}}", html.escape(text["exported"]))
        .replace("{{VIEW_MODE}}", html.escape(view_mode or "Unknown"))
        .replace("{{VIEW_LABEL}}", html.escape(text["view"]))
        .replace("{{CASE_TABLE}}", case_context_table_html(case_context))
        .replace("{{ROWS_COUNT}}", str(len(rows)))
        .replace("{{ROWS_LABEL}}", html.escape(text["rows"]))
        .replace("{{COLUMNS_COUNT}}", str(len(headers)))
        .replace("{{COLUMNS_LABEL}}", html.escape(text["columns"]))
        .replace("{{FILES_COUNT}}", str(files_count))
        .replace("{{JSON_FILES_LABEL}}", html.escape(text["json_files"]))
        .replace("{{TABLE_TITLE}}", html.escape(text["table_title"]))
        .replace("{{TABLE_HEADERS}}", table_headers)
        .replace("{{TABLE_ROWS}}", table_rows)
    )

    path.write_text(rendered, encoding="utf-8")


def _report_text() -> dict[str, str]:
    return {
        "title": "ViaNyquist Listing Report",
        "dataset": "Dataset",
        "exported": "Exported",
        "view": "View",
        "rows": "Rows",
        "columns": "Columns",
        "json_files": "JSON files",
        "table_title": "Listing Data",
    }
