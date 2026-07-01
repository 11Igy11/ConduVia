from __future__ import annotations

from datetime import datetime

from core.db import Project
from core.exporters.listing_exporter import export_listing_csv, export_listing_excel
from core.exporters.table_exporter import export_table_html


def build_osint_export_rows(
    *,
    entity_kind: str = "",
    entity_label: str = "",
    entity_value: str = "",
    results_text: str = "",
    exported_at: str | None = None,
) -> tuple[list[str], list[list[str]]]:
    stamp = exported_at or datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    headers = ["Field", "Value"]
    rows: list[list[str]] = [
        ["Entity type", (entity_label or entity_kind or "—").strip() or "—"],
        ["Entity value", (entity_value or "—").strip() or "—"],
        ["Exported", stamp],
        ["", ""],
    ]
    body = str(results_text or "")
    if body.strip():
        for line in body.splitlines():
            rows.append(["Result", line])
    else:
        rows.append(["Result", "(no lookup output)"])
    return headers, rows


def export_osint_results(
    file_path: str,
    export_format: str,
    *,
    entity_kind: str = "",
    entity_label: str = "",
    entity_value: str = "",
    results_text: str = "",
    project: Project | None = None,
    project_name: str = "",
    source_label: str = "",
) -> None:
    headers, rows = build_osint_export_rows(
        entity_kind=entity_kind,
        entity_label=entity_label,
        entity_value=entity_value,
        results_text=results_text,
    )
    title = f"OSINT results — {entity_value or entity_kind or 'entity'}"

    if export_format == "csv":
        export_listing_csv(file_path, headers, rows, project=project, project_name=project_name)
        return
    if export_format == "xlsx":
        export_listing_excel(
            file_path,
            headers,
            rows,
            sheet_title="OSINT results",
            project=project,
            project_name=project_name,
        )
        return
    if export_format == "html":
        export_table_html(
            file_path,
            title,
            headers,
            rows,
            project=project,
            project_name=project_name,
            source_label=source_label or entity_value,
        )
        return
    raise ValueError(f"Unsupported export format: {export_format}")
