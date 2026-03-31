from __future__ import annotations

import csv
import html
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter


def export_listing_csv(file_path: str, headers: list[str], rows: list[list[str]]) -> None:
    path = Path(file_path)

    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

def export_listing_excel(file_path: str, headers: list[str], rows: list[list[str]]) -> None:
    path = Path(file_path)

    wb = Workbook()
    ws = wb.active
    ws.title = "Listing"

    # Header
    ws.append(headers)

    header_fill = PatternFill(fill_type="solid", fgColor="1F2937")
    header_font = Font(bold=True, color="FFFFFF")

    for col_idx, header in enumerate(headers, start=1):
        cell = ws.cell(row=1, column=col_idx)
        cell.fill = header_fill
        cell.font = header_font

    # Data
    for row in rows:
        ws.append(row)

    # Freeze header
    ws.freeze_panes = "A2"

    # Autofilter
    ws.auto_filter.ref = ws.dimensions

    # Autosize columns
    for col_idx, header in enumerate(headers, start=1):
        max_len = len(str(header))

        for row_idx in range(2, ws.max_row + 1):
            value = ws.cell(row=row_idx, column=col_idx).value
            if value is not None:
                max_len = max(max_len, len(str(value)))

        ws.column_dimensions[get_column_letter(col_idx)].width = min(max_len + 2, 40)

    wb.save(path)

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
) -> None:
    path = Path(file_path)

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
        .replace("{{TITLE}}", "ConduVia Listing Export")
        .replace("{{DATASET}}", html.escape(dataset or "(no dataset)"))
        .replace("{{EXPORTED_AT}}", datetime.now().strftime("%d.%m.%Y %H:%M:%S"))
        .replace("{{VIEW_MODE}}", html.escape(view_mode or "Unknown"))
        .replace("{{ROWS_COUNT}}", str(len(rows)))
        .replace("{{COLUMNS_COUNT}}", str(len(headers)))
        .replace("{{FILES_COUNT}}", str(files_count))
        .replace("{{TABLE_HEADERS}}", table_headers)
        .replace("{{TABLE_ROWS}}", table_rows)
    )

    path.write_text(rendered, encoding="utf-8")