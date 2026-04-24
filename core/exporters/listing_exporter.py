from __future__ import annotations

import csv
import html
import base64
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
    meta: dict | None = None,
) -> None:
    path = Path(file_path)

    meta = meta or {}

    def _fmt_date(value: str) -> str:
        if not value or value == "-":
            return "-"
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return dt.strftime("%d.%m.%Y.")
        except Exception:
            return str(value)

    klasa = str(meta.get("OrigRegNo") or "-")
    urbroj = str(meta.get("RegNo") or "-")
    target = str(meta.get("target") or "-")
    targettype = str(meta.get("targettype") or "")

    target_display = target

    bt = _fmt_date(str(meta.get("bt") or ""))
    et = _fmt_date(str(meta.get("et") or ""))

    period = "-"
    if bt != "-" or et != "-":
        period = f"{bt} – {et}"

    dataset_name = Path(dataset).name if dataset else "(no dataset)"
    project_root = Path(__file__).resolve().parents[2]
    logo_path = project_root / "assets" / "ConduVia.png"

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
        .replace("{{TITLE}}", "ConduVia Listing Export")
        .replace("{{LOGO}}", html.escape(logo_data_uri))
        .replace("{{DATASET}}", html.escape(dataset_name))
        .replace("{{EXPORTED_AT}}", datetime.now().strftime("%d.%m.%Y %H:%M:%S"))
        .replace("{{VIEW_MODE}}", html.escape(view_mode or "Unknown"))
        .replace("{{KLASA}}", html.escape(klasa))
        .replace("{{URBROJ}}", html.escape(urbroj))
        .replace("{{TARGET}}", html.escape(target_display))
        .replace("{{PERIOD}}", html.escape(period))
        .replace("{{ROWS_COUNT}}", str(len(rows)))
        .replace("{{COLUMNS_COUNT}}", str(len(headers)))
        .replace("{{FILES_COUNT}}", str(files_count))
        .replace("{{TABLE_HEADERS}}", table_headers)
        .replace("{{TABLE_ROWS}}", table_rows)
    )

    path.write_text(rendered, encoding="utf-8")