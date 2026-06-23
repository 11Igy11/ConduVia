from __future__ import annotations

import csv
import unicodedata
from pathlib import Path

from openpyxl import Workbook
from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from core.exporters.case_context import case_export_metadata_rows

_EXCEL_MAX_CELL_LEN = 32767
_EXCEL_MAX_SHEET_TITLE_LEN = 31
_HEADER_FILL = PatternFill(fill_type="solid", fgColor="1F2937")
_HEADER_FONT = Font(bold=True, color="FFFFFF")
_META_LABEL_FONT = Font(bold=True, color="374151")


def _sanitize_excel_sheet_title(title: str) -> str:
    text = ILLEGAL_CHARACTERS_RE.sub("", str(title or ""))
    text = "".join(ch for ch in text if ch not in "[]:*?/\\'")
    text = text.strip() or "Data"
    return text[:_EXCEL_MAX_SHEET_TITLE_LEN] or "Data"


def _sanitize_excel_cell(value: object) -> str:
    if value is None:
        return ""
    text = ILLEGAL_CHARACTERS_RE.sub("", str(value))
    cleaned: list[str] = []
    for ch in text:
        code = ord(ch)
        if unicodedata.category(ch) in {"Cc", "Cs"}:
            continue
        if code in {0xFEFF} or 0xE0000 <= code <= 0xE007F:
            continue
        cleaned.append(ch)
    text = "".join(cleaned)
    if len(text) > _EXCEL_MAX_CELL_LEN:
        return text[: _EXCEL_MAX_CELL_LEN - 3] + "..."
    return text


def _autosize_columns(ws, *, min_col: int = 1, max_col: int | None = None, header_row: int = 1) -> None:
    if max_col is None:
        max_col = ws.max_column
    for col_idx in range(min_col, max_col + 1):
        max_len = 0
        for row_idx in range(header_row, ws.max_row + 1):
            value = ws.cell(row=row_idx, column=col_idx).value
            if value is not None:
                max_len = max(max_len, len(str(value)))
        ws.column_dimensions[get_column_letter(col_idx)].width = min(max(max_len + 2, 10), 48)


def _write_case_sheet(ws, metadata_rows: list[tuple[str, str]]) -> None:
    ws.title = "Case"
    ws.append(["Field", "Value"])
    for col in (1, 2):
        cell = ws.cell(row=1, column=col)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
    for label, value in metadata_rows:
        ws.append([_sanitize_excel_cell(label), _sanitize_excel_cell(value)])
        ws.cell(row=ws.max_row, column=1).font = _META_LABEL_FONT
    ws.freeze_panes = "A2"
    _autosize_columns(ws, header_row=1)


def _write_data_sheet(
    ws,
    headers: list[str],
    rows: list[list[str]],
    *,
    sheet_title: str,
) -> None:
    ws.title = _sanitize_excel_sheet_title(sheet_title)
    safe_headers = [_sanitize_excel_cell(header) for header in headers]
    ws.append(safe_headers)
    header_row = 1
    for col_idx, header in enumerate(safe_headers, start=1):
        cell = ws.cell(row=header_row, column=col_idx)
        cell.fill = _HEADER_FILL
        cell.font = _HEADER_FONT
        cell.alignment = Alignment(vertical="top", wrap_text=True)

    for row in rows:
        ws.append([_sanitize_excel_cell(cell) for cell in row])

    if safe_headers:
        last_col = get_column_letter(len(safe_headers))
        last_row = max(header_row, ws.max_row)
        ws.auto_filter.ref = f"A{header_row}:{last_col}{last_row}"

    ws.freeze_panes = "A2"
    _autosize_columns(ws, header_row=header_row)


def export_tabular_csv(
    file_path: str,
    headers: list[str],
    rows: list[list[str]],
    *,
    metadata_rows: list[tuple[str, str]],
) -> None:
    path = Path(file_path)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        if metadata_rows:
            writer.writerow(["Field", "Value"])
            writer.writerows(metadata_rows)
            writer.writerow([])
        writer.writerow(headers)
        writer.writerows(rows)


def export_tabular_excel(
    file_path: str,
    headers: list[str],
    rows: list[list[str]],
    *,
    sheet_title: str = "Data",
    metadata_rows: list[tuple[str, str]] | None = None,
) -> None:
    wb = Workbook()
    metadata_rows = metadata_rows or []

    if metadata_rows:
        _write_case_sheet(wb.active, metadata_rows)
        data_ws = wb.create_sheet()
    else:
        data_ws = wb.active

    _write_data_sheet(data_ws, headers, rows, sheet_title=sheet_title)
    wb.save(Path(file_path))
