from __future__ import annotations

import html
import re
from pathlib import Path
from typing import Any


def stats_html(items: list[tuple[str, Any]]) -> str:
    cards = []
    for label, value in items:
        cards.append(
            '<div class="stat">'
            f'<div class="t">{html.escape(str(label))}</div>'
            f'<div class="v">{html.escape(str(value))}</div>'
            "</div>"
        )
    if not cards:
        return ""
    return f'<div class="stats">{"".join(cards)}</div>'


def ranked_list_html(
    title: str,
    rows: list[Any],
    *,
    empty_text: str = "No records.",
    limit: int = 24,
    label_key: str = "label",
    value_key: str = "count",
    value_label_key: str = "",
    meta_key: str = "",
) -> str:
    heading = f"<h3>{html.escape(title)}</h3>" if title else ""
    parsed = _ranked_items(
        rows,
        limit=limit,
        label_key=label_key,
        value_key=value_key,
        value_label_key=value_label_key,
        meta_key=meta_key,
    )
    if not parsed:
        return f'{heading}<div class="empty">{html.escape(empty_text)}</div>'

    max_value = max(item[2] for item in parsed) or 1.0
    body = []
    for index, (label, display, numeric, meta) in enumerate(parsed, start=1):
        width = max(2.0, min(100.0, (numeric / max_value) * 100.0)) if numeric else 0.0
        meta_html = f'<div class="rank-meta">{html.escape(meta)}</div>' if meta else ""
        body.append(
            '<div class="rank-row">'
            f'<span class="rank">{index}</span>'
            "<div>"
            f'<div class="rank-name">{html.escape(label)}</div>'
            f"{meta_html}"
            "</div>"
            f"<strong>{html.escape(display)}</strong>"
            f'<div class="rank-bar"><div class="bar"><span style="width:{width:.1f}%"></span></div></div>'
            "</div>"
        )
    return heading + "".join(body)


def _ranked_items(
    rows: list[Any],
    *,
    limit: int,
    label_key: str,
    value_key: str,
    value_label_key: str,
    meta_key: str,
) -> list[tuple[str, str, float, str]]:
    parsed: list[tuple[str, str, float, str]] = []
    for row in list(rows or [])[:limit]:
        if isinstance(row, dict):
            label = str(row.get(label_key) or row.get("service") or row.get("domain") or row.get("query") or row.get("host") or "-")
            numeric = _numeric(row.get(value_key))
            if numeric <= 0:
                numeric = _numeric(row.get("share"))
            display = str(row.get(value_label_key) or row.get("bytes_label") or row.get(value_key) or display_number(numeric))
            meta = str(row.get(meta_key) or row.get("detail") or row.get("example") or "")
        else:
            label = str(row[0] if row else "-")
            raw_value = row[1] if len(row) > 1 else 0
            numeric = _numeric(raw_value)
            display = str(raw_value)
            meta = str(row[2]) if len(row) > 2 else ""
        parsed.append((label, display, numeric, meta))
    return parsed


def period_label_from_meta(meta: dict[str, Any] | None) -> str:
    from core.formatters import format_short_date

    meta = meta or {}
    start = format_short_date(meta.get("bt"), missing="") if meta.get("bt") else ""
    end = format_short_date(meta.get("et"), missing="") if meta.get("et") else ""
    if start and end:
        return f"{start} – {end}"
    return start or end or ""


def header_value(*candidates: Any, empty: str = "—") -> str:
    for value in candidates:
        text = str(value or "").strip()
        if text and text not in {"-", "—"}:
            return text
    return empty


def format_export_source_label(path: Any) -> str:
    text = str(path or "").strip()
    if not text:
        return ""
    name = Path(text).name.strip()
    return name or text


def format_selected_period_label(
    *,
    active_day: str = "",
    granularity: str = "day",
    range_start: str = "",
    range_end: str = "",
) -> str:
    from core.evidence_policy import format_period_day_label

    mode = str(granularity or "day")
    start = str(range_start or "").strip()
    end = str(range_end or "").strip()
    if mode == "range" and (start or end):
        left = format_period_day_label(start) if start else ""
        right = format_period_day_label(end) if end else ""
        if left and right:
            return f"{left} – {right}"
        return left or right
    day = str(active_day or "").strip()
    return format_period_day_label(day) if day else ""


def display_number(value: float) -> str:
    if value <= 0:
        return "0"
    if value.is_integer():
        return f"{int(value):,}"
    return f"{value:.1f}"


def _numeric(value: Any) -> float:
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value or "").strip().replace(",", "")
    if not text:
        return 0.0
    match = re.search(r"-?\d+(?:\.\d+)?", text)
    if not match:
        return 0.0
    try:
        number = float(match.group(0))
    except Exception:
        return 0.0
    lowered = text.casefold()
    if "gb" in lowered:
        return number * 1024 ** 3
    if "mb" in lowered:
        return number * 1024 ** 2
    if "kb" in lowered:
        return number * 1024
    return number
