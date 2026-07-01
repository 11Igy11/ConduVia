from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from core.db import DEFAULT_DB_PATH, get_project, update_project_case_metadata
from core.formatters import format_flow_datetime
from core.timeutils import LOCAL_TZ, parse_timestamp

LAWFUL_INTERCEPTION_DATES_LABEL = "Lawful interception dates"
LAWFUL_INTERCEPTION_DATES_ACTIVE_LABEL = f"{LAWFUL_INTERCEPTION_DATES_LABEL} (active)"
EARLIER_LAWFUL_INTERCEPTION_DATES_LABEL = "Earlier lawful interception dates"
LAWFUL_INTERCEPTION_PERIOD_PICKER_TITLE = "Lawful interception periods"


def _now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def empty_case_metadata() -> dict[str, Any]:
    return {
        "klasa_entries": [],
        "urbroj_entries": [],
        "order_validity_periods": [],
        "active_order_validity": {"bt": "", "et": ""},
        "active_klasa": "",
        "active_urbroj": "",
    }


def load_case_metadata(project_id: int, *, db_path: Path = DEFAULT_DB_PATH) -> dict[str, Any]:
    project = get_project(project_id, db_path=db_path)
    if not project:
        return empty_case_metadata()
    raw = str(getattr(project, "case_metadata_json", "") or "").strip()
    if not raw:
        return empty_case_metadata()
    try:
        data = json.loads(raw)
    except Exception:
        return empty_case_metadata()
    if not isinstance(data, dict):
        return empty_case_metadata()
    base = empty_case_metadata()
    for key in base:
        if key in data:
            base[key] = data[key]
    return base


def save_case_metadata(project_id: int, metadata: dict[str, Any], *, db_path: Path = DEFAULT_DB_PATH) -> None:
    update_project_case_metadata(project_id, json.dumps(metadata, ensure_ascii=False), db_path=db_path)


def format_order_datetime(value: Any, *, missing: str = "-") -> str:
    text = str(value or "").strip()
    if not text:
        return missing
    formatted = format_flow_datetime(text)
    return formatted or text


def _parse_order_datetime(value: str) -> datetime | None:
    dt = parse_timestamp(value)
    if dt is not None:
        return dt
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%d.%m.%Y %H:%M:%S", "%d.%m.%Y"):
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed.replace(tzinfo=LOCAL_TZ)
        except Exception:
            continue
    return None


def _same_order_datetime(left: str, right: str) -> bool:
    left_dt = _parse_order_datetime(str(left or "").strip())
    right_dt = _parse_order_datetime(str(right or "").strip())
    if left_dt is not None and right_dt is not None:
        return left_dt == right_dt
    return str(left or "").strip() == str(right or "").strip()


def _canonical_order_datetime(value: str) -> str:
    dt = _parse_order_datetime(str(value or "").strip())
    if dt is None:
        return str(value or "").strip()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _append_unique_entry(
    entries: list[dict[str, Any]],
    *,
    value: str,
    source: str,
    extra: dict[str, Any] | None = None,
) -> bool:
    text = str(value or "").strip()
    if not text or text == "-":
        return False
    for row in entries:
        if str(row.get("value") or "").strip() == text:
            return False
    item = {"value": text, "source": source, "recorded_at": _now_iso()}
    if extra:
        item.update(extra)
    entries.append(item)
    return True


def active_klasa_value(metadata: dict[str, Any]) -> str:
    explicit = str(metadata.get("active_klasa") or "").strip()
    if explicit:
        return explicit
    entries = list(metadata.get("klasa_entries") or [])
    if entries:
        return str(entries[-1].get("value") or "").strip()
    return ""


def active_urbroj_value(metadata: dict[str, Any]) -> str:
    explicit = str(metadata.get("active_urbroj") or "").strip()
    if explicit:
        return explicit
    entries = list(metadata.get("urbroj_entries") or [])
    if entries:
        return str(entries[-1].get("value") or "").strip()
    return ""


def merged_order_validity_bounds(metadata: dict[str, Any]) -> tuple[str, str]:
    periods = list(metadata.get("order_validity_periods") or [])
    best_start = ("", None)
    best_end = ("", None)
    for row in periods:
        bt_s = str(row.get("bt") or "").strip()
        et_s = str(row.get("et") or "").strip()
        bt_dt = parse_timestamp(bt_s)
        et_dt = parse_timestamp(et_s)
        if bt_dt and (best_start[1] is None or bt_dt < best_start[1]):
            best_start = (bt_s, bt_dt)
        if et_dt and (best_end[1] is None or et_dt > best_end[1]):
            best_end = (et_s, et_dt)
    if best_start[0] or best_end[0]:
        return best_start[0], best_end[0]
    active = dict(metadata.get("active_order_validity") or {})
    return str(active.get("bt") or "").strip(), str(active.get("et") or "").strip()


def refresh_merged_order_validity_active(metadata: dict[str, Any]) -> dict[str, Any]:
    data = dict(metadata or empty_case_metadata())
    bt, et = merged_order_validity_bounds(data)
    data["active_order_validity"] = {"bt": bt, "et": et, "source_file": "merged"}
    return data


def order_validity_period_rows(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(metadata.get("order_validity_periods") or [], start=1):
        bt_raw = str(row.get("bt") or "").strip()
        et_raw = str(row.get("et") or "").strip()
        rows.append({
            "label": f"Period {index}",
            "from": format_order_datetime(bt_raw, missing=""),
            "to": format_order_datetime(et_raw, missing=""),
            "bt_raw": bt_raw,
            "et_raw": et_raw,
            "source": str(row.get("source_file") or row.get("source") or ""),
        })
    return rows


def apply_manual_case_fields(
    metadata: dict[str, Any],
    *,
    klasa: str = "",
    urbroj: str = "",
    order_validity_bt: str = "",
    order_validity_et: str = "",
) -> dict[str, Any]:
    data = dict(metadata or empty_case_metadata())
    klasa_text = str(klasa or "").strip()
    urbroj_text = str(urbroj or "").strip()
    if klasa_text:
        data["active_klasa"] = klasa_text
        _append_unique_entry(
            data.setdefault("klasa_entries", []),
            value=klasa_text,
            source="manual",
        )
    if urbroj_text:
        data["active_urbroj"] = urbroj_text
        _append_unique_entry(
            data.setdefault("urbroj_entries", []),
            value=urbroj_text,
            source="manual",
        )
    bt = _canonical_order_datetime(str(order_validity_bt or "").strip())
    et = _canonical_order_datetime(str(order_validity_et or "").strip())
    if bt or et:
        merged_bt, merged_et = merged_order_validity_bounds(data)
        unchanged_merged = _same_order_datetime(bt, merged_bt) and _same_order_datetime(et, merged_et)
        if not unchanged_merged:
            periods = list(data.setdefault("order_validity_periods", []))
            duplicate = any(
                _same_order_datetime(str(row.get("bt") or ""), bt)
                and _same_order_datetime(str(row.get("et") or ""), et)
                for row in periods
            )
            if not duplicate:
                periods.append({"bt": bt, "et": et, "source_file": "manual", "recorded_at": _now_iso()})
                data["order_validity_periods"] = periods
        data = refresh_merged_order_validity_active(data)
    return data


def sync_case_metadata_from_json(
    project_id: int,
    meta: dict[str, Any],
    *,
    source_file: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> list[str]:
    metadata = load_case_metadata(project_id, db_path=db_path)
    updated, warnings = merge_json_case_metadata(
        metadata,
        klasa=str(meta.get("OrigRegNo") or ""),
        urbroj=str(meta.get("RegNo") or ""),
        bt=str(meta.get("bt") or ""),
        et=str(meta.get("et") or ""),
        source_file=source_file,
    )
    save_case_metadata(project_id, updated, db_path=db_path)
    return warnings


def merge_json_case_metadata(
    metadata: dict[str, Any],
    *,
    klasa: str = "",
    urbroj: str = "",
    bt: str = "",
    et: str = "",
    source_file: str = "",
) -> tuple[dict[str, Any], list[str]]:
    """Append metadata from a JSON dataset; return updated metadata and warning lines."""
    data = dict(metadata or empty_case_metadata())
    warnings: list[str] = []
    source = str(source_file or "json").strip() or "json"

    klasa_text = str(klasa or "").strip()
    urbroj_text = str(urbroj or "").strip()
    bt_text = str(bt or "").strip()
    et_text = str(et or "").strip()

    if klasa_text and klasa_text != "-":
        existing = [str(row.get("value") or "") for row in data.get("klasa_entries") or []]
        if existing and klasa_text not in existing:
            warnings.append(f"Klasa differs from saved values ({', '.join(existing[:3])}).")
        if _append_unique_entry(data.setdefault("klasa_entries", []), value=klasa_text, source=source):
            data["active_klasa"] = klasa_text

    if urbroj_text and urbroj_text != "-":
        existing = [str(row.get("value") or "") for row in data.get("urbroj_entries") or []]
        if existing and urbroj_text not in existing:
            warnings.append(f"Urbroj differs from saved values ({', '.join(existing[:3])}).")
        if _append_unique_entry(data.setdefault("urbroj_entries", []), value=urbroj_text, source=source):
            data["active_urbroj"] = urbroj_text

    if bt_text or et_text:
        periods = list(data.setdefault("order_validity_periods", []))
        duplicate = any(
            str(row.get("bt") or "") == bt_text and str(row.get("et") or "") == et_text
            for row in periods
        )
        if not duplicate:
            periods.append({
                "bt": bt_text,
                "et": et_text,
                "source_file": source,
                "recorded_at": _now_iso(),
            })
            data["order_validity_periods"] = periods
        data = refresh_merged_order_validity_active(data)

    return data, warnings


def format_klasa_all(metadata: dict[str, Any]) -> str:
    values = [str(row.get("value") or "") for row in metadata.get("klasa_entries") or [] if str(row.get("value") or "")]
    return "; ".join(values) if values else "-"


def format_urbroj_all(metadata: dict[str, Any]) -> str:
    values = [str(row.get("value") or "") for row in metadata.get("urbroj_entries") or [] if str(row.get("value") or "")]
    return "; ".join(values) if values else "-"


def format_klasa_summary(metadata: dict[str, Any]) -> str:
    value = active_klasa_value(metadata)
    return value or "-"


def format_urbroj_summary(metadata: dict[str, Any]) -> str:
    value = active_urbroj_value(metadata)
    return value or "-"


def format_active_order_validity(metadata: dict[str, Any]) -> str:
    bt, et = merged_order_validity_bounds(metadata)
    if bt or et:
        return f"{format_order_datetime(bt)} → {format_order_datetime(et)}"
    return "-"


def format_order_validity_history(metadata: dict[str, Any], *, preview: int = 0) -> str:
    rows = order_validity_period_rows(metadata)
    if not rows:
        return ""
    if preview > 0:
        rows = rows[-preview:]
    labels = [f"{row['from']} → {row['to']}" for row in rows if row.get("from") or row.get("to")]
    return "; ".join(labels)
