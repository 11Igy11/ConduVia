from __future__ import annotations

import csv
import json
import re
from functools import lru_cache
from pathlib import Path

from core.db import APP_DATA_DIR, get_app_setting

PACKAGE_DIR = Path(__file__).resolve().parent
BUNDLED_TAC_PATH = PACKAGE_DIR / "data" / "tac_db.json"
IMPORTED_TAC_PATH = APP_DATA_DIR / "osint" / "tac_import.json"

TAC_RE = re.compile(r"^\d{8}$")


def normalize_tac(value: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) >= 8:
        return digits[:8]
    return ""


def _load_json_map(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if isinstance(payload, list):
        rows = {}
        for row in payload:
            if not isinstance(row, dict):
                continue
            tac = normalize_tac(str(row.get("tac") or ""))
            if tac:
                rows[tac] = row
        return rows
    if isinstance(payload, dict):
        out: dict[str, dict] = {}
        for key, row in payload.items():
            tac = normalize_tac(str(key))
            if tac and isinstance(row, dict):
                out[tac] = row
        return out
    return {}


@lru_cache(maxsize=1)
def load_tac_database() -> dict[str, dict]:
    merged: dict[str, dict] = {}
    merged.update(_load_json_map(BUNDLED_TAC_PATH))
    merged.update(_load_json_map(IMPORTED_TAC_PATH))
    return merged


def tac_entry_count() -> int:
    return len(load_tac_database())


def lookup_tac(tac: str) -> dict | None:
    key = normalize_tac(tac)
    if not key:
        return None
    row = load_tac_database().get(key)
    if not row:
        return None
    return {
        "tac": key,
        "manufacturer": str(row.get("manufacturer") or row.get("brand") or "").strip(),
        "model": str(row.get("model") or row.get("marketing_name") or row.get("name") or "").strip(),
        "device_type": str(row.get("device_type") or row.get("device") or "").strip(),
    }


def invalidate_tac_cache() -> None:
    load_tac_database.cache_clear()


def import_tac_csv(csv_path: str | Path) -> tuple[int, str]:
    path = Path(csv_path)
    if not path.exists():
        return 0, f"File not found: {path}"

    rows: dict[str, dict] = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return 0, "CSV has no header row."
        fields = {name.strip().lower(): name for name in reader.fieldnames if name}

        def pick(*names: str) -> str:
            for name in names:
                key = fields.get(name.lower())
                if key:
                    return key
            return ""

        tac_col = pick("tac", "tac_prefix", "type_allocation_code")
        brand_col = pick("manufacturer", "brand", "vendor", "make")
        model_col = pick("model", "marketing_name", "name", "device")
        type_col = pick("device_type", "device", "type")

        if not tac_col:
            return 0, "CSV must include a TAC column (tac / tac_prefix)."

        for row in reader:
            tac = normalize_tac(str(row.get(tac_col) or ""))
            if not tac:
                continue
            rows[tac] = {
                "tac": tac,
                "manufacturer": str(row.get(brand_col) or "").strip() if brand_col else "",
                "model": str(row.get(model_col) or "").strip() if model_col else "",
                "device_type": str(row.get(type_col) or "").strip() if type_col else "",
            }

    if not rows:
        return 0, "No valid 8-digit TAC rows found in CSV."

    IMPORTED_TAC_PATH.parent.mkdir(parents=True, exist_ok=True)
    IMPORTED_TAC_PATH.write_text(json.dumps(list(rows.values()), ensure_ascii=False, indent=2), encoding="utf-8")
    set_tac_import_source(str(path.resolve()))
    invalidate_tac_cache()
    return len(rows), f"Imported {len(rows):,} TAC rows from {path.name}."


def set_tac_import_source(path: str) -> None:
    from core.db import set_app_setting

    set_app_setting("osint.tac_csv_path", path or "")


def tac_import_source() -> str:
    return get_app_setting("osint.tac_csv_path", "")
