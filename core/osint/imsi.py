from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from core.osint.enrichers.base import EnrichResult

PACKAGE_DIR = Path(__file__).resolve().parent
MCC_MNC_PATH = PACKAGE_DIR / "data" / "mcc_mnc.json"
IMSI_RE = re.compile(r"^\d{5,15}$")
DEFAULT_HR_MCC = "219"


def normalize_imsi(value: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if 5 <= len(digits) <= 15:
        return digits
    return ""


def is_imsi_target_type(target_type: str) -> bool:
    return "imsi" in str(target_type or "").strip().casefold()


def format_intercept_imsi(value: str, *, default_mcc: str = DEFAULT_HR_MCC) -> str:
    """Normalize IMSI values from intercept JSON exports for display and lookup."""
    raw = str(value or "").strip()
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return raw

    mcc = str(default_mcc or DEFAULT_HR_MCC).strip()
    if mcc and digits.startswith(mcc) and len(digits) in {14, 15}:
        return digits

    # MNC-first export (e.g. 01370011193097) — prepend default MCC.
    if len(digits) in {13, 14} and digits.startswith("01"):
        return f"{mcc}{digits}"

    # Observed export drops leading MCC digits (e.g. 901370011193097 -> 21901370011193097).
    if len(digits) in {14, 15} and mcc and not digits.startswith(mcc):
        prefixed = f"21{digits}"
        if prefixed.startswith(mcc):
            return prefixed

    return digits


def imsi_lookup_values(value: str, *, default_mcc: str = DEFAULT_HR_MCC) -> list[str]:
    raw = str(value or "").strip()
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return []
    values = [digits, normalize_imsi(raw), format_intercept_imsi(raw, default_mcc=default_mcc)]
    if raw and raw not in values:
        values.append(raw)
    seen: list[str] = []
    for item in values:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.append(text)
    return seen


def format_identifier_display(value: str, identifier_type: str = "") -> str:
    """Format an identifier for UI display."""
    raw = str(value or "").strip()
    kind = str(identifier_type or "").strip()
    if not raw:
        return ""
    if is_imsi_target_type(kind):
        return format_intercept_imsi(raw)
    kind_fold = kind.casefold()
    if kind_fold in {"msisdn", "imsi", "imei", "oib", "target", "isdndataonly"}:
        compact = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
        if compact.startswith("+"):
            compact = compact[1:]
        return compact or raw
    return raw


@lru_cache(maxsize=1)
def _mcc_mnc_table() -> dict:
    if not MCC_MNC_PATH.exists():
        return {}
    try:
        return json.loads(MCC_MNC_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def decode_imsi(value: str) -> EnrichResult:
    imsi = normalize_imsi(format_intercept_imsi(value))
    if not imsi:
        return EnrichResult("operator_decode", "identifier", value, status="error", summary="Invalid IMSI format.")

    mcc = imsi[:3]
    mnc2 = imsi[3:5]
    mnc3 = imsi[3:6]
    table = _mcc_mnc_table()
    country_block = table.get(mcc) or {}
    country = str(country_block.get("country") or "")
    operators = country_block.get("operators") or {}

    operator = operators.get(mnc3) or operators.get(mnc2) or ""
    mnc = mnc3 if mnc3 in operators else (mnc2 if mnc2 in operators else mnc2)

    details = {
        "imsi": imsi,
        "mcc": mcc,
        "mnc": mnc,
        "country": country or "Unknown",
        "operator": operator or "Unknown",
        "source": "offline MCC/MNC table",
    }
    if operator:
        summary = f"{country} · {operator} (MCC {mcc}, MNC {mnc})"
        status = "ok"
    else:
        summary = f"MCC {mcc} / MNC {mnc} not mapped in local table."
        status = "error"

    return EnrichResult(
        "operator_decode",
        "identifier",
        imsi,
        status=status,
        summary=summary,
        details=details,
    )
