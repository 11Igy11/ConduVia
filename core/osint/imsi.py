from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from core.osint.enrichers.base import EnrichResult

PACKAGE_DIR = Path(__file__).resolve().parent
MCC_MNC_PATH = PACKAGE_DIR / "data" / "mcc_mnc.json"
IMSI_RE = re.compile(r"^\d{5,15}$")


def normalize_imsi(value: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if 5 <= len(digits) <= 15:
        return digits
    return ""


@lru_cache(maxsize=1)
def _mcc_mnc_table() -> dict:
    if not MCC_MNC_PATH.exists():
        return {}
    try:
        return json.loads(MCC_MNC_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def decode_imsi(value: str) -> EnrichResult:
    imsi = normalize_imsi(value)
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
