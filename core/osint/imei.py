from __future__ import annotations

import re

from core.osint.enrichers.base import EnrichResult
from core.osint.tac_store import lookup_tac, normalize_tac

IMEI_RE = re.compile(r"^\d{14,16}$")


def normalize_imei(value: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) == 15:
        return digits
    if len(digits) == 16 and digits.endswith("0"):
        return digits[:15]
    if 14 <= len(digits) <= 16:
        return digits[:15]
    return ""


def expected_luhn_check_digit(imei: str) -> int | None:
    digits = normalize_imei(imei)
    if len(digits) != 15:
        return None
    total = 0
    for index, ch in enumerate(digits[:14]):
        n = int(ch)
        if index % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return (10 - (total % 10)) % 10


def imei_luhn_valid(imei: str) -> bool:
    digits = normalize_imei(imei)
    if len(digits) != 15:
        return False
    expected = expected_luhn_check_digit(digits)
    if expected is None:
        return False
    return expected == int(digits[14])


def decode_imei(value: str) -> EnrichResult:
    imei = normalize_imei(value)
    if not imei:
        return EnrichResult("imei_decode", "identifier", value, status="error", summary="Invalid IMEI format.")

    tac = normalize_tac(imei)
    valid = imei_luhn_valid(imei)
    expected_check = expected_luhn_check_digit(imei)
    entry = lookup_tac(tac)

    details: dict[str, object] = {
        "imei": imei,
        "tac": tac,
        "luhn_valid": valid,
    }
    if not valid and expected_check is not None:
        details["expected_check_digit"] = expected_check
        details["checksum_note"] = "Invalid Luhn checksum is common in operator exports; TAC decode still applies."
    if entry:
        details["manufacturer"] = entry.get("manufacturer") or ""
        details["model"] = entry.get("model") or ""
        if entry.get("device_type"):
            details["device_type"] = entry.get("device_type")

    if entry and (entry.get("manufacturer") or entry.get("model")):
        summary = " ".join(
            part
            for part in (
                entry.get("manufacturer"),
                entry.get("model"),
            )
            if part
        )
        if not valid:
            summary = f"{summary} (checksum invalid)"
        status = "ok"
    elif valid:
        summary = f"Unknown TAC {tac}. Import a larger TAC database in Settings."
        status = "ok"
    else:
        summary = (
            f"Unknown TAC {tac}. Checksum invalid (common in operator exports). "
            f"Expected check digit: {expected_check}. Import a larger TAC database in Settings."
        )
        status = "warning"

    return EnrichResult("imei_decode", "identifier", imei, status=status, summary=summary, details=details)
