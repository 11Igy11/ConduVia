from __future__ import annotations

import re

from core.osint.enrichers.base import EnrichResult
from core.osint.normalize import normalize_msisdn

# HR mobile prefixes — heuristic hints only (number portability shared prefixes).
HR_PREFIX_HINTS: tuple[tuple[str, str], ...] = (
    ("38591", "Hrvatski Telekom / A1 (shared 091 prefix)"),
    ("38592", "Hrvatski Telekom / A1 (shared 092 prefix)"),
    ("38595", "Telemach / Hrvatski Telekom (shared 095 prefix)"),
    ("38597", "Hrvatski Telekom (097 prefix)"),
    ("38598", "Hrvatski Telekom (098 prefix)"),
    ("38599", "Hrvatski Telekom (099 prefix)"),
)


def decode_msisdn_operator(value: str) -> EnrichResult:
    msisdn = normalize_msisdn(value)
    if not msisdn:
        return EnrichResult("operator_decode", "identifier", value, status="error", summary="Invalid mobile number.")

    digits = re.sub(r"\D", "", msisdn)
    if not digits.startswith("385"):
        return EnrichResult(
            "operator_decode",
            "identifier",
            msisdn,
            status="error",
            summary="Carrier hint available for Croatian (+385) numbers only.",
            details={"msisdn": msisdn, "source": "offline HR prefix table"},
        )

    hint = ""
    for prefix, label in HR_PREFIX_HINTS:
        if digits.startswith(prefix):
            hint = label
            break

    if not hint:
        national = digits[3:]
        if national.startswith("91"):
            hint = HR_PREFIX_HINTS[0][1]
        elif national.startswith("92"):
            hint = HR_PREFIX_HINTS[1][1]
        elif national.startswith("95"):
            hint = HR_PREFIX_HINTS[2][1]

    details = {
        "msisdn": msisdn,
        "country": "Croatia",
        "hint": hint or "No HR prefix match",
        "source": "offline HR prefix table (hint, not HLR)",
    }
    if hint:
        return EnrichResult(
            "operator_decode",
            "identifier",
            msisdn,
            status="ok",
            summary=f"Croatia · {hint}",
            details=details,
        )
    return EnrichResult(
        "operator_decode",
        "identifier",
        msisdn,
        status="error",
        summary="No Croatian operator hint for this prefix.",
        details=details,
    )
