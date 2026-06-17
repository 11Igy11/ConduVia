from __future__ import annotations

from core.osint.enrichers.base import EnrichResult
from core.osint.imei import decode_imei
from core.osint.imsi import decode_imsi
from core.osint.msisdn_carrier import decode_msisdn_operator


def decode_identifier(kind: str, value: str) -> EnrichResult | None:
    text_kind = str(kind or "").strip().upper()
    text_value = str(value or "").strip()
    if not text_value:
        return None

    if text_kind == "IMEI":
        return decode_imei(text_value)
    if text_kind == "IMSI":
        return decode_imsi(text_value)
    if text_kind in {"MSISDN", "MOBILE NUMBER", "PHONE"}:
        return decode_msisdn_operator(text_value)

    return None


def format_identifier_notes_block(
    *,
    entity_value: str,
    entity_kind: str,
    entity_type_label: str,
    registrable_domain: str = "",
    decode_result: EnrichResult | None = None,
    results_text: str = "",
) -> str:
    lines = [
        "=== OSINT ===",
        f"Entity: {entity_value}",
        f"Type: {entity_type_label or entity_kind}",
    ]
    if registrable_domain:
        lines.append(f"Registrable domain: {registrable_domain}")
    if decode_result is not None:
        lines.append(f"Decode [{decode_result.status}]: {decode_result.summary}")
        for key, value in (decode_result.details or {}).items():
            if value not in (None, ""):
                lines.append(f"  {key}: {value}")
    if results_text.strip():
        lines.append("")
        lines.append("Results:")
        lines.append(results_text.strip())
    lines.append("Source: ViaNyquist OSINT (offline/online enrichment)")
    return "\n".join(lines)
