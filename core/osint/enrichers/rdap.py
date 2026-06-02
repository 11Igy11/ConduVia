from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from core.osint.enrichers.base import EnrichResult
from core.osint.registrable_domain import registrable_domain

_USER_AGENT = "ViaNyquist/1.0 (+local-investigation-tool)"


def enrich_rdap(entity_kind: str, entity_value: str) -> EnrichResult:
    if entity_kind not in {"domain", "ip"}:
        return EnrichResult("rdap", entity_kind, entity_value, status="error", summary="RDAP supports domains and IPs only.")

    value = str(entity_value or "").strip()
    if not value:
        return EnrichResult("rdap", entity_kind, entity_value, status="error", summary="Missing value.")

    lookup = value
    if entity_kind == "domain":
        lookup = registrable_domain(value) or value

    path = f"domain/{lookup}" if entity_kind == "domain" else f"ip/{value}"
    url = f"https://rdap.org/{path}"

    try:
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/rdap+json"})
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        return EnrichResult("rdap", entity_kind, entity_value, status="error", summary=f"RDAP HTTP {exc.code} for {value}.")
    except Exception as exc:
        return EnrichResult("rdap", entity_kind, entity_value, status="error", summary=f"RDAP lookup failed: {exc}")

    details = _extract_rdap_details(payload)
    if entity_kind == "domain" and lookup != value:
        details["observed_host"] = value
        details["registrable_domain"] = lookup
    summary = details.pop("summary", f"RDAP for {lookup}")
    return EnrichResult("rdap", entity_kind, entity_value, summary=summary, details=details)


def _extract_rdap_details(payload: dict) -> dict:
    details: dict = {}
    entities = payload.get("entities") or []
    registrar = ""
    for entity in entities:
        roles = entity.get("roles") or []
        if "registrar" in roles:
            vcard = entity.get("vcardArray") or []
            registrar = _vcard_fn(vcard) or str(entity.get("handle") or "")
            break

    events = payload.get("events") or []
    created = _event_date(events, "registration")
    updated = _event_date(events, "last changed")
    expires = _event_date(events, "expiration")

    status = ", ".join(str(item) for item in (payload.get("status") or [])[:5])
    name = str(payload.get("name") or payload.get("handle") or "").strip()
    country = ""
    for entity in entities:
        vcard = entity.get("vcardArray") or []
        country = _vcard_country(vcard)
        if country:
            break

    summary_bits = [bit for bit in (name, registrar, country) if bit]
    details["summary"] = " | ".join(summary_bits) if summary_bits else "RDAP record"
    if registrar:
        details["registrar"] = registrar
    if created:
        details["created"] = created
    if updated:
        details["updated"] = updated
    if expires:
        details["expires"] = expires
    if status:
        details["status"] = status
    if country:
        details["country"] = country
    return details


def _event_date(events: list, action: str) -> str:
    for event in events:
        if str(event.get("eventAction") or "").lower() == action:
            return str(event.get("eventDate") or "")
    return ""


def _vcard_fn(vcard) -> str:
    if not isinstance(vcard, list) or len(vcard) < 2:
        return ""
    for row in vcard[1]:
        if isinstance(row, list) and len(row) >= 4 and row[0] == "fn":
            return str(row[3] or "")
    return ""


def _vcard_country(vcard) -> str:
    if not isinstance(vcard, list) or len(vcard) < 2:
        return ""
    for row in vcard[1]:
        if isinstance(row, list) and len(row) >= 4 and row[0] == "adr":
            parts = row[3]
            if isinstance(parts, list) and len(parts) >= 7:
                return str(parts[6] or "")
    return ""
