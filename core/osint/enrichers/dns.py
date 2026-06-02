from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request

from core.osint.enrichers.base import EnrichResult

_DNS_TYPES = {
    "A": 1,
    "AAAA": 28,
    "MX": 15,
    "NS": 2,
    "TXT": 16,
}


def enrich_dns(entity_kind: str, entity_value: str) -> EnrichResult:
    if entity_kind != "domain":
        return EnrichResult("dns", entity_kind, entity_value, status="error", summary="DNS lookup supports domains only.")

    domain = str(entity_value or "").strip().rstrip(".")
    if not domain:
        return EnrichResult("dns", entity_kind, entity_value, status="error", summary="Missing domain.")

    records: dict[str, list[str]] = {}

    for rrtype in ("A", "AAAA"):
        try:
            family = socket.AF_INET if rrtype == "A" else socket.AF_INET6
            answers = socket.getaddrinfo(domain, None, family=family, type=socket.SOCK_STREAM)
            values = []
            for item in answers:
                ip = item[4][0]
                if ip not in values:
                    values.append(ip)
            if values:
                records[rrtype] = values
        except Exception:
            continue

    for rrtype, type_id in _DNS_TYPES.items():
        if rrtype in records:
            continue
        values = _query_google_dns(domain, type_id)
        if values:
            records[rrtype] = values

    if not records:
        return EnrichResult("dns", entity_kind, entity_value, status="error", summary=f"No DNS records found for {domain}.")

    return EnrichResult(
        "dns",
        entity_kind,
        entity_value,
        summary=f"DNS for {domain}",
        details=records,
    )


def _query_google_dns(domain: str, type_id: int) -> list[str]:
    url = f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type={type_id}"
    try:
        with urllib.request.urlopen(url, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception:
        return []

    answers = payload.get("Answer") or []
    values: list[str] = []
    for row in answers:
        data = str(row.get("data") or "").strip()
        if not data:
            continue
        if type_id == 15 and " " in data:
            data = data.split(" ", 1)[1].strip()
        data = data.rstrip(".")
        if data and data not in values:
            values.append(data)
    return values
