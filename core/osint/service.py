from __future__ import annotations

from core.osint.enrichers import dns, geoip, leaks, rdap, reverse_dns, shodan, virustotal
from core.osint.enrichers.base import EnrichResult
from core.osint.settings import OsintSettings, load_osint_settings


def enrich_rdap(entity_kind: str, entity_value: str, *, settings: OsintSettings | None = None) -> EnrichResult:
    return rdap.enrich_rdap(entity_kind, entity_value)


def enrich_virustotal(entity_kind: str, entity_value: str, *, settings: OsintSettings | None = None) -> EnrichResult:
    return virustotal.enrich_virustotal(entity_kind, entity_value, settings=settings or load_osint_settings())


def enrich_shodan(entity_kind: str, entity_value: str, *, settings: OsintSettings | None = None) -> EnrichResult:
    return shodan.enrich_shodan(entity_kind, entity_value, settings=settings or load_osint_settings())


_ENRICHERS = {
    "dns": dns.enrich_dns,
    "rdap": enrich_rdap,
    "reverse_dns": reverse_dns.enrich_reverse_dns,
    "geoip": geoip.enrich_geoip,
    "virustotal": enrich_virustotal,
    "shodan": enrich_shodan,
    "leaks": lambda entity_kind, entity_value, settings=None: leaks.enrich_leaks(entity_kind, entity_value),
}


def available_enrichers(entity_kind: str) -> list[str]:
    if entity_kind == "domain":
        return ["dns", "rdap", "virustotal", "shodan"]
    if entity_kind == "ip":
        return ["rdap", "reverse_dns", "geoip", "virustotal", "shodan"]
    return []


def enrich_entity(
    enricher: str,
    entity_kind: str,
    entity_value: str,
    *,
    settings: OsintSettings | None = None,
) -> EnrichResult:
    fn = _ENRICHERS.get(enricher)
    if fn is None:
        return EnrichResult(enricher, entity_kind, entity_value, status="error", summary=f"Unknown enricher: {enricher}")

    settings = settings or load_osint_settings()
    if enricher in {"virustotal", "shodan"}:
        return fn(entity_kind, entity_value, settings=settings)
    return fn(entity_kind, entity_value)
