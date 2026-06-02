from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from core.osint.enrichers.base import EnrichResult
from core.osint.normalize import ip_scope

_USER_AGENT = "ViaNyquist/1.0 (+local-investigation-tool)"


def enrich_geoip(entity_kind: str, entity_value: str) -> EnrichResult:
    if entity_kind != "ip":
        return EnrichResult("geoip", entity_kind, entity_value, status="error", summary="GeoIP supports IPs only.")

    ip = str(entity_value or "").strip()
    if not ip:
        return EnrichResult("geoip", entity_kind, entity_value, status="error", summary="Missing IP.")

    scope = ip_scope(ip)
    if scope != "public":
        return EnrichResult("geoip", entity_kind, entity_value, status="error", summary=f"GeoIP skipped for {scope} address.")

    url = f"http://ip-api.com/json/{urllib.parse.quote(ip)}?fields=status,message,country,regionName,city,isp,org,as,query"
    try:
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(request, timeout=12) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception as exc:
        return EnrichResult("geoip", entity_kind, entity_value, status="error", summary=f"GeoIP lookup failed: {exc}")

    if str(payload.get("status") or "").lower() != "success":
        message = str(payload.get("message") or "lookup failed")
        return EnrichResult("geoip", entity_kind, entity_value, status="error", summary=message)

    city = str(payload.get("city") or "")
    region = str(payload.get("regionName") or "")
    country = str(payload.get("country") or "")
    isp = str(payload.get("isp") or "")
    org = str(payload.get("org") or "")
    asn = str(payload.get("as") or "")

    location = ", ".join(part for part in (city, region, country) if part)
    summary = location or isp or org or ip
    details = {
        "location": location,
        "isp": isp,
        "org": org,
        "asn": asn,
    }
    return EnrichResult("geoip", entity_kind, entity_value, summary=summary, details=details)
