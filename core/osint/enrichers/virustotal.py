from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from core.osint.enrichers.base import EnrichResult
from core.osint.settings import OsintSettings

_USER_AGENT = "ViaNyquist/1.0 (+local-investigation-tool)"


def enrich_virustotal(entity_kind: str, entity_value: str, *, settings: OsintSettings) -> EnrichResult:
    api_key = (settings.virustotal_api_key or "").strip()
    if not api_key:
        return EnrichResult("virustotal", entity_kind, entity_value, status="error", summary="VirusTotal API key not configured in Settings.")

    value = str(entity_value or "").strip()
    if not value:
        return EnrichResult("virustotal", entity_kind, entity_value, status="error", summary="Missing value.")

    if entity_kind == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(value)}"
    elif entity_kind == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(value)}"
    else:
        return EnrichResult("virustotal", entity_kind, entity_value, status="error", summary="VirusTotal supports domains and IPs only.")

    try:
        request = urllib.request.Request(
            url,
            headers={"x-apikey": api_key, "User-Agent": _USER_AGENT, "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
        return EnrichResult("virustotal", entity_kind, entity_value, status="error", summary=f"VirusTotal HTTP {exc.code}: {body[:200]}")
    except Exception as exc:
        return EnrichResult("virustotal", entity_kind, entity_value, status="error", summary=f"VirusTotal lookup failed: {exc}")

    data = payload.get("data") or {}
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    reputation = attrs.get("reputation")
    categories = attrs.get("categories") or {}

    summary = f"VT: malicious={malicious}, suspicious={suspicious}, harmless={harmless}"
    details = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "reputation": reputation,
        "categories": ", ".join(f"{k}:{v}" for k, v in list(categories.items())[:5]),
    }
    return EnrichResult("virustotal", entity_kind, entity_value, summary=summary, details=details)
