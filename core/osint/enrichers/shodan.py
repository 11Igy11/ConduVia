from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from core.osint.enrichers.base import EnrichResult
from core.osint.normalize import ip_scope
from core.osint.settings import OsintSettings

_USER_AGENT = "ViaNyquist/1.0 (+local-investigation-tool)"


def enrich_shodan(entity_kind: str, entity_value: str, *, settings: OsintSettings) -> EnrichResult:
    api_key = (settings.shodan_api_key or "").strip()
    if not api_key:
        return EnrichResult("shodan", entity_kind, entity_value, status="error", summary="Shodan API key not configured in Settings.")

    value = str(entity_value or "").strip()
    if not value:
        return EnrichResult("shodan", entity_kind, entity_value, status="error", summary="Missing value.")

    if entity_kind == "ip":
        scope = ip_scope(value)
        if scope != "public":
            return EnrichResult(
                "shodan",
                entity_kind,
                entity_value,
                status="error",
                summary=f"Shodan host lookup skipped for {scope} address. Use a public IP observed on the internet.",
            )

    if entity_kind == "ip":
        url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(value)}?key={urllib.parse.quote(api_key)}"
    elif entity_kind == "domain":
        url = f"https://api.shodan.io/dns/domain/{urllib.parse.quote(value)}?key={urllib.parse.quote(api_key)}"
    else:
        return EnrichResult("shodan", entity_kind, entity_value, status="error", summary="Shodan supports domains and IPs only.")

    try:
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"})
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else ""
        return EnrichResult(
            "shodan",
            entity_kind,
            entity_value,
            status="error",
            summary=_format_shodan_http_error(exc.code, body),
        )
    except Exception as exc:
        return EnrichResult("shodan", entity_kind, entity_value, status="error", summary=f"Shodan lookup failed: {exc}")

    if entity_kind == "ip":
        org = str(payload.get("org") or "")
        isp = str(payload.get("isp") or "")
        country = str(payload.get("country_name") or "")
        ports = payload.get("ports") or []
        hostnames = payload.get("hostnames") or []
        summary = ", ".join(part for part in (country, org or isp) if part) or value
        details = {
            "country": country,
            "org": org,
            "isp": isp,
            "ports": ", ".join(str(p) for p in ports[:20]),
            "hostnames": ", ".join(hostnames[:10]),
        }
    else:
        subdomains = payload.get("subdomains") or []
        tags = payload.get("tags") or []
        summary = f"{len(subdomains)} subdomains indexed"
        details = {
            "subdomains": ", ".join(subdomains[:20]),
            "tags": ", ".join(str(tag) for tag in tags[:10]),
        }

    return EnrichResult("shodan", entity_kind, entity_value, summary=summary, details=details)


def _format_shodan_http_error(code: int, body: str) -> str:
    message = ""
    try:
        payload = json.loads(body or "{}")
        message = str(payload.get("error") or payload.get("message") or "").strip()
    except Exception:
        message = (body or "").strip()

    lowered = message.lower()
    if code == 401:
        return "Shodan rejected the API key (HTTP 401). Check the key in Settings and save again."
    if code == 403 and "membership" in lowered:
        return (
            "Shodan HTTP 403: this query needs a paid Shodan membership, or the target is not available "
            "on the free plan. For IPs, try a public address; private IPs (10.x, 192.168.x) are not in Shodan."
        )
    if code == 404:
        return "Shodan has no indexed data for this target (HTTP 404)."
    if message:
        return f"Shodan HTTP {code}: {message}"
    return f"Shodan HTTP {code}: {body[:200]}"
