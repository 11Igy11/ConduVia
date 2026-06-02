from __future__ import annotations

from urllib.parse import quote_plus


def google_search_url(query: str) -> str:
    return f"https://www.google.com/search?q={quote_plus(str(query or '').strip())}"


def duckduckgo_search_url(query: str) -> str:
    return f"https://duckduckgo.com/?q={quote_plus(str(query or '').strip())}"


def crtsh_url(domain: str) -> str:
    return f"https://crt.sh/?q={quote_plus(str(domain or '').strip())}"


def wayback_url(url: str) -> str:
    return f"https://web.archive.org/web/*/{quote_plus(str(url or '').strip())}"


def shodan_web_url(query: str) -> str:
    return f"https://www.shodan.io/search?query={quote_plus(str(query or '').strip())}"


def virustotal_web_url(kind: str, value: str) -> str:
    text = str(value or "").strip()
    if kind == "domain":
        return f"https://www.virustotal.com/gui/domain/{quote_plus(text)}"
    if kind == "ip":
        return f"https://www.virustotal.com/gui/ip-address/{quote_plus(text)}"
    return f"https://www.virustotal.com/gui/search/{quote_plus(text)}"


def build_identifier_search_links(*, name: str = "", identifier: str = "", kind: str = "") -> list[dict[str, str]]:
    links: list[dict[str, str]] = []
    value = str(identifier or "").strip()
    if not value and not name:
        return links

    if name:
        links.append({"label": "Google name", "url": google_search_url(f'"{name}"')})
        links.append({"label": "LinkedIn", "url": google_search_url(f'site:linkedin.com "{name}"')})
        links.append({"label": "Facebook", "url": google_search_url(f'site:facebook.com "{name}"')})

    if value:
        links.append({"label": "Google identifier", "url": google_search_url(f'"{value}"')})
        if kind.upper() == "MSISDN":
            links.append({"label": "Google phone", "url": google_search_url(value)})
        if kind.upper() == "EMAIL":
            links.append({"label": "Google email", "url": google_search_url(value)})

    return links


def build_domain_links(domain: str) -> list[dict[str, str]]:
    value = str(domain or "").strip()
    if not value:
        return []
    return [
        {"label": "Google", "url": google_search_url(f'"{value}"')},
        {"label": "crt.sh", "url": crtsh_url(value)},
        {"label": "Wayback", "url": wayback_url(f"https://{value}")},
        {"label": "VirusTotal", "url": virustotal_web_url("domain", value)},
        {"label": "Shodan", "url": shodan_web_url(f"hostname:{value}")},
    ]


def build_ip_links(ip: str) -> list[dict[str, str]]:
    value = str(ip or "").strip()
    if not value:
        return []
    return [
        {"label": "Google", "url": google_search_url(f'"{value}"')},
        {"label": "VirusTotal", "url": virustotal_web_url("ip", value)},
        {"label": "Shodan", "url": shodan_web_url(value)},
    ]
