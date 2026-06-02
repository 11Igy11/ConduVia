from __future__ import annotations

import re

from core.osint.normalize import normalize_domain

INFRASTRUCTURE_SUFFIXES = (
    "akadns.net",
    "edgekey.net",
    "edgesuite.net",
    "cloudfront.net",
    "amazonaws.com",
    "googleusercontent.com",
    "googlevideo.com",
    "fbcdn.net",
    "icloud-content.com",
    "apple-dns.net",
    "fastly.net",
    "azureedge.net",
    "cdn77.org",
)

MULTI_PART_PUBLIC_SUFFIXES = (
    "co.uk",
    "com.au",
    "com.hr",
    "co.jp",
)

SERVICE_LABEL_PREFIXES = ("push-", "api-", "cdn-", "mobile-")


def registrable_domain(value: str) -> str:
    host = normalize_domain(value) or str(value or "").strip().lower().rstrip(".")
    if not host or "." not in host:
        return ""

    host = _strip_infrastructure_suffix(host)
    host = _extract_brand_from_service_label(host)

    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_PUBLIC_SUFFIXES:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _strip_infrastructure_suffix(host: str) -> str:
    changed = True
    while changed:
        changed = False
        for suffix in INFRASTRUCTURE_SUFFIXES:
            if host == suffix:
                return host
            if host.endswith("." + suffix):
                host = host[: -(len(suffix) + 1)].rstrip(".")
                changed = True
                break
    return host


def _extract_brand_from_service_label(host: str) -> str:
    parts = host.split(".")
    if len(parts) < 2:
        return host

    for index, label in enumerate(parts[:-1]):
        for prefix in SERVICE_LABEL_PREFIXES:
            if not label.startswith(prefix):
                continue
            brand = label[len(prefix) :]
            if not brand or not re.fullmatch(r"[a-z0-9-]+", brand):
                continue
            tld_parts = parts[index + 1 :]
            if tld_parts:
                return f"{brand}.{'.'.join(tld_parts)}"
    return host


def registrable_domain_label(value: str) -> str:
    root = registrable_domain(value)
    host = normalize_domain(value) or value
    if not root or root == host:
        return ""
    return root
