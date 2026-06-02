from __future__ import annotations

import socket

from core.osint.enrichers.base import EnrichResult


def enrich_reverse_dns(entity_kind: str, entity_value: str) -> EnrichResult:
    if entity_kind != "ip":
        return EnrichResult("reverse_dns", entity_kind, entity_value, status="error", summary="Reverse DNS supports IPs only.")

    ip = str(entity_value or "").strip()
    if not ip:
        return EnrichResult("reverse_dns", entity_kind, entity_value, status="error", summary="Missing IP.")

    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
    except Exception as exc:
        return EnrichResult("reverse_dns", entity_kind, entity_value, status="error", summary=f"No PTR record for {ip}: {exc}")

    details = {"hostname": host}
    if aliases:
        details["aliases"] = aliases
    return EnrichResult(
        "reverse_dns",
        entity_kind,
        entity_value,
        summary=f"{ip} -> {host}",
        details=details,
    )
