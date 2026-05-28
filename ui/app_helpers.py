"""Shared helper utilities for the desktop app."""

from __future__ import annotations

import ipaddress


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def status_emoji(status: str) -> str:
    s = (status or "").strip() or "New"
    return {"New": "🆕", "Investigating": "🟡", "Confirmed": "✅", "False Positive": "⚪"}.get(s, "🆕")


def normalize_tags(tags: str) -> str:
    raw = (tags or "").strip()
    if not raw:
        return ""
    parts = []
    seen = set()
    for p in raw.replace(";", ",").split(","):
        t = p.strip()
        if not t:
            continue
        if t.lower() in seen:
            continue
        seen.add(t.lower())
        parts.append(t)
    return ", ".join(parts)


def normalize_ui_theme(value: str | None) -> str:
    theme = (value or "dark").strip().lower()
    return theme if theme in {"dark", "light"} else "dark"
