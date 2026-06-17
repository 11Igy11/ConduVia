"""Shared helper utilities for the desktop app."""

from __future__ import annotations


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
