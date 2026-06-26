from __future__ import annotations

from typing import Any

# Primary rules shared by Profile behavior and PCAP communication indicators.
SERVICE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Apple / iCloud", (
        "apple.com",
        "icloud",
        "push.apple",
        "courier",
        "itunes",
        "mzstatic",
        "apple-dns",
        "mask-api.icloud",
        "configuration.apple",
        "applepush",
    )),
    ("Facebook / Meta", (
        "facebook",
        "fbcdn",
        "fb.com",
        "instagram",
        "edge-mqtt",
        "messenger",
    )),
    ("WhatsApp", ("whatsapp", "wa.me")),
    ("Google / YouTube", (
        "youtube",
        "ytimg",
        "googlevideo",
        "googleapis",
        "googleusercontent",
        "geller-pa.googleapis.com",
        "notifications-pa",
    )),
    ("TikTok", ("tiktok", "byteoversea", "pangle")),
    ("Telegram", ("telegram", "t.me")),
    ("Viber", ("viber",)),
    ("Signal", ("signal.org", "signal.art", "whispersystems")),
    ("Snapchat", ("snapchat", "snap.com")),
    ("X / Twitter", ("twitter", "x.com", "twimg")),
    ("Microsoft / Teams", ("microsoft", "office365", "outlook", "teams", "skype", "live.com")),
    ("Spotify", ("spotify",)),
    ("Travel / Booking", ("booking", "booking.com", "airbnb", "tripadvisor")),
    ("Advertising / tracking", (
        "doubleclick",
        "googlesyndication",
        "adservice",
        "analytics",
        "ads.",
        "adnxs",
        "adform",
        "criteo",
        "rubiconproject",
        "zemanta",
    )),
)

# Extra host-only labels used by PCAP investigator service groups.
EXTENDED_SERVICE_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Samsung", ("samsung",)),
    ("Certificates / validation", ("ocsp", "cert", "crl", "godaddy")),
    ("Cloudflare / CDN", ("cloudflare", "cloudfront", "akamai", "cdn")),
    ("LinkedIn", ("linkedin",)),
)

# Backwards-compatible alias for PCAP communication matching.
COMMUNICATION_SERVICE_RULES = SERVICE_RULES


def match_service(
    text: str,
    *,
    rules: tuple[tuple[str, tuple[str, ...]], ...] = SERVICE_RULES,
) -> str:
    haystack = (text or "").lower()
    if not haystack:
        return ""
    for service, needles in rules:
        if any(needle in haystack for needle in needles):
            return service
    return ""


def classify_behavior_service(value: str) -> str:
    label = match_service(value)
    if label:
        return label
    text = (value or "").lower()
    return "Other visible services" if "." in text else ""


def classify_pcap_investigator_service(host: str) -> str:
    label = match_service(host)
    if label:
        return label
    label = match_service(host, rules=EXTENDED_SERVICE_RULES)
    if label:
        return label
    return "Other visible services"


def classify_communication_service(flow: dict[str, Any]) -> str:
    text = " ".join(
        str(flow.get(key) or "")
        for key in ("requested_server_name", "application_name", "pcap_payload_preview")
    )
    return match_service(text)
