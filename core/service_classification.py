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


SOCIAL_MEDIA_SERVICES = frozenset({
    "Google / YouTube",
    "TikTok",
    "Spotify",
    "Snapchat",
    "X / Twitter",
})

_SOCIAL_ACTIVITY_MARKERS = (
    "app/api or content",
    "app service contact",
    "large encrypted app transfer",
    "background keepalive",
    "metadata burst",
)


def communication_indicator_category(service: str, activity_type: str) -> str:
    service_name = str(service or "").strip()
    activity = str(activity_type or "").strip().casefold()
    if service_name in SOCIAL_MEDIA_SERVICES:
        if any(marker in activity for marker in _SOCIAL_ACTIVITY_MARKERS):
            return "social"
    if service_name == "Facebook / Meta" and any(marker in activity for marker in _SOCIAL_ACTIVITY_MARKERS):
        return "social"
    return "communications"


def communication_indicator_rank_score(row: dict[str, Any]) -> int:
    confidence = {"high": 3, "medium": 2, "low": 1}.get(str(row.get("confidence") or "").casefold(), 0)
    bytes_count = int(row.get("bytes") or 0)
    packets = int(row.get("packets") or 0)
    duration_ms = int(row.get("duration_ms") or 0)
    return confidence * 1_000_000_000 + bytes_count + packets * 2_000 + duration_ms


def communication_indicator_family(activity_type: str) -> str:
    activity = str(activity_type or "").strip().casefold()
    if any(token in activity for token in ("voice", "video", "call", "media session", "webrtc", "relay")):
        return "call_media"
    if any(token in activity for token in ("message", "messaging", "push", "notification", "chat")):
        return "messaging"
    if any(token in activity for token in ("background", "keepalive", "sync")):
        return "background"
    if any(token in activity for token in ("content", "transfer", "stream", "api")):
        return "content"
    return "other"


_COMMUNICATION_ACTIVITY_LABELS: dict[str, str] = {
    "Push/notification transport": "Push channel (notifications/sync)",
    "Possible iCloud sync or push transport": "iCloud sync/push channel",
    "Background keepalive / sync connection": "Background sync/keepalive",
    "App contact / metadata burst": "Short metadata burst",
    "App service contact observed": "Generic encrypted contact",
    "Possible messaging/chat transport": "Messaging/chat transport",
    "Possible messaging/chat endpoint": "Messaging/chat endpoint",
    "Possible call/media relay": "Call/media relay (STUN/TURN)",
    "Possible app call/media session": "Likely app call/media session",
    "Possible voice/video session": "Likely voice/video session",
    "Possible encrypted call/media session": "Encrypted call/media session",
    "Possible heavy encrypted app session": "Heavy encrypted app session",
    "Large encrypted app transfer": "Large encrypted transfer",
    "App/API or content service connection": "App/API or content connection",
}

_COMMUNICATION_TYPE_LABELS = {
    "call_media": "Call / media",
    "messaging": "Messaging / push",
    "background": "Background / sync",
    "content": "Content / API",
    "other": "Other contact",
}

_ROUTINE_ACTIVITY_MARKERS = (
    "app service contact observed",
    "metadata burst",
    "background keepalive",
    "push/notification transport",
    "icloud sync or push transport",
    "app/api or content service connection",
)


def communication_activity_label(activity_type: str) -> str:
    text = str(activity_type or "").strip()
    if not text:
        return ""
    return _COMMUNICATION_ACTIVITY_LABELS.get(text, text)


def communication_type_label(family: str) -> str:
    key = str(family or "").strip()
    return _COMMUNICATION_TYPE_LABELS.get(key, _COMMUNICATION_TYPE_LABELS["other"])


def communication_indicator_tier(row: dict[str, Any]) -> str:
    family = str(row.get("family") or communication_indicator_family(str(row.get("activity_type") or "")))
    confidence = str(row.get("confidence") or "").casefold()
    activity = str(row.get("activity_type") or "").casefold()

    if family == "call_media" and confidence in {"high", "medium"}:
        return "review"
    if confidence == "high":
        return "review"
    if family == "messaging" and confidence == "medium":
        if not any(marker in activity for marker in _ROUTINE_ACTIVITY_MARKERS):
            return "review"
    if family == "background":
        return "routine"
    if any(marker in activity for marker in _ROUTINE_ACTIVITY_MARKERS):
        return "routine"
    if family == "other" and confidence == "low":
        return "routine"
    if family == "messaging":
        return "messaging"
    if family == "content":
        return "messaging"
    return "messaging"


def communication_tier_sort_key(tier: str) -> int:
    return {"review": 0, "messaging": 1, "routine": 2}.get(str(tier or ""), 9)
