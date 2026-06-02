from __future__ import annotations

import ipaddress
import re

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def normalize_ip(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return ""


def ip_scope(value: str) -> str:
    ip = normalize_ip(value)
    if not ip:
        return ""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if addr.is_private:
        return "private"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    return "public"


def normalize_domain(value: str) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if not text or _looks_like_ip(text):
        return ""
    if text.startswith("www."):
        text = text[4:]
    if DOMAIN_RE.match(text):
        return text
    return ""


def normalize_msisdn(value: str, *, default_country: str = "385") -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    if not digits:
        return ""
    if digits.startswith("00"):
        digits = digits[2:]
    if digits.startswith(default_country):
        return f"+{digits}"
    if digits.startswith("0") and len(digits) >= 9:
        return f"+{default_country}{digits.lstrip('0')}"
    if len(digits) >= 8:
        return f"+{digits}"
    return ""


def normalize_email(value: str) -> str:
    text = str(value or "").strip().lower()
    if EMAIL_RE.match(text):
        return text
    return ""


def oib_check_digit(first_ten: str) -> int:
    """ISO 7064 MOD 11,10 control digit for the first 10 OIB digits."""
    remainder = 10
    for char in first_ten:
        remainder = (remainder + int(char)) % 10
        if remainder == 0:
            remainder = 10
        remainder = (remainder * 2) % 11
    return (11 - remainder) % 10


def is_valid_oib(value: str) -> bool:
    """True if value is a syntactically valid Croatian OIB (11 digits + checksum)."""
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) != 11:
        return False
    return oib_check_digit(digits[:10]) == int(digits[10])


def parse_extra_identifiers(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if ":" in line:
            kind, value = line.split(":", 1)
            kind = kind.strip() or "Identifier"
            value = value.strip()
        else:
            kind, value = "Identifier", line
        email = normalize_email(value)
        if email:
            rows.append({"kind": "Email", "value": email, "label": "Email"})
            continue
        msisdn = normalize_msisdn(value)
        if msisdn and sum(ch.isdigit() for ch in value) >= 8:
            rows.append({"kind": "MSISDN", "value": msisdn, "label": "Mobile number"})
            continue
        rows.append({"kind": kind, "value": value, "label": kind})
    return rows


def _looks_like_ip(value: str) -> bool:
    return bool(normalize_ip(value))
