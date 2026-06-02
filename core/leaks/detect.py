from __future__ import annotations

import re

from core.leaks.schema import FIELD_SKIP

DELIMITER_CANDIDATES: tuple[str, ...] = (":", "\t", ";", "|", ",")

_PHONE_RE = re.compile(r"^\+?\d[\d\s().-]{6,16}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DIGITS_RE = re.compile(r"^\d+$")
_DATE_RE = re.compile(r"^\d{1,4}[/.\-]\d{1,2}[/.\-]\d{1,4}")
_GENDER_VALUES = {"male", "female", "m", "f", "muski", "muški", "zenski", "ženski"}
_NAME_RE = re.compile(r"^[A-Za-zÀ-ÿČĆŽŠĐčćžšđ][A-Za-zÀ-ÿČĆŽŠĐčćžšđ '\-]{1,}$")


def detect_delimiter(sample_lines: list[str]) -> str:
    """Pick the delimiter that splits sample lines most consistently."""
    lines = [ln for ln in sample_lines if ln.strip()][:200]
    if not lines:
        return ":"
    best = ":"
    best_score = -1.0
    for delim in DELIMITER_CANDIDATES:
        counts = [ln.count(delim) for ln in lines]
        present = [c for c in counts if c > 0]
        if not present:
            continue
        # Consistency: how many lines share the modal count.
        modal = max(set(present), key=present.count)
        if modal == 0:
            continue
        consistency = present.count(modal) / len(lines)
        score = consistency * modal
        if score > best_score:
            best_score = score
            best = delim
    return best


def split_line(line: str, delimiter: str) -> list[str]:
    return [part.strip() for part in str(line).split(delimiter)]


def split_rows(sample_lines: list[str], delimiter: str) -> list[list[str]]:
    rows = []
    for ln in sample_lines:
        if ln.strip():
            rows.append(split_line(ln, delimiter))
    return rows


def column_count(rows: list[list[str]]) -> int:
    return max((len(r) for r in rows), default=0)


def suggest_fields(rows: list[list[str]]) -> list[str]:
    """Return a suggested canonical field token per column index."""
    cols = column_count(rows)
    suggestions: list[str] = []
    alpha_name_slots = ["first_name", "last_name"]
    used_phone = used_email = used_fbid = used_oib = False

    for index in range(cols):
        values = [r[index] for r in rows if index < len(r) and r[index].strip()]
        kind = _classify_column(values)

        if kind in ("phone", "fb_id"):
            # Both columns are numeric and easy to confuse: the first
            # phone-shaped column wins `phone`, any later numeric column
            # falls back to `fb_id`.
            if kind == "phone" and not used_phone:
                used_phone = True
                suggestions.append("phone")
            elif not used_fbid:
                used_fbid = True
                suggestions.append("fb_id")
            elif not used_phone:
                used_phone = True
                suggestions.append("phone")
            else:
                suggestions.append(FIELD_SKIP)
        elif kind == "email" and not used_email:
            used_email = True
            suggestions.append("email")
        elif kind == "oib" and not used_oib:
            used_oib = True
            suggestions.append("oib")
        elif kind == "gender":
            suggestions.append("gender")
        elif kind == "datetime":
            suggestions.append("source_date")
        elif kind == "date":
            suggestions.append("birthday")
        elif kind == "name" and alpha_name_slots:
            suggestions.append(alpha_name_slots.pop(0))
        else:
            suggestions.append(FIELD_SKIP)
    return suggestions


def _classify_column(values: list[str]) -> str:
    if not values:
        return "empty"
    sample = values[:50]
    total = len(sample)

    def ratio(predicate) -> float:
        return sum(1 for v in sample if predicate(v)) / total

    if ratio(lambda v: bool(_EMAIL_RE.match(v))) >= 0.6:
        return "email"
    if ratio(lambda v: v.strip().lower() in _GENDER_VALUES) >= 0.6:
        return "gender"
    if ratio(lambda v: bool(_DATE_RE.match(v))) >= 0.6:
        # A date that also carries a time component is almost always a
        # scrape/registration timestamp, not a date of birth.
        if ratio(lambda v: (":" in v) or ("AM" in v.upper()) or ("PM" in v.upper())) >= 0.5:
            return "datetime"
        return "date"

    digit_ratio = ratio(lambda v: bool(_DIGITS_RE.match(re.sub(r"[\s+().-]", "", v))))
    if digit_ratio >= 0.8:
        lengths = [len(re.sub(r"\D", "", v)) for v in sample if v.strip()]
        avg_len = sum(lengths) / len(lengths) if lengths else 0
        if all(l == 11 for l in lengths):
            return "oib"
        if ratio(lambda v: bool(_PHONE_RE.match(v.strip()))) >= 0.6 and 8 <= avg_len <= 15:
            return "phone"
        return "fb_id"

    if ratio(lambda v: bool(_NAME_RE.match(v.strip()))) >= 0.6:
        return "name"
    return "text"
