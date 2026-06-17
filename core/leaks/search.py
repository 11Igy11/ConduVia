from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from core.leaks.db import LEAKS_DB_PATH, fts_available, init_leaks_db
from core.leaks.encoding import ascii_fold
from core.osint.imsi import format_intercept_imsi, imsi_lookup_values, is_imsi_target_type, normalize_imsi
from core.osint.normalize import normalize_email, normalize_msisdn

_FILTER_COLUMNS = {
    "phone",
    "email",
    "oib",
    "fb_id",
    "username",
    "first_name",
    "last_name",
    "full_name",
    "gender",
    "birthday",
    "city",
    "hometown",
    "employer",
    "address",
}
_FTS_LIKE_COLUMNS = ("name_ascii", "employer", "city", "hometown")


def _like(value: str) -> str:
    return f"%{value}%"


def _hit_kind_aliases(kind: str | None) -> str:
    text = str(kind or "").strip().upper()
    aliases = {
        "MOBILE NUMBER": "MSISDN",
        "MOBILE": "MSISDN",
        "E-MAIL": "EMAIL",
        "FACEBOOK ID": "FB_ID",
        "FACEBOOK": "FB_ID",
        "TEL": "PHONE",
        "TELEPHONE": "PHONE",
    }
    return aliases.get(text, text)


def _identifier_clause(text: str, *, kind: str | None = None) -> tuple[str, list]:
    """Route a bare identifier query to the right indexed column(s)."""
    raw = text.strip()
    digits = re.sub(r"\D", "", raw)
    normalized_kind = _hit_kind_aliases(kind)

    email = normalize_email(raw)
    if email or "@" in raw:
        return (
            "(lr.email LIKE ? OR lr.extra LIKE ?)",
            [_like(email or raw.lower()), _like(raw.lower())],
        )

    if normalized_kind == "OIB" and digits:
        return (
            "(lr.oib = ? OR lr.oib LIKE ? OR lr.extra LIKE ?)",
            [digits, _like(digits), _like(digits)],
        )

    if normalized_kind in {"FB_ID", "USERNAME"} and raw:
        needle = digits or raw
        return (
            "(lr.fb_id LIKE ? OR lr.username LIKE ? OR lr.extra LIKE ?)",
            [_like(needle), _like(raw), _like(raw)],
        )

    if normalized_kind == "EMAIL" and raw:
        email = normalize_email(raw)
        needle = email or raw.lower()
        return (
            "(lr.email LIKE ? OR lr.extra LIKE ?)",
            [_like(needle), _like(needle)],
        )

    if normalized_kind in {"MSISDN", "MOBILE NUMBER", "PHONE"} and digits:
        msisdn = normalize_msisdn(raw)
        clauses = ["lr.phone LIKE ?", "lr.fb_id LIKE ?", "lr.extra LIKE ?"]
        params: list = [_like(digits), _like(digits), _like(digits)]
        if msisdn:
            clauses.insert(0, "lr.phone = ?")
            params.insert(0, msisdn)
        return ("(" + " OR ".join(clauses) + ")", params)

    if normalized_kind == "IMSI" and digits:
        needles = imsi_lookup_values(raw)
        clauses = ["lr.phone LIKE ?", "lr.fb_id LIKE ?", "lr.extra LIKE ?", "lr.raw LIKE ?"]
        combined: list[str] = []
        params: list[str] = []
        for needle in needles:
            combined.extend(clauses)
            params.extend([_like(needle)] * len(clauses))
        return ("(" + " OR ".join(combined) + ")", params)

    if normalized_kind == "IMEI" and digits:
        return (
            "(lr.phone LIKE ? OR lr.fb_id LIKE ? OR lr.extra LIKE ? OR lr.raw LIKE ?)",
            [_like(digits), _like(digits), _like(digits), _like(digits)],
        )

    if digits:
        if len(digits) == 11 and not raw.startswith("+"):
            return (
                "(lr.oib = ? OR lr.fb_id LIKE ? OR lr.phone LIKE ? OR lr.extra LIKE ?)",
                [digits, _like(digits), _like(digits), _like(digits)],
            )
        msisdn = normalize_msisdn(raw)
        clauses = ["lr.phone LIKE ?", "lr.fb_id LIKE ?", "lr.extra LIKE ?"]
        params = [_like(digits), _like(digits), _like(digits)]
        if msisdn:
            clauses.insert(0, "lr.phone = ?")
            params.insert(0, msisdn)
        return ("(" + " OR ".join(clauses) + ")", params)

    return ("", [])


def _text_clause(text: str, *, fts_ok: bool, kind: str | None = None) -> tuple[str, list]:
    raw = text.strip()
    if not raw:
        return ("", [])

    ident_clause, ident_params = _identifier_clause(raw, kind=kind)
    if ident_clause:
        return (ident_clause, ident_params)

    folded = ascii_fold(raw)
    like_parts = [f"lr.{col} LIKE ?" for col in _FTS_LIKE_COLUMNS]
    params: list = [_like(folded if col == "name_ascii" else raw) for col in _FTS_LIKE_COLUMNS]
    # Also search free-text custom columns stored in the extra JSON blob.
    like_parts.append("lr.extra LIKE ?")
    params.append(_like(raw))

    if fts_ok:
        tokens = [t for t in re.split(r"\s+", raw) if t]
        match = " ".join(f'"{t}"*' for t in tokens) if tokens else f'"{raw}"*'
        clause = (
            "(lr.id IN (SELECT rowid FROM leak_records_fts WHERE leak_records_fts MATCH ?) OR "
            + " OR ".join(like_parts)
            + ")"
        )
        return (clause, [match] + params)

    return ("(" + " OR ".join(like_parts) + ")", params)


def _filter_clauses(filters: dict | None) -> tuple[list[str], list]:
    clauses: list[str] = []
    params: list = []
    if not filters:
        return clauses, params
    for key, value in filters.items():
        value = str(value or "").strip()
        if not value:
            continue
        if key == "name":
            clauses.append("lr.name_ascii LIKE ?")
            params.append(_like(ascii_fold(value)))
        elif key in _FILTER_COLUMNS:
            clauses.append(f"lr.{key} LIKE ?")
            params.append(_like(value))
    return clauses, params


def search_records(
    filters: dict | None = None,
    text: str = "",
    *,
    dataset_id: int | None = None,
    kind: str | None = None,
    limit: int = 100,
    offset: int = 0,
    db_path: Path = LEAKS_DB_PATH,
) -> tuple[list[sqlite3.Row], int]:
    if not Path(db_path).exists():
        return [], 0
    init_leaks_db(db_path)

    from core.leaks.db import _connect

    with _connect(db_path) as con:
        fts_ok = fts_available(con)

        where: list[str] = []
        params: list = []

        if dataset_id is not None:
            where.append("lr.dataset_id = ?")
            params.append(int(dataset_id))

        text_clause, text_params = _text_clause(text, fts_ok=fts_ok, kind=kind)
        if text_clause:
            where.append(text_clause)
            params.extend(text_params)

        filt_clauses, filt_params = _filter_clauses(filters)
        where.extend(filt_clauses)
        params.extend(filt_params)

        where_sql = (" WHERE " + " AND ".join(where)) if where else ""

        total = int(
            con.execute(
                f"SELECT COUNT(*) FROM leak_records lr{where_sql};", params
            ).fetchone()[0]
        )
        rows = con.execute(
            f"SELECT lr.*, d.name AS dataset_name, d.source_note AS dataset_note "
            f"FROM leak_records lr JOIN datasets d ON d.id = lr.dataset_id"
            f"{where_sql} ORDER BY lr.id LIMIT ? OFFSET ?;",
            params + [int(limit), int(offset)],
        ).fetchall()
        return rows, total


def lookup_identifier(value: str, *, kind: str | None = None, db_path: Path = LEAKS_DB_PATH) -> tuple[list[sqlite3.Row], int]:
    """Exact identifier lookup used by the OSINT auto-enricher."""
    return search_records(text=value, kind=kind, limit=200, offset=0, db_path=db_path)


# Identifier kinds that should trigger an automatic internal-database hit check.
HIT_KINDS = {
    "MSISDN", "IMEI", "IMSI", "OIB", "EMAIL", "E-MAIL", "PHONE",
    "MOBILE NUMBER", "MOBILE", "FB_ID", "FACEBOOK ID", "USERNAME",
}

_HIT_KIND_ALIASES = {
    "MOBILE NUMBER": "MSISDN",
    "MOBILE": "MSISDN",
    "E-MAIL": "EMAIL",
    "FACEBOOK ID": "FB_ID",
    "FACEBOOK": "FB_ID",
    "TEL": "PHONE",
    "TELEPHONE": "PHONE",
}


def normalize_hit_kind(kind: str | None, value: str = "") -> str | None:
    text = str(kind or "").strip().upper()
    if text in _HIT_KIND_ALIASES:
        text = _HIT_KIND_ALIASES[text]
    if text in HIT_KINDS:
        return text

    raw = str(value or "").strip()
    if not raw:
        return None
    if "@" in raw:
        return "EMAIL"

    digits = re.sub(r"\D", "", raw)
    if not digits:
        return None
    if len(digits) == 11:
        return "OIB"
    if len(digits) == 15:
        return "IMEI"
    if len(digits) in {13, 14}:
        return "IMSI"
    if len(digits) >= 8:
        return "MSISDN"
    return None


def find_hits(value: str, *, kind: str | None = None, db_path: Path = LEAKS_DB_PATH) -> tuple[int, str, list[int]]:
    """Return (hit_count, dataset summary, record_ids) for a value in the repository."""
    text = str(value or "").strip()
    if not text:
        return 0, "", []
    rows, total = search_records(text=text, kind=kind, limit=50, offset=0, db_path=db_path)
    if not total:
        return 0, "", []
    datasets: dict[str, int] = {}
    record_ids: list[int] = []
    for row in rows:
        record_ids.append(int(row["id"]))
        name = str(row["dataset_name"] or "")
        datasets[name] = datasets.get(name, 0) + 1
    summary = ", ".join(f"{name} ({count})" for name, count in datasets.items())
    return total, summary, record_ids


def find_repository_hits(
    value: str,
    *,
    kind: str | None = None,
    db_path: Path = LEAKS_DB_PATH,
) -> tuple[int, str, list[int]]:
    """Lookup repository hits using kind-aware search with a broader fallback."""
    text = str(value or "").strip()
    if not text:
        return 0, "", []
    normalized_kind = normalize_hit_kind(kind, text)
    if normalized_kind:
        total, summary, record_ids = find_hits(text, kind=normalized_kind, db_path=db_path)
        if total:
            return total, summary, record_ids
    return find_hits(text, kind=None, db_path=db_path)
