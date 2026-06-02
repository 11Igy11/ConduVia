from __future__ import annotations

import re
import sqlite3
from pathlib import Path

from core.leaks.db import LEAKS_DB_PATH, fts_available, init_leaks_db
from core.leaks.encoding import ascii_fold
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


def _identifier_clause(text: str) -> tuple[str, list]:
    """Route a bare identifier query to the right indexed column(s)."""
    raw = text.strip()
    digits = re.sub(r"\D", "", raw)

    email = normalize_email(raw)
    if email or "@" in raw:
        return (
            "(lr.email LIKE ? OR lr.extra LIKE ?)",
            [_like(email or raw.lower()), _like(raw.lower())],
        )

    if digits:
        if len(digits) == 11 and not raw.startswith("+"):
            return (
                "(lr.oib = ? OR lr.fb_id LIKE ? OR lr.phone LIKE ? OR lr.extra LIKE ?)",
                [digits, _like(digits), _like(digits), _like(digits)],
            )
        msisdn = normalize_msisdn(raw)
        clauses = ["lr.phone LIKE ?", "lr.fb_id LIKE ?", "lr.extra LIKE ?"]
        params: list = [_like(digits), _like(digits), _like(digits)]
        if msisdn:
            clauses.insert(0, "lr.phone = ?")
            params.insert(0, msisdn)
        return ("(" + " OR ".join(clauses) + ")", params)

    return ("", [])


def _text_clause(text: str, *, fts_ok: bool) -> tuple[str, list]:
    raw = text.strip()
    if not raw:
        return ("", [])

    ident_clause, ident_params = _identifier_clause(raw)
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

        text_clause, text_params = _text_clause(text, fts_ok=fts_ok)
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


def lookup_identifier(value: str, *, db_path: Path = LEAKS_DB_PATH) -> tuple[list[sqlite3.Row], int]:
    """Exact identifier lookup used by the OSINT auto-enricher."""
    return search_records(text=value, limit=200, offset=0, db_path=db_path)


# Identifier kinds that should trigger an automatic internal-database hit check.
HIT_KINDS = {"MSISDN", "IMEI", "IMSI", "OIB"}


def find_hits(value: str, *, kind: str | None = None, db_path: Path = LEAKS_DB_PATH) -> tuple[int, str]:
    """Return (hit_count, 'Dataset (n), …') for a value in the internal database.

    For OIB the value must pass the checksum before it is even looked up.
    """
    text = str(value or "").strip()
    if not text:
        return 0, ""
    normalized_kind = str(kind or "").strip().upper()
    if normalized_kind == "OIB":
        from core.osint.normalize import is_valid_oib

        if not is_valid_oib(text):
            return 0, ""
    rows, total = search_records(text=text, limit=50, offset=0, db_path=db_path)
    if not total:
        return 0, ""
    datasets: dict[str, int] = {}
    for row in rows:
        name = str(row["dataset_name"] or "")
        datasets[name] = datasets.get(name, 0) + 1
    summary = ", ".join(f"{name} ({count})" for name, count in datasets.items())
    return total, summary
