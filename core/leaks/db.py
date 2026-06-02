from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from core.db import APP_DATA_DIR

LEAKS_DB_PATH = APP_DATA_DIR / "leaks" / "leaks.db"

# Columns inserted per record, in fixed order (matches importer output).
_RECORD_COLUMNS: tuple[str, ...] = (
    "dataset_id",
    "phone",
    "email",
    "oib",
    "fb_id",
    "username",
    "first_name",
    "last_name",
    "full_name",
    "name_ascii",
    "gender",
    "birthday",
    "city",
    "hometown",
    "employer",
    "address",
    "secret",
    "extra",
    "raw",
)


@contextmanager
def _connect(db_path: Path = LEAKS_DB_PATH) -> Iterator[sqlite3.Connection]:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fts_available(con: sqlite3.Connection) -> bool:
    try:
        con.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _fts_probe USING fts5(x);")
        con.execute("DROP TABLE IF EXISTS _fts_probe;")
        return True
    except sqlite3.OperationalError:
        return False


def init_leaks_db(db_path: Path = LEAKS_DB_PATH) -> None:
    with _connect(db_path) as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS datasets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                source_note TEXT NOT NULL DEFAULT '',
                source_path TEXT NOT NULL DEFAULT '',
                delimiter TEXT NOT NULL DEFAULT ':',
                encoding TEXT NOT NULL DEFAULT 'utf-8',
                profile_name TEXT NOT NULL DEFAULT '',
                columns_json TEXT NOT NULL DEFAULT '',
                record_count INTEGER NOT NULL DEFAULT 0,
                imported_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT ''
            );
            """
        )
        existing = {row[1] for row in con.execute("PRAGMA table_info(datasets);")}
        if "columns_json" not in existing:
            con.execute("ALTER TABLE datasets ADD COLUMN columns_json TEXT NOT NULL DEFAULT '';")
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS leak_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                dataset_id INTEGER NOT NULL,
                phone TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                oib TEXT NOT NULL DEFAULT '',
                fb_id TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                first_name TEXT NOT NULL DEFAULT '',
                last_name TEXT NOT NULL DEFAULT '',
                full_name TEXT NOT NULL DEFAULT '',
                name_ascii TEXT NOT NULL DEFAULT '',
                gender TEXT NOT NULL DEFAULT '',
                birthday TEXT NOT NULL DEFAULT '',
                city TEXT NOT NULL DEFAULT '',
                hometown TEXT NOT NULL DEFAULT '',
                employer TEXT NOT NULL DEFAULT '',
                address TEXT NOT NULL DEFAULT '',
                secret TEXT NOT NULL DEFAULT '',
                extra TEXT NOT NULL DEFAULT '',
                raw TEXT NOT NULL DEFAULT ''
            );
            """
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_lr_dataset ON leak_records(dataset_id);")
        con.execute("CREATE INDEX IF NOT EXISTS idx_lr_phone ON leak_records(phone) WHERE phone <> '';")
        con.execute("CREATE INDEX IF NOT EXISTS idx_lr_email ON leak_records(email) WHERE email <> '';")
        con.execute("CREATE INDEX IF NOT EXISTS idx_lr_oib ON leak_records(oib) WHERE oib <> '';")
        con.execute("CREATE INDEX IF NOT EXISTS idx_lr_fbid ON leak_records(fb_id) WHERE fb_id <> '';")
        con.execute("CREATE INDEX IF NOT EXISTS idx_lr_name ON leak_records(name_ascii) WHERE name_ascii <> '';")
        # Partial unique index used for phone+fb_id dedup (INSERT OR IGNORE).
        con.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_lr_phone_fbid "
            "ON leak_records(phone, fb_id) WHERE phone <> '' AND fb_id <> '';"
        )
        if fts_available(con):
            con.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS leak_records_fts "
                "USING fts5(full_name, city, hometown, employer, content='');"
            )


def create_dataset(
    name: str,
    *,
    source_note: str = "",
    source_path: str = "",
    delimiter: str = ":",
    encoding: str = "utf-8",
    profile_name: str = "",
    columns: list[str] | None = None,
    db_path: Path = LEAKS_DB_PATH,
) -> int:
    columns_json = json.dumps(list(columns)) if columns else ""
    with _connect(db_path) as con:
        cur = con.execute(
            """
            INSERT INTO datasets
                (name, source_note, source_path, delimiter, encoding, profile_name,
                 columns_json, record_count, imported_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, '', ?)
            """,
            (name, source_note, source_path, delimiter, encoding, profile_name,
             columns_json, _now()),
        )
        return int(cur.lastrowid)


def update_dataset(
    dataset_id: int,
    *,
    name: str | None = None,
    source_note: str | None = None,
    columns: list[str] | None = None,
    rename_map: dict[str, str] | None = None,
    db_path: Path = LEAKS_DB_PATH,
) -> None:
    """Edit a dataset's metadata/columns and migrate record data on column rename.

    ``rename_map`` maps an old column token to its new token; matching record
    values are moved between dedicated columns / the ``extra`` blob accordingly.
    """
    with _connect(db_path) as con:
        if rename_map:
            _migrate_renames(con, int(dataset_id), rename_map)
        sets: list[str] = []
        params: list = []
        if name is not None:
            sets.append("name = ?")
            params.append(name)
        if source_note is not None:
            sets.append("source_note = ?")
            params.append(source_note)
        if columns is not None:
            sets.append("columns_json = ?")
            params.append(json.dumps(list(columns)))
        if sets:
            params.append(int(dataset_id))
            con.execute(f"UPDATE datasets SET {', '.join(sets)} WHERE id = ?;", params)


def _migrate_renames(con: sqlite3.Connection, dataset_id: int, rename_map: dict[str, str]) -> None:
    from core.leaks.schema import DEDICATED_FIELDS

    effective = {old: new for old, new in rename_map.items() if old and new and old != new}
    if not effective:
        return
    rows = con.execute(
        "SELECT * FROM leak_records WHERE dataset_id = ?;", (dataset_id,)
    ).fetchall()
    if not rows:
        return
    for row in rows:
        flat: dict[str, str] = {}
        for field in DEDICATED_FIELDS:
            value = str(row[field] or "").strip()
            if value:
                flat[field] = value
        try:
            extra = json.loads(row["extra"] or "{}")
        except Exception:
            extra = {}
        for key, value in extra.items():
            if str(value or "").strip():
                flat[key] = str(value)
        for old, new in effective.items():
            if old in flat:
                flat[new] = flat.pop(old)
        dedicated, new_extra, name_ascii = _prepare_record_values(flat)
        extra_json = json.dumps(new_extra, ensure_ascii=False) if new_extra else ""
        con.execute(
            """
            UPDATE leak_records SET
                phone=?, email=?, oib=?, fb_id=?, username=?, first_name=?, last_name=?,
                full_name=?, name_ascii=?, gender=?, birthday=?, city=?, hometown=?,
                employer=?, address=?, secret=?, extra=?
            WHERE id=?;
            """,
            (
                dedicated["phone"], dedicated["email"], dedicated["oib"], dedicated["fb_id"],
                dedicated["username"], dedicated["first_name"], dedicated["last_name"],
                dedicated["full_name"], name_ascii, dedicated["gender"], dedicated["birthday"],
                dedicated["city"], dedicated["hometown"], dedicated["employer"],
                dedicated["address"], dedicated["secret"], extra_json, int(row["id"]),
            ),
        )
    # The FTS index is contentless and partially populated (bulk import only),
    # so per-row updates are unsafe. Rebuild it wholesale to stay consistent.
    _rebuild_fts(con)


def dataset_layout(dataset_id: int | None = None, db_path: Path = LEAKS_DB_PATH) -> list[str]:
    """Ordered column names exactly as the user mapped them at import time."""
    if not Path(db_path).exists():
        return []
    with _connect(db_path) as con:
        if dataset_id is not None:
            fetched = con.execute(
                "SELECT columns_json FROM datasets WHERE id = ?;", (int(dataset_id),)
            ).fetchall()
        else:
            fetched = con.execute(
                "SELECT columns_json FROM datasets ORDER BY datetime(created_at) DESC, id DESC;"
            ).fetchall()
    ordered: list[str] = []
    seen: set[str] = set()
    for row in fetched:
        try:
            cols = json.loads(row[0] or "[]")
        except Exception:
            cols = []
        for token in cols:
            if token and token != "skip" and token not in seen:
                seen.add(token)
                ordered.append(token)
    return ordered


def finalize_dataset(dataset_id: int, *, db_path: Path = LEAKS_DB_PATH) -> int:
    """Populate FTS for the dataset and update its record count."""
    with _connect(db_path) as con:
        count = int(
            con.execute(
                "SELECT COUNT(*) FROM leak_records WHERE dataset_id = ?;", (dataset_id,)
            ).fetchone()[0]
        )
        if fts_available(con):
            con.execute(
                "INSERT INTO leak_records_fts(rowid, full_name, city, hometown, employer) "
                "SELECT id, full_name, city, hometown, employer FROM leak_records "
                "WHERE dataset_id = ?;",
                (dataset_id,),
            )
        con.execute(
            "UPDATE datasets SET record_count = ?, imported_at = ? WHERE id = ?;",
            (count, _now(), dataset_id),
        )
        return count


def _prepare_record_values(values: dict) -> tuple[dict, dict, str]:
    """Split a {field: value} map into normalized dedicated/extra parts."""
    from core.leaks.encoding import ascii_fold
    from core.leaks.importer import normalize_oib
    from core.leaks.schema import DEDICATED_FIELDS
    from core.osint.normalize import normalize_email, normalize_msisdn

    dedicated = {field: "" for field in DEDICATED_FIELDS}
    extra: dict[str, str] = {}
    for key, value in values.items():
        text = str(value or "").strip()
        if not text:
            continue
        if key in dedicated:
            dedicated[key] = text
        else:
            extra[key] = text

    if dedicated["phone"]:
        dedicated["phone"] = normalize_msisdn(dedicated["phone"]) or dedicated["phone"]
    if dedicated["email"]:
        dedicated["email"] = normalize_email(dedicated["email"]) or dedicated["email"].lower()
    if dedicated["oib"]:
        dedicated["oib"] = normalize_oib(dedicated["oib"])

    full_name = dedicated["full_name"] or " ".join(
        p for p in (dedicated["first_name"], dedicated["last_name"]) if p
    ).strip()
    dedicated["full_name"] = full_name
    name_ascii = ascii_fold(full_name or f"{dedicated['first_name']} {dedicated['last_name']}")
    return dedicated, extra, name_ascii


def _record_tuple(dataset_id: int, dedicated: dict, extra: dict, name_ascii: str) -> tuple:
    extra_json = json.dumps(extra, ensure_ascii=False) if extra else ""
    return (
        dataset_id,
        dedicated["phone"], dedicated["email"], dedicated["oib"], dedicated["fb_id"],
        dedicated["username"], dedicated["first_name"], dedicated["last_name"],
        dedicated["full_name"], name_ascii, dedicated["gender"], dedicated["birthday"],
        dedicated["city"], dedicated["hometown"], dedicated["employer"], dedicated["address"],
        dedicated["secret"], extra_json, "",
    )


def insert_single_record(dataset_id: int, values: dict, *, db_path: Path = LEAKS_DB_PATH) -> int | None:
    """Manually add one record to a dataset. Returns its id, or None if a duplicate."""
    init_leaks_db(db_path)
    dedicated, extra, name_ascii = _prepare_record_values(values)
    row = _record_tuple(int(dataset_id), dedicated, extra, name_ascii)
    placeholders = ", ".join(["?"] * len(_RECORD_COLUMNS))
    cols = ", ".join(_RECORD_COLUMNS)
    with _connect(db_path) as con:
        cur = con.execute(
            f"INSERT OR IGNORE INTO leak_records ({cols}) VALUES ({placeholders});", row
        )
        if cur.rowcount == 0:
            return None
        record_id = int(cur.lastrowid)
        con.execute(
            "UPDATE datasets SET record_count = record_count + 1 WHERE id = ?;", (int(dataset_id),)
        )
    return record_id


def update_record(record_id: int, values: dict, *, db_path: Path = LEAKS_DB_PATH) -> None:
    """Overwrite the editable fields of a single record."""
    dedicated, extra, name_ascii = _prepare_record_values(values)
    extra_json = json.dumps(extra, ensure_ascii=False) if extra else ""
    with _connect(db_path) as con:
        con.execute(
            """
            UPDATE leak_records SET
                phone=?, email=?, oib=?, fb_id=?, username=?, first_name=?, last_name=?,
                full_name=?, name_ascii=?, gender=?, birthday=?, city=?, hometown=?,
                employer=?, address=?, secret=?, extra=?
            WHERE id=?;
            """,
            (
                dedicated["phone"], dedicated["email"], dedicated["oib"], dedicated["fb_id"],
                dedicated["username"], dedicated["first_name"], dedicated["last_name"],
                dedicated["full_name"], name_ascii, dedicated["gender"], dedicated["birthday"],
                dedicated["city"], dedicated["hometown"], dedicated["employer"],
                dedicated["address"], dedicated["secret"], extra_json, int(record_id),
            ),
        )


def delete_record(record_id: int, *, db_path: Path = LEAKS_DB_PATH) -> None:
    with _connect(db_path) as con:
        row = con.execute(
            "SELECT dataset_id FROM leak_records WHERE id = ?;", (int(record_id),)
        ).fetchone()
        con.execute("DELETE FROM leak_records WHERE id = ?;", (int(record_id),))
        if row is not None:
            con.execute(
                "UPDATE datasets SET record_count = MAX(0, record_count - 1) WHERE id = ?;",
                (int(row[0]),),
            )


def insert_records(con: sqlite3.Connection, rows: Iterable[tuple]) -> None:
    placeholders = ", ".join(["?"] * len(_RECORD_COLUMNS))
    columns = ", ".join(_RECORD_COLUMNS)
    con.executemany(
        f"INSERT OR IGNORE INTO leak_records ({columns}) VALUES ({placeholders});",
        rows,
    )


def record_columns() -> tuple[str, ...]:
    return _RECORD_COLUMNS


def list_datasets(db_path: Path = LEAKS_DB_PATH) -> list[sqlite3.Row]:
    with _connect(db_path) as con:
        return con.execute(
            "SELECT * FROM datasets ORDER BY datetime(created_at) DESC, id DESC;"
        ).fetchall()


def get_dataset(dataset_id: int, db_path: Path = LEAKS_DB_PATH) -> sqlite3.Row | None:
    with _connect(db_path) as con:
        return con.execute("SELECT * FROM datasets WHERE id = ?;", (dataset_id,)).fetchone()


def _rebuild_fts(con: sqlite3.Connection) -> None:
    """Rebuild the (contentless) FTS index from scratch.

    The FTS5 table uses ``content=''`` and is only partially populated (bulk
    import inserts rows, manual records do not), so the special per-row
    ``'delete'`` command is unreliable and can corrupt the index. Dropping and
    repopulating from ``leak_records`` is the only consistent approach.
    """
    if not fts_available(con):
        return
    try:
        con.execute("DROP TABLE IF EXISTS leak_records_fts;")
        con.execute(
            "CREATE VIRTUAL TABLE leak_records_fts "
            "USING fts5(full_name, city, hometown, employer, content='');"
        )
        con.execute(
            "INSERT INTO leak_records_fts(rowid, full_name, city, hometown, employer) "
            "SELECT id, full_name, city, hometown, employer FROM leak_records;"
        )
    except sqlite3.DatabaseError:
        # A previously corrupted FTS index can refuse rebuild; drop it so the
        # next search recreates an empty one (init_leaks_db) and falls back to
        # LIKE matching. The dataset/record delete itself must still succeed.
        try:
            con.execute("DROP TABLE IF EXISTS leak_records_fts;")
        except sqlite3.DatabaseError:
            pass


def delete_dataset(dataset_id: int, db_path: Path = LEAKS_DB_PATH) -> None:
    with _connect(db_path) as con:
        con.execute("DELETE FROM leak_records WHERE dataset_id = ?;", (dataset_id,))
        con.execute("DELETE FROM datasets WHERE id = ?;", (dataset_id,))
        _rebuild_fts(con)


def total_record_count(db_path: Path = LEAKS_DB_PATH) -> int:
    with _connect(db_path) as con:
        return int(con.execute("SELECT COUNT(*) FROM leak_records;").fetchone()[0])


_POPULATED_CANDIDATES: tuple[str, ...] = (
    "phone",
    "first_name",
    "last_name",
    "full_name",
    "gender",
    "birthday",
    "city",
    "hometown",
    "employer",
    "email",
    "fb_id",
    "oib",
    "username",
    "address",
    "secret",
)


def extra_field_names(
    dataset_id: int | None = None, db_path: Path = LEAKS_DB_PATH, sample: int = 500
) -> list[str]:
    """Custom (non-canonical) column names the user mapped, in first-seen order."""
    if not Path(db_path).exists():
        return []
    clauses = ["extra <> ''"]
    params: list = []
    if dataset_id is not None:
        clauses.insert(0, "dataset_id = ?")
        params.append(int(dataset_id))
    where = " WHERE " + " AND ".join(clauses)
    names: list[str] = []
    seen: set[str] = set()
    with _connect(db_path) as con:
        rows = con.execute(
            f"SELECT extra FROM leak_records{where} LIMIT ?;", params + [int(sample)]
        ).fetchall()
    for row in rows:
        try:
            data = json.loads(row[0])
        except Exception:
            continue
        for key in data:
            if key not in seen:
                seen.add(key)
                names.append(key)
    return names


def populated_columns(dataset_id: int | None = None, db_path: Path = LEAKS_DB_PATH) -> list[str]:
    """Return the candidate columns that hold at least one non-empty value."""
    if not Path(db_path).exists():
        return []
    sums = ", ".join(
        f"SUM(CASE WHEN {col} <> '' THEN 1 ELSE 0 END)" for col in _POPULATED_CANDIDATES
    )
    where = " WHERE dataset_id = ?" if dataset_id is not None else ""
    params = (int(dataset_id),) if dataset_id is not None else ()
    with _connect(db_path) as con:
        row = con.execute(f"SELECT {sums} FROM leak_records{where};", params).fetchone()
    if row is None:
        return []
    return [col for col, value in zip(_POPULATED_CANDIDATES, row) if value]


@contextmanager
def import_connection(db_path: Path = LEAKS_DB_PATH) -> Iterator[sqlite3.Connection]:
    """Long-lived connection for bulk import (caller controls commit cadence)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=OFF;")
    try:
        yield con
        con.commit()
    finally:
        con.close()
