from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import os
import hashlib
import json
from typing import Optional, Iterable

# Project root = parent of /core
APP_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "ViaNyquist"
DEFAULT_DB_PATH = APP_DATA_DIR / "vianyquist.db"

@dataclass
class Project:
    id: int
    name: str
    description: str
    base_folder: str
    created_at: str
    updated_at: str
    target_identifier: str = ""
    target_type: str = ""
    subject_first_name: str = ""
    subject_last_name: str = ""
    subject_oib: str = ""
    subject_msisdn: str = ""
    subject_imsi: str = ""
    subject_imei: str = ""
    subject_ip: str = ""
    subject_extra_identifiers: str = ""

@dataclass
class PcapSource:
    id: int
    project_id: int
    file_path: str
    file_name: str
    file_sha256: str
    file_size: int
    analyzed_at: str
    format: str
    packet_count: int
    wire_bytes: int
    first_seen: str
    last_seen: str
    duration_seconds: float
    likely_device_ip: str
    summary_text: str
    period_day: str
    created_at: str
    updated_at: str

@dataclass
class IngestItem:
    id: int
    project_id: int
    source_root: str
    file_path: str
    file_name: str
    file_type: str
    file_size: int
    observed_date: str
    status: str
    message: str
    created_at: str
    updated_at: str

@contextmanager
def _connect(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()

def _column_exists(con: sqlite3.Connection, table: str, col: str) -> bool:
    rows = con.execute(f"PRAGMA table_info({table});").fetchall()
    return any(str(r["name"]) == col for r in rows)

def _ensure_columns(con: sqlite3.Connection, table: str, cols: Iterable[tuple[str, str]]) -> None:
    """
    cols: [(col_name, sqlite_type_and_default_sql), ...]
    Example: ("status", "TEXT NOT NULL DEFAULT 'New'")
    IMPORTANT: SQLite ALTER TABLE ADD COLUMN only allows CONSTANT defaults.
    """
    for col, ddl in cols:
        if not _column_exists(con, table, col):
            con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl};")

def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    with _connect(db_path) as con:
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA foreign_keys=ON;")

        # --- Projects ---
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                base_folder TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            """
        )

        # migration-safe: notes column
        _ensure_columns(con, "projects", [
            ("notes", "TEXT NOT NULL DEFAULT ''"),
            ("target_identifier", "TEXT NOT NULL DEFAULT ''"),
            ("target_type", "TEXT NOT NULL DEFAULT ''"),
            ("subject_first_name", "TEXT NOT NULL DEFAULT ''"),
            ("subject_last_name", "TEXT NOT NULL DEFAULT ''"),
            ("subject_oib", "TEXT NOT NULL DEFAULT ''"),
            ("subject_msisdn", "TEXT NOT NULL DEFAULT ''"),
            ("subject_imsi", "TEXT NOT NULL DEFAULT ''"),
            ("subject_imei", "TEXT NOT NULL DEFAULT ''"),
            ("subject_ip", "TEXT NOT NULL DEFAULT ''"),
            ("subject_extra_identifiers", "TEXT NOT NULL DEFAULT ''"),
        ])

        # --- Datasets (load history) ---
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS datasets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                folder_path TEXT NOT NULL,
                loaded_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            """
        )

        # --- PCAP sources (project evidence inputs) ---
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS pcap_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                file_name TEXT NOT NULL DEFAULT '',
                file_sha256 TEXT NOT NULL DEFAULT '',
                file_size INTEGER NOT NULL DEFAULT 0,
                analyzed_at TEXT NOT NULL DEFAULT (datetime('now')),
                format TEXT NOT NULL DEFAULT '',
                packet_count INTEGER NOT NULL DEFAULT 0,
                wire_bytes INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL DEFAULT '',
                last_seen TEXT NOT NULL DEFAULT '',
                duration_seconds REAL NOT NULL DEFAULT 0,
                likely_device_ip TEXT NOT NULL DEFAULT '',
                summary_text TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                UNIQUE(project_id, file_sha256)
            );
            """
        )
        _ensure_columns(con, "pcap_sources", [
            ("period_day", "TEXT NOT NULL DEFAULT ''"),
        ])

        # --- Findings ---
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER,
                protocol TEXT,
                application_name TEXT,
                requested_server_name TEXT,
                bidirectional_bytes INTEGER,
                bidirectional_packets INTEGER,
                bidirectional_duration_ms INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            """
        )

        # migration-safe: triage columns
        # NOTE: updated_at cannot have DEFAULT datetime('now') when added via ALTER TABLE
        _ensure_columns(con, "findings", [
            ("status", "TEXT NOT NULL DEFAULT 'New'"),
            ("tags", "TEXT NOT NULL DEFAULT ''"),
            ("updated_at", "TEXT NOT NULL DEFAULT ''"),
        ])

        _ensure_columns(con, "datasets", [
            ("json_file_count", "INTEGER NOT NULL DEFAULT 0"),
            ("pcap_file_count", "INTEGER NOT NULL DEFAULT 0"),
            ("total_size", "INTEGER NOT NULL DEFAULT 0"),
            ("first_observed", "TEXT NOT NULL DEFAULT ''"),
            ("last_observed", "TEXT NOT NULL DEFAULT ''"),
            ("indexed_at", "TEXT NOT NULL DEFAULT ''"),
        ])

        # backfill updated_at if empty (for old rows)
        if _column_exists(con, "findings", "updated_at"):
            con.execute(
                """
                UPDATE findings
                SET updated_at = created_at
                WHERE updated_at IS NULL OR updated_at = '';
                """
            )

        # --- Activity log ---
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            """
        )

        # --- Evidence ingest queue/status ---
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS ingest_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id INTEGER NOT NULL,
                source_root TEXT NOT NULL DEFAULT '',
                file_path TEXT NOT NULL,
                file_name TEXT NOT NULL DEFAULT '',
                file_type TEXT NOT NULL DEFAULT '',
                file_size INTEGER NOT NULL DEFAULT 0,
                observed_date TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                message TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE,
                UNIQUE(project_id, file_path)
            );
            """
        )

        con.execute(
            """
            CREATE TABLE IF NOT EXISTS project_behavior_profiles (
                project_id INTEGER PRIMARY KEY,
                source_key TEXT NOT NULL DEFAULT '',
                flow_count INTEGER NOT NULL DEFAULT 0,
                json_file_count INTEGER NOT NULL DEFAULT 0,
                profile_json TEXT NOT NULL DEFAULT '{}',
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            """
        )

        # --- App settings ---
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            """
        )

        # --- Indexes (performance) ---
        con.execute("CREATE INDEX IF NOT EXISTS idx_datasets_project_loaded ON datasets(project_id, loaded_at);")
        con.execute("CREATE INDEX IF NOT EXISTS idx_pcap_sources_project_created ON pcap_sources(project_id, created_at);")
        con.execute("CREATE INDEX IF NOT EXISTS idx_pcap_sources_project_device ON pcap_sources(project_id, likely_device_ip);")
        con.execute("CREATE INDEX IF NOT EXISTS idx_findings_project_created ON findings(project_id, created_at);")
        con.execute("CREATE INDEX IF NOT EXISTS idx_activity_project_created ON activity_log(project_id, created_at);")
        con.execute("CREATE INDEX IF NOT EXISTS idx_ingest_items_project_status ON ingest_items(project_id, status, file_type);")

# ---------------- App settings ----------------
def get_app_setting(key: str, default: str = "", db_path: Path = DEFAULT_DB_PATH) -> str:
    key = (key or "").strip()
    if not key:
        return default

    with _connect(db_path) as con:
        row = con.execute(
            "SELECT value FROM app_settings WHERE key = ?;",
            (key,),
        ).fetchone()

    if not row:
        return default

    return str(row["value"] or "")


def set_app_setting(key: str, value: str, db_path: Path = DEFAULT_DB_PATH) -> None:
    key = (key or "").strip()
    if not key:
        raise ValueError("Setting key is required.")

    with _connect(db_path) as con:
        con.execute(
            """
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = datetime('now');
            """,
            (key, value or ""),
        )


def get_app_settings(prefix: str = "", db_path: Path = DEFAULT_DB_PATH) -> dict[str, str]:
    prefix = prefix or ""

    with _connect(db_path) as con:
        if prefix:
            rows = con.execute(
                "SELECT key, value FROM app_settings WHERE key LIKE ? ORDER BY key;",
                (prefix + "%",),
            ).fetchall()
        else:
            rows = con.execute("SELECT key, value FROM app_settings ORDER BY key;").fetchall()

    return {str(r["key"]): str(r["value"] or "") for r in rows}

# ---------------- Projects ----------------
def create_project(
    name: str,
    description: str = "",
    base_folder: str = "",
    subject_first_name: str = "",
    subject_last_name: str = "",
    subject_oib: str = "",
    subject_msisdn: str = "",
    subject_imsi: str = "",
    subject_imei: str = "",
    subject_ip: str = "",
    subject_extra_identifiers: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> int:
    name = (name or "").strip()
    if not name:
        raise ValueError("Project name is required.")

    with _connect(db_path) as con:
        cur = con.execute(
            """
            INSERT INTO projects (
                name,
                description,
                base_folder,
                subject_first_name,
                subject_last_name,
                subject_oib,
                subject_msisdn,
                subject_imsi,
                subject_imei,
                subject_ip,
                subject_extra_identifiers,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'));
            """,
            (
                name,
                description or "",
                base_folder or "",
                (subject_first_name or "").strip(),
                (subject_last_name or "").strip(),
                (subject_oib or "").strip(),
                (subject_msisdn or "").strip(),
                (subject_imsi or "").strip(),
                (subject_imei or "").strip(),
                (subject_ip or "").strip(),
                (subject_extra_identifiers or "").strip(),
            ),
        )
        return int(cur.lastrowid)
    
def update_project(
    project_id: int,
    name: str,
    description: str = "",
    base_folder: str = "",
    subject_first_name: str = "",
    subject_last_name: str = "",
    subject_oib: str = "",
    subject_msisdn: str = "",
    subject_imsi: str = "",
    subject_imei: str = "",
    subject_ip: str = "",
    subject_extra_identifiers: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    name = (name or "").strip()

    if not name:
        raise ValueError("Project name is required.")

    with _connect(db_path) as con:
        con.execute(
            """
            UPDATE projects
            SET
                name = ?,
                description = ?,
                base_folder = ?,
                subject_first_name = ?,
                subject_last_name = ?,
                subject_oib = ?,
                subject_msisdn = ?,
                subject_imsi = ?,
                subject_imei = ?,
                subject_ip = ?,
                subject_extra_identifiers = ?,
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (
                name,
                description or "",
                base_folder or "",
                (subject_first_name or "").strip(),
                (subject_last_name or "").strip(),
                (subject_oib or "").strip(),
                (subject_msisdn or "").strip(),
                (subject_imsi or "").strip(),
                (subject_imei or "").strip(),
                (subject_ip or "").strip(),
                (subject_extra_identifiers or "").strip(),
                project_id,
            ),
        )

def list_projects(db_path: Path = DEFAULT_DB_PATH) -> list[Project]:
    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT
                id,
                name,
                description,
                base_folder,
                created_at,
                updated_at,
                target_identifier,
                target_type,
                subject_first_name,
                subject_last_name,
                subject_oib,
                subject_msisdn,
                subject_imsi,
                subject_imei,
                subject_ip,
                subject_extra_identifiers
            FROM projects
            ORDER BY updated_at DESC;
            """
        ).fetchall()

    return [
        Project(
            id=int(r["id"]),
            name=str(r["name"]),
            description=str(r["description"] or ""),
            base_folder=str(r["base_folder"] or ""),
            created_at=str(r["created_at"]),
            updated_at=str(r["updated_at"]),
            target_identifier=str(r["target_identifier"] or ""),
            target_type=str(r["target_type"] or ""),
            subject_first_name=str(r["subject_first_name"] or ""),
            subject_last_name=str(r["subject_last_name"] or ""),
            subject_oib=str(r["subject_oib"] or ""),
            subject_msisdn=str(r["subject_msisdn"] or ""),
            subject_imsi=str(r["subject_imsi"] or ""),
            subject_imei=str(r["subject_imei"] or ""),
            subject_ip=str(r["subject_ip"] or ""),
            subject_extra_identifiers=str(r["subject_extra_identifiers"] or ""),
        )
        for r in rows
    ]

def get_project(project_id: int, db_path: Path = DEFAULT_DB_PATH) -> Optional[Project]:
    with _connect(db_path) as con:
        r = con.execute(
            """
            SELECT
                id,
                name,
                description,
                base_folder,
                created_at,
                updated_at,
                target_identifier,
                target_type,
                subject_first_name,
                subject_last_name,
                subject_oib,
                subject_msisdn,
                subject_imsi,
                subject_imei,
                subject_ip,
                subject_extra_identifiers
            FROM projects
            WHERE id = ?;
            """,
            (project_id,),
        ).fetchone()

    if not r:
        return None

    return Project(
        id=int(r["id"]),
        name=str(r["name"]),
        description=str(r["description"] or ""),
        base_folder=str(r["base_folder"] or ""),
        created_at=str(r["created_at"]),
        updated_at=str(r["updated_at"]),
        target_identifier=str(r["target_identifier"] or ""),
        target_type=str(r["target_type"] or ""),
        subject_first_name=str(r["subject_first_name"] or ""),
        subject_last_name=str(r["subject_last_name"] or ""),
        subject_oib=str(r["subject_oib"] or ""),
        subject_msisdn=str(r["subject_msisdn"] or ""),
        subject_imsi=str(r["subject_imsi"] or ""),
        subject_imei=str(r["subject_imei"] or ""),
        subject_ip=str(r["subject_ip"] or ""),
        subject_extra_identifiers=str(r["subject_extra_identifiers"] or ""),
    )

def touch_project(project_id: int, db_path: Path = DEFAULT_DB_PATH) -> None:
    with _connect(db_path) as con:
        con.execute(
            "UPDATE projects SET updated_at = datetime('now') WHERE id = ?;",
            (project_id,),
        )

def set_project_target(
    project_id: int,
    target_identifier: str = "",
    target_type: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    with _connect(db_path) as con:
        con.execute(
            """
            UPDATE projects
            SET
                target_identifier = ?,
                target_type = ?,
                updated_at = datetime('now')
            WHERE id = ?;
            """,
            (
                (target_identifier or "").strip(),
                (target_type or "").strip(),
                project_id,
            ),
        )

def set_project_subject(
    project_id: int,
    *,
    first_name: str = "",
    last_name: str = "",
    oib: str = "",
    msisdn: str = "",
    imsi: str = "",
    imei: str = "",
    ip: str = "",
    extra_identifiers: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    with _connect(db_path) as con:
        con.execute(
            """
            UPDATE projects
            SET
                subject_first_name = ?,
                subject_last_name = ?,
                subject_oib = ?,
                subject_msisdn = ?,
                subject_imsi = ?,
                subject_imei = ?,
                subject_ip = ?,
                subject_extra_identifiers = ?,
                updated_at = datetime('now')
            WHERE id = ?;
            """,
            (
                (first_name or "").strip(),
                (last_name or "").strip(),
                (oib or "").strip(),
                (msisdn or "").strip(),
                (imsi or "").strip(),
                (imei or "").strip(),
                (ip or "").strip(),
                (extra_identifiers or "").strip(),
                project_id,
            ),
        )

def delete_project(project_id: int, db_path: Path = DEFAULT_DB_PATH) -> None:
    with _connect(db_path) as con:
        # foreign_keys=ON je u init_db, ali je dobro osigurati i ovdje
        con.execute("PRAGMA foreign_keys=ON;")
        con.execute("DELETE FROM projects WHERE id = ?;", (project_id,))

def get_project_notes(project_id: int, db_path: Path = DEFAULT_DB_PATH) -> str:
    with _connect(db_path) as con:
        r = con.execute("SELECT notes FROM projects WHERE id = ?;", (project_id,)).fetchone()
    return str(r["notes"] or "") if r else ""

def set_project_notes(project_id: int, notes: str, db_path: Path = DEFAULT_DB_PATH) -> None:
    with _connect(db_path) as con:
        con.execute(
            "UPDATE projects SET notes = ?, updated_at = datetime('now') WHERE id = ?;",
            (notes or "", project_id),
        )

# ---------------- Activity log ----------------
def add_activity(project_id: int, event_type: str, message: str = "", db_path: Path = DEFAULT_DB_PATH) -> None:
    with _connect(db_path) as con:
        con.execute(
            """
            INSERT INTO activity_log (project_id, event_type, message)
            VALUES (?, ?, ?);
            """,
            (project_id, (event_type or "").strip() or "event", message or ""),
        )

def list_activity(project_id: int, limit: int = 200, db_path: Path = DEFAULT_DB_PATH) -> list[sqlite3.Row]:
    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT *
            FROM activity_log
            WHERE project_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?;
            """,
            (project_id, limit),
        ).fetchall()
    return rows


# ---------------- Evidence ingest status ----------------
def upsert_ingest_items(
    project_id: int,
    source_root: str,
    items: Iterable[dict],
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    source_root = (source_root or "").strip()
    rows = []
    for item in items:
        file_path = str(item.get("file_path") or item.get("path") or "").strip()
        if not file_path:
            continue
        rows.append({
            "source_root": source_root,
            "file_path": file_path,
            "file_name": str(item.get("file_name") or Path(file_path).name),
            "file_type": str(item.get("file_type") or item.get("kind") or "").strip().lower(),
            "file_size": max(0, int(item.get("file_size") or item.get("size") or 0)),
            "observed_date": str(item.get("observed_date") or ""),
        })
    if not rows:
        return

    with _connect(db_path) as con:
        for row in rows:
            con.execute(
                """
                INSERT INTO ingest_items (
                    project_id, source_root, file_path, file_name, file_type,
                    file_size, observed_date, status, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', strftime('%Y-%m-%d %H:%M:%f', 'now'))
                ON CONFLICT(project_id, file_path) DO UPDATE SET
                    source_root = excluded.source_root,
                    file_name = excluded.file_name,
                    file_type = excluded.file_type,
                    file_size = excluded.file_size,
                    observed_date = excluded.observed_date,
                    status = CASE
                        WHEN ingest_items.status = 'done' THEN ingest_items.status
                        ELSE 'pending'
                    END,
                    message = CASE
                        WHEN ingest_items.status = 'done' THEN ingest_items.message
                        ELSE ''
                    END,
                    updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now');
                """,
                (
                    project_id,
                    row["source_root"],
                    row["file_path"],
                    row["file_name"],
                    row["file_type"],
                    row["file_size"],
                    row["observed_date"],
                ),
            )


def mark_ingest_item(
    project_id: int,
    file_path: str,
    status: str,
    message: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    file_path = (file_path or "").strip()
    status = (status or "").strip().lower()
    if not file_path or not status:
        return

    with _connect(db_path) as con:
        con.execute(
            """
            UPDATE ingest_items
            SET status = ?,
                message = ?,
                updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now')
            WHERE project_id = ? AND file_path = ?;
            """,
            (status, message or "", project_id, file_path),
        )


def list_ingest_items(
    project_id: int,
    *,
    source_root: str = "",
    file_type: str = "",
    status: str = "",
    limit: int = 10000,
    db_path: Path = DEFAULT_DB_PATH,
) -> list[IngestItem]:
    clauses = ["project_id = ?"]
    params: list[object] = [project_id]
    if source_root:
        clauses.append("source_root = ?")
        params.append(source_root)
    if file_type:
        clauses.append("file_type = ?")
        params.append(file_type.strip().lower())
    if status:
        clauses.append("status = ?")
        params.append(status.strip().lower())
    params.append(limit)

    with _connect(db_path) as con:
        rows = con.execute(
            f"""
            SELECT *
            FROM ingest_items
            WHERE {' AND '.join(clauses)}
            ORDER BY observed_date ASC, file_path ASC
            LIMIT ?;
            """,
            tuple(params),
        ).fetchall()
    return [_ingest_item_from_row(row) for row in rows]


def ingest_status_map(
    project_id: int,
    file_paths: Iterable[str],
    db_path: Path = DEFAULT_DB_PATH,
) -> dict[str, str]:
    paths = [str(path or "").strip() for path in file_paths if str(path or "").strip()]
    if not paths:
        return {}
    out: dict[str, str] = {}
    with _connect(db_path) as con:
        for path in paths:
            row = con.execute(
                """
                SELECT file_path, status
                FROM ingest_items
                WHERE project_id = ? AND file_path = ?;
                """,
                (project_id, path),
            ).fetchone()
            if row:
                out[str(row["file_path"])] = str(row["status"] or "")
    return out


def _ingest_item_from_row(row: sqlite3.Row) -> IngestItem:
    return IngestItem(
        id=int(row["id"]),
        project_id=int(row["project_id"]),
        source_root=str(row["source_root"] or ""),
        file_path=str(row["file_path"] or ""),
        file_name=str(row["file_name"] or ""),
        file_type=str(row["file_type"] or ""),
        file_size=int(row["file_size"] or 0),
        observed_date=str(row["observed_date"] or ""),
        status=str(row["status"] or ""),
        message=str(row["message"] or ""),
        created_at=str(row["created_at"] or ""),
        updated_at=str(row["updated_at"] or ""),
    )


def save_project_behavior_profile(
    project_id: int,
    profile: dict,
    *,
    source_key: str = "",
    json_file_count: int = 0,
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    payload = json.dumps(profile or {}, ensure_ascii=False)
    flow_count = int((profile or {}).get("flow_count") or 0)
    with _connect(db_path) as con:
        con.execute(
            """
            INSERT INTO project_behavior_profiles (
                project_id, source_key, flow_count, json_file_count, profile_json, updated_at
            )
            VALUES (?, ?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%f', 'now'))
            ON CONFLICT(project_id) DO UPDATE SET
                source_key = excluded.source_key,
                flow_count = excluded.flow_count,
                json_file_count = excluded.json_file_count,
                profile_json = excluded.profile_json,
                updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now');
            """,
            (project_id, source_key or "", flow_count, int(json_file_count or 0), payload),
        )


def get_project_behavior_profile(project_id: int, db_path: Path = DEFAULT_DB_PATH) -> dict:
    with _connect(db_path) as con:
        row = con.execute(
            """
            SELECT *
            FROM project_behavior_profiles
            WHERE project_id = ?;
            """,
            (project_id,),
        ).fetchone()
    if not row:
        return {}
    try:
        profile = json.loads(str(row["profile_json"] or "{}"))
    except Exception:
        profile = {}
    if isinstance(profile, dict):
        profile.setdefault("source_key", str(row["source_key"] or ""))
        profile.setdefault("json_file_count", int(row["json_file_count"] or 0))
        profile.setdefault("flow_count", int(row["flow_count"] or 0))
        profile.setdefault("persisted_at", str(row["updated_at"] or ""))
        profile["from_project_index"] = True
        return profile
    return {}

# ---------------- Datasets ----------------
def _dataset_path_key(path_text: str) -> str:
    text = (path_text or "").strip()
    if not text:
        return ""
    try:
        return str(Path(text).resolve()).casefold()
    except Exception:
        return text.casefold()


def add_dataset_load(project_id: int, folder_path: str, db_path: Path = DEFAULT_DB_PATH) -> None:
    folder_path = (folder_path or "").strip()
    if not folder_path:
        return

    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT id, folder_path
            FROM datasets
            WHERE project_id = ?;
            """,
            (project_id,),
        ).fetchall()
        path_key = _dataset_path_key(folder_path)
        existing_id = None
        for row in rows:
            if _dataset_path_key(str(row["folder_path"] or "")) == path_key:
                existing_id = int(row["id"])
                break

        if existing_id is not None:
            con.execute(
                """
                UPDATE datasets
                SET folder_path = ?, loaded_at = strftime('%Y-%m-%d %H:%M:%f', 'now')
                WHERE id = ?;
                """,
                (folder_path, existing_id),
            )
        else:
            con.execute(
                """
                INSERT INTO datasets (project_id, folder_path, loaded_at)
                VALUES (?, ?, strftime('%Y-%m-%d %H:%M:%f', 'now'));
                """,
                (project_id, folder_path),
            )

    touch_project(project_id, db_path=db_path)
    add_activity(project_id, "dataset_loaded", folder_path, db_path=db_path)


def update_dataset_scan_metadata(
    project_id: int,
    folder_path: str,
    *,
    json_file_count: int = 0,
    pcap_file_count: int = 0,
    total_size: int = 0,
    first_observed: str = "",
    last_observed: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    folder_path = (folder_path or "").strip()
    if not folder_path:
        return

    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT id, folder_path, json_file_count, pcap_file_count, total_size, first_observed, last_observed
            FROM datasets
            WHERE project_id = ?;
            """,
            (project_id,),
        ).fetchall()
        path_key = _dataset_path_key(folder_path)
        dataset_id = None
        existing_row = None
        for row in rows:
            if _dataset_path_key(str(row["folder_path"] or "")) == path_key:
                dataset_id = int(row["id"])
                existing_row = row
                break

        if dataset_id is None:
            con.execute(
                """
                INSERT INTO datasets (
                    project_id, folder_path, loaded_at,
                    json_file_count, pcap_file_count, total_size,
                    first_observed, last_observed, indexed_at
                )
                VALUES (
                    ?, ?, strftime('%Y-%m-%d %H:%M:%f', 'now'),
                    ?, ?, ?, ?, ?, strftime('%Y-%m-%d %H:%M:%f', 'now')
                );
                """,
                (
                    project_id,
                    folder_path,
                    max(0, int(json_file_count or 0)),
                    max(0, int(pcap_file_count or 0)),
                    max(0, int(total_size or 0)),
                    first_observed or "",
                    last_observed or "",
                ),
            )
        else:
            existing_first = str(existing_row["first_observed"] or "") if existing_row else ""
            existing_last = str(existing_row["last_observed"] or "") if existing_row else ""
            merged_first = min([value for value in (existing_first, first_observed or "") if value] or [""])
            merged_last = max([value for value in (existing_last, last_observed or "") if value] or [""])
            con.execute(
                """
                UPDATE datasets
                SET json_file_count = ?,
                    pcap_file_count = ?,
                    total_size = ?,
                    first_observed = ?,
                    last_observed = ?,
                    indexed_at = strftime('%Y-%m-%d %H:%M:%f', 'now')
                WHERE id = ?;
                """,
                (
                    max(int(existing_row["json_file_count"] or 0), max(0, int(json_file_count or 0))) if existing_row else max(0, int(json_file_count or 0)),
                    max(int(existing_row["pcap_file_count"] or 0), max(0, int(pcap_file_count or 0))) if existing_row else max(0, int(pcap_file_count or 0)),
                    max(int(existing_row["total_size"] or 0), max(0, int(total_size or 0))) if existing_row else max(0, int(total_size or 0)),
                    merged_first,
                    merged_last,
                    dataset_id,
                ),
            )


def list_recent_dataset_sources(project_id: int, limit: int = 10, db_path: Path = DEFAULT_DB_PATH) -> list[sqlite3.Row]:
    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT *
            FROM datasets
            WHERE project_id = ?
            ORDER BY loaded_at DESC, id DESC
            """,
            (project_id,),
        ).fetchall()
    recent: list[sqlite3.Row] = []
    seen: set[str] = set()
    for row in rows:
        path = str(row["folder_path"] or "")
        key = _dataset_path_key(path)
        if not key or key in seen:
            continue
        seen.add(key)
        recent.append(row)
        if len(recent) >= limit:
            break
    return recent

def list_recent_datasets(project_id: int, limit: int = 10, db_path: Path = DEFAULT_DB_PATH) -> list[str]:
    return [
        str(row["folder_path"] or "")
        for row in list_recent_dataset_sources(project_id, limit=limit, db_path=db_path)
    ]

# ---------------- PCAP sources ----------------
def file_sha256(file_path: str | Path, *, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with Path(file_path).open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def add_pcap_source(
    project_id: int,
    *,
    file_path: str,
    file_sha256_value: str,
    file_size: int,
    file_name: str = "",
    format: str = "",
    packet_count: int = 0,
    wire_bytes: int = 0,
    first_seen: str = "",
    last_seen: str = "",
    duration_seconds: float = 0.0,
    likely_device_ip: str = "",
    summary_text: str = "",
    period_day: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> int:
    file_path = (file_path or "").strip()
    file_sha256_value = (file_sha256_value or "").strip()
    if not file_path:
        raise ValueError("PCAP file path is required.")
    if not file_sha256_value:
        raise ValueError("PCAP file hash is required.")

    file_name = file_name or Path(file_path).name

    with _connect(db_path) as con:
        existing = con.execute(
            """
            SELECT id
            FROM pcap_sources
            WHERE project_id = ? AND file_sha256 = ?;
            """,
            (project_id, file_sha256_value),
        ).fetchone()

        if existing:
            source_id = int(existing["id"])
            con.execute(
                """
                UPDATE pcap_sources
                SET
                    file_path = ?,
                    file_name = ?,
                    file_size = ?,
                    analyzed_at = strftime('%Y-%m-%d %H:%M:%f', 'now'),
                    format = ?,
                    packet_count = ?,
                    wire_bytes = ?,
                    first_seen = ?,
                    last_seen = ?,
                    duration_seconds = ?,
                    likely_device_ip = ?,
                    summary_text = ?,
                    period_day = ?,
                    updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now')
                WHERE id = ?;
                """,
                (
                    file_path,
                    file_name,
                    int(file_size or 0),
                    format or "",
                    int(packet_count or 0),
                    int(wire_bytes or 0),
                    first_seen or "",
                    last_seen or "",
                    float(duration_seconds or 0.0),
                    likely_device_ip or "",
                    summary_text or "",
                    period_day or "",
                    source_id,
                ),
            )
        else:
            cur = con.execute(
                """
                INSERT INTO pcap_sources (
                    project_id,
                    file_path,
                    file_name,
                    file_sha256,
                    file_size,
                    format,
                    packet_count,
                    wire_bytes,
                    first_seen,
                    last_seen,
                    duration_seconds,
                    likely_device_ip,
                    summary_text,
                    period_day
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    project_id,
                    file_path,
                    file_name,
                    file_sha256_value,
                    int(file_size or 0),
                    format or "",
                    int(packet_count or 0),
                    int(wire_bytes or 0),
                    first_seen or "",
                    last_seen or "",
                    float(duration_seconds or 0.0),
                    likely_device_ip or "",
                    summary_text or "",
                    period_day or "",
                ),
            )
            source_id = int(cur.lastrowid)

    touch_project(project_id, db_path=db_path)
    add_activity(project_id, "pcap_saved", f"#{source_id} {file_name}", db_path=db_path)
    return source_id


def save_pcap_period_summary(
    project_id: int,
    *,
    period_day: str,
    file_path: str,
    file_sha256_value: str,
    file_size: int,
    file_name: str = "",
    format: str = "",
    packet_count: int = 0,
    wire_bytes: int = 0,
    first_seen: str = "",
    last_seen: str = "",
    duration_seconds: float = 0.0,
    likely_device_ip: str = "",
    summary_text: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> int:
    """Upsert one daily PCAP aggregate for a project period (stable Profile day row)."""
    period_day = (period_day or "").strip()
    if not period_day:
        raise ValueError("period_day is required for daily PCAP saves.")

    with _connect(db_path) as con:
        existing = con.execute(
            """
            SELECT id
            FROM pcap_sources
            WHERE project_id = ?
              AND period_day = ?;
            """,
            (project_id, period_day),
        ).fetchone()

        if existing:
            source_id = int(existing["id"])
            con.execute(
                """
                UPDATE pcap_sources
                SET
                    file_path = ?,
                    file_name = ?,
                    file_sha256 = ?,
                    file_size = ?,
                    analyzed_at = strftime('%Y-%m-%d %H:%M:%f', 'now'),
                    format = ?,
                    packet_count = ?,
                    wire_bytes = ?,
                    first_seen = ?,
                    last_seen = ?,
                    duration_seconds = ?,
                    likely_device_ip = ?,
                    summary_text = ?,
                    updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now')
                WHERE id = ?;
                """,
                (
                    file_path,
                    file_name,
                    file_sha256_value,
                    int(file_size or 0),
                    format or "",
                    int(packet_count or 0),
                    int(wire_bytes or 0),
                    first_seen or "",
                    last_seen or "",
                    float(duration_seconds or 0.0),
                    likely_device_ip or "",
                    summary_text or "",
                    source_id,
                ),
            )
        else:
            source_id = add_pcap_source(
                project_id,
                file_path=file_path,
                file_sha256_value=file_sha256_value,
                file_size=file_size,
                file_name=file_name,
                format=format,
                packet_count=packet_count,
                wire_bytes=wire_bytes,
                first_seen=first_seen,
                last_seen=last_seen,
                duration_seconds=duration_seconds,
                likely_device_ip=likely_device_ip,
                summary_text=summary_text,
                period_day=period_day,
                db_path=db_path,
            )
            return source_id

    touch_project(project_id, db_path=db_path)
    add_activity(project_id, "pcap_saved", f"#{source_id} {file_name}", db_path=db_path)
    return source_id


def list_saved_pcap_period_days(project_id: int, *, db_path: Path = DEFAULT_DB_PATH) -> list[str]:
    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT DISTINCT period_day
            FROM pcap_sources
            WHERE project_id = ?
              AND period_day != ''
            ORDER BY period_day;
            """,
            (project_id,),
        ).fetchall()
    return [str(row["period_day"]) for row in rows if str(row["period_day"] or "").strip()]


def list_pcap_sources(project_id: int, limit: int = 50, db_path: Path = DEFAULT_DB_PATH) -> list[PcapSource]:
    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT *
            FROM pcap_sources
            WHERE project_id = ?
            ORDER BY updated_at DESC, created_at DESC, id DESC
            LIMIT ?;
            """,
            (project_id, limit),
        ).fetchall()

    return [_pcap_source_from_row(r) for r in rows]


def list_project_pcap_device_ips(project_id: int, db_path: Path = DEFAULT_DB_PATH) -> list[str]:
    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT DISTINCT likely_device_ip
            FROM pcap_sources
            WHERE project_id = ?
              AND likely_device_ip IS NOT NULL
              AND likely_device_ip != ''
            ORDER BY likely_device_ip;
            """,
            (project_id,),
        ).fetchall()

    return [str(r["likely_device_ip"] or "") for r in rows if str(r["likely_device_ip"] or "").strip()]


def _pcap_source_from_row(r: sqlite3.Row) -> PcapSource:
    return PcapSource(
        id=int(r["id"]),
        project_id=int(r["project_id"]),
        file_path=str(r["file_path"] or ""),
        file_name=str(r["file_name"] or ""),
        file_sha256=str(r["file_sha256"] or ""),
        file_size=int(r["file_size"] or 0),
        analyzed_at=str(r["analyzed_at"] or ""),
        format=str(r["format"] or ""),
        packet_count=int(r["packet_count"] or 0),
        wire_bytes=int(r["wire_bytes"] or 0),
        first_seen=str(r["first_seen"] or ""),
        last_seen=str(r["last_seen"] or ""),
        duration_seconds=float(r["duration_seconds"] or 0.0),
        likely_device_ip=str(r["likely_device_ip"] or ""),
        summary_text=str(r["summary_text"] or ""),
        period_day=str(r["period_day"] or "") if "period_day" in r.keys() else "",
        created_at=str(r["created_at"] or ""),
        updated_at=str(r["updated_at"] or ""),
    )

# ---------------- Findings ----------------
def add_finding(
    project_id: int,
    flow: dict,
    title: str,
    note: str = "",
    status: str = "New",
    tags: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> int:
    title = (title or "").strip()
    if not title:
        raise ValueError("Finding title is required.")

    src_ip = str(flow.get("src_ip", "") or "")
    dst_ip = str(flow.get("dst_ip", "") or "")
    if not src_ip or not dst_ip:
        raise ValueError("Flow must contain src_ip and dst_ip.")

    status = (status or "").strip() or "New"
    tags = (tags or "").strip()

    with _connect(db_path) as con:
        cur = con.execute(
            """
            INSERT INTO findings (
                project_id, title, note, status, tags, updated_at,
                src_ip, src_port, dst_ip, dst_port,
                protocol, application_name, requested_server_name,
                bidirectional_bytes, bidirectional_packets, bidirectional_duration_ms
            )
            VALUES (?, ?, ?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                project_id,
                title,
                note or "",
                status,
                tags,
                src_ip,
                flow.get("src_port"),
                dst_ip,
                flow.get("dst_port"),
                str(flow.get("protocol", "") or ""),
                str(flow.get("application_name", "") or ""),
                str(flow.get("requested_server_name", "") or ""),
                flow.get("bidirectional_bytes"),
                flow.get("bidirectional_packets"),
                flow.get("bidirectional_duration_ms"),
            ),
        )
        fid = int(cur.lastrowid)

    touch_project(project_id, db_path=db_path)
    add_activity(project_id, "finding_created", f"#{fid} {title}", db_path=db_path)
    return fid

def list_findings(project_id: int, limit: int = 200, db_path: Path = DEFAULT_DB_PATH) -> list[sqlite3.Row]:
    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT *
            FROM findings
            WHERE project_id = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?;
            """,
            (project_id, limit),
        ).fetchall()
    return rows

def get_finding(finding_id: int, db_path: Path = DEFAULT_DB_PATH) -> Optional[sqlite3.Row]:
    with _connect(db_path) as con:
        row = con.execute(
            "SELECT * FROM findings WHERE id = ?;",
            (finding_id,),
        ).fetchone()
    return row

def _get_finding_project_and_title(finding_id: int, db_path: Path = DEFAULT_DB_PATH) -> tuple[int | None, str]:
    with _connect(db_path) as con:
        r = con.execute(
            "SELECT project_id, title FROM findings WHERE id = ?;",
            (finding_id,),
        ).fetchone()
    if not r:
        return None, ""
    return int(r["project_id"]), str(r["title"] or "")

def update_finding(
    finding_id: int,
    title: str,
    note: str = "",
    status: str = "New",
    tags: str = "",
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    title = (title or "").strip()
    if not title:
        raise ValueError("Finding title is required.")

    status = (status or "").strip() or "New"
    tags = (tags or "").strip()

    proj_id, _old_title = _get_finding_project_and_title(finding_id, db_path=db_path)

    with _connect(db_path) as con:
        con.execute(
            """
            UPDATE findings
            SET title = ?, note = ?, status = ?, tags = ?, updated_at = datetime('now')
            WHERE id = ?;
            """,
            (title, note or "", status, tags, finding_id),
        )

    if proj_id is not None:
        touch_project(proj_id, db_path=db_path)
        add_activity(proj_id, "finding_updated", f"#{finding_id} {title}", db_path=db_path)

def delete_finding(finding_id: int, db_path: Path = DEFAULT_DB_PATH) -> None:
    proj_id, title = _get_finding_project_and_title(finding_id, db_path=db_path)

    with _connect(db_path) as con:
        con.execute("DELETE FROM findings WHERE id = ?;", (finding_id,))

    if proj_id is not None:
        touch_project(proj_id, db_path=db_path)
        add_activity(proj_id, "finding_deleted", f"#{finding_id} {title}", db_path=db_path)
