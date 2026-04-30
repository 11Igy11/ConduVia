from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import os
import hashlib
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
    db_path: Path = DEFAULT_DB_PATH,
) -> int:
    name = (name or "").strip()
    if not name:
        raise ValueError("Project name is required.")

    with _connect(db_path) as con:
        cur = con.execute(
            """
            INSERT INTO projects (name, description, base_folder, updated_at)
            VALUES (?, ?, ?, datetime('now'));
            """,
            (name, description or "", base_folder or ""),
        )
        return int(cur.lastrowid)
    
def update_project(
    project_id: int,
    name: str,
    description: str = "",
    base_folder: str = "",
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
                updated_at = datetime('now')
            WHERE id = ?
            """,
            (
                name,
                description or "",
                base_folder or "",
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
                target_type
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
                target_type
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

# ---------------- Datasets ----------------
def add_dataset_load(project_id: int, folder_path: str, db_path: Path = DEFAULT_DB_PATH) -> None:
    folder_path = (folder_path or "").strip()
    if not folder_path:
        return

    with _connect(db_path) as con:
        con.execute(
            """
            INSERT INTO datasets (project_id, folder_path)
            VALUES (?, ?);
            """,
            (project_id, folder_path),
        )

    touch_project(project_id, db_path=db_path)
    add_activity(project_id, "dataset_loaded", folder_path, db_path=db_path)

def list_recent_datasets(project_id: int, limit: int = 10, db_path: Path = DEFAULT_DB_PATH) -> list[str]:
    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT folder_path
            FROM datasets
            WHERE project_id = ?
            ORDER BY loaded_at DESC, id DESC
            LIMIT ?;
            """,
            (project_id, limit),
        ).fetchall()
    return [str(r["folder_path"]) for r in rows]

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
                    analyzed_at = datetime('now'),
                    format = ?,
                    packet_count = ?,
                    wire_bytes = ?,
                    first_seen = ?,
                    last_seen = ?,
                    duration_seconds = ?,
                    likely_device_ip = ?,
                    summary_text = ?,
                    updated_at = datetime('now')
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
                    summary_text
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                ),
            )
            source_id = int(cur.lastrowid)

    touch_project(project_id, db_path=db_path)
    add_activity(project_id, "pcap_saved", f"#{source_id} {file_name}", db_path=db_path)
    return source_id


def list_pcap_sources(project_id: int, limit: int = 50, db_path: Path = DEFAULT_DB_PATH) -> list[PcapSource]:
    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT *
            FROM pcap_sources
            WHERE project_id = ?
            ORDER BY created_at DESC, id DESC
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
