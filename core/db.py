from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Iterable


# Project root = parent of /core
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = PROJECT_ROOT / "cache" / "conduvia.db"


@dataclass
class Project:
    id: int
    name: str
    description: str
    base_folder: str
    created_at: str
    updated_at: str


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    return con


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

        # --- Indexes (performance) ---
        con.execute("CREATE INDEX IF NOT EXISTS idx_datasets_project_loaded ON datasets(project_id, loaded_at);")
        con.execute("CREATE INDEX IF NOT EXISTS idx_findings_project_created ON findings(project_id, created_at);")
        con.execute("CREATE INDEX IF NOT EXISTS idx_activity_project_created ON activity_log(project_id, created_at);")


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


def list_projects(db_path: Path = DEFAULT_DB_PATH) -> list[Project]:
    with _connect(db_path) as con:
        rows = con.execute(
            """
            SELECT id, name, description, base_folder, created_at, updated_at
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
        )
        for r in rows
    ]


def get_project(project_id: int, db_path: Path = DEFAULT_DB_PATH) -> Optional[Project]:
    with _connect(db_path) as con:
        r = con.execute(
            """
            SELECT id, name, description, base_folder, created_at, updated_at
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
    )


def touch_project(project_id: int, db_path: Path = DEFAULT_DB_PATH) -> None:
    with _connect(db_path) as con:
        con.execute(
            "UPDATE projects SET updated_at = datetime('now') WHERE id = ?;",
            (project_id,),
        )


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
