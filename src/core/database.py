"""SQLite access layer: connections, versioned migrations and seed data."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from src.core import config, constants


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect(write: bool = False):
    """Yield a connection inside a transaction. Commits on success, rolls back on error."""
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(config.DB_PATH, timeout=30, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=30000")
    try:
        con.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield con
        except BaseException:
            if con.in_transaction:
                con.execute("ROLLBACK")
            raise
        else:
            if con.in_transaction:
                con.execute("COMMIT")
    finally:
        con.close()


# Each migration is a list of single statements (executed inside one transaction).
MIGRATIONS: list[tuple[int, list[str]]] = [
    (1, [
        """CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            display_name TEXT,
            status TEXT NOT NULL CHECK (status IN ('active','disabled','pending')),
            created_at TEXT NOT NULL,
            created_by TEXT,
            last_login_at TEXT)""",
        """CREATE TABLE roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            description TEXT,
            is_system INTEGER NOT NULL DEFAULT 0)""",
        """CREATE TABLE role_permissions (
            role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            permission TEXT NOT NULL,
            PRIMARY KEY (role_id, permission))""",
        """CREATE TABLE user_roles (
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, role_id))""",
        """CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT,
            updated_by TEXT)""",
        """CREATE TABLE sessions (
            sid_hash TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen TEXT NOT NULL)""",
        """CREATE TABLE audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            panel TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            outcome TEXT NOT NULL,
            details TEXT,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL)""",
        "CREATE INDEX idx_audit_ts ON audit_log(ts)",
        "CREATE INDEX idx_audit_actor ON audit_log(actor)",
        "CREATE INDEX idx_audit_panel ON audit_log(panel)",
        """CREATE TABLE chat_sessions (
            id TEXT PRIMARY KEY,
            owner TEXT NOT NULL COLLATE NOCASE,
            title TEXT NOT NULL,
            created_at TEXT NOT NULL)""",
        """CREATE TABLE chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL REFERENCES chat_sessions(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            tools_used TEXT,
            created_at TEXT NOT NULL)""",
        "CREATE INDEX idx_chat_messages_session ON chat_messages(session_id, id)",
        """CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT,
            subject TEXT NOT NULL,
            recipient TEXT NOT NULL,
            body_markdown TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            created_at TEXT NOT NULL)""",
        """CREATE TABLE containment_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            description TEXT,
            source TEXT NOT NULL CHECK (source IN ('env','arm')),
            url_env TEXT,
            workflow_id TEXT,
            trigger_name TEXT NOT NULL DEFAULT 'When_an_HTTP_request_is_received',
            payload_template TEXT NOT NULL,
            risk_level TEXT NOT NULL DEFAULT 'standard' CHECK (risk_level IN ('standard','high')),
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL)""",
    ]),
    (2, [
        """CREATE TABLE containment_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            kind TEXT NOT NULL CHECK (kind IN ('logicapp','api')),
            category TEXT NOT NULL CHECK (category IN ('ip_block','url_block','device_isolation','advanced')),
            description TEXT,
            url_enc TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'POST',
            headers_enc TEXT,
            body_format TEXT NOT NULL DEFAULT 'json' CHECK (body_format IN ('json','text')),
            body_template TEXT NOT NULL DEFAULT '',
            risk_level TEXT NOT NULL DEFAULT 'standard' CHECK (risk_level IN ('standard','high')),
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL)""",
        """CREATE TABLE hunting_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL COLLATE NOCASE,
            name TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('nl','kql')),
            text TEXT NOT NULL,
            shared INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL)""",
        "CREATE INDEX idx_hunting_owner ON hunting_queries(owner)",
        """INSERT OR IGNORE INTO role_permissions (role_id, permission)
           SELECT id, 'containment.manage_targets' FROM roles WHERE name = 'SOC Manager'""",
        """INSERT OR IGNORE INTO role_permissions (role_id, permission)
           SELECT id, 'hunting.use' FROM roles WHERE name IN ('SOC Manager','L2 Analyst','L1 Analyst')""",
        """INSERT OR IGNORE INTO role_permissions (role_id, permission)
           SELECT id, 'hunting.save' FROM roles WHERE name IN ('SOC Manager','L2 Analyst')""",
    ]),
    (3, [
        """CREATE TABLE containment_targets_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            kind TEXT NOT NULL CHECK (kind IN ('logicapp','api')),
            category TEXT NOT NULL CHECK (category IN ('ip_block','url_block','device_isolation','advanced','enrichment')),
            description TEXT,
            url_enc TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'POST',
            headers_enc TEXT,
            body_format TEXT NOT NULL DEFAULT 'json' CHECK (body_format IN ('json','text')),
            body_template TEXT NOT NULL DEFAULT '',
            risk_level TEXT NOT NULL DEFAULT 'standard' CHECK (risk_level IN ('standard','high')),
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL)""",
        "INSERT INTO containment_targets_new SELECT * FROM containment_targets",
        "DROP TABLE containment_targets",
        "ALTER TABLE containment_targets_new RENAME TO containment_targets",
    ]),
    (4, [
        """CREATE TABLE containment_targets_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE COLLATE NOCASE,
            kind TEXT NOT NULL CHECK (kind IN ('logicapp','api')),
            category TEXT NOT NULL,
            description TEXT,
            url_enc TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'POST',
            headers_enc TEXT,
            body_format TEXT NOT NULL DEFAULT 'json' CHECK (body_format IN ('json','text')),
            body_template TEXT NOT NULL DEFAULT '',
            risk_level TEXT NOT NULL DEFAULT 'standard' CHECK (risk_level IN ('standard','high')),
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL)""",
        "INSERT INTO containment_targets_new SELECT * FROM containment_targets",
        "DROP TABLE containment_targets",
        "ALTER TABLE containment_targets_new RENAME TO containment_targets",
    ]),
    (5, [
        """CREATE TABLE lake_datasets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            table_name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL CHECK (kind IN ('table','document')),
            description TEXT NOT NULL DEFAULT '',
            tags TEXT NOT NULL DEFAULT '',
            source_filename TEXT NOT NULL,
            rows INTEGER NOT NULL DEFAULT 0,
            columns_json TEXT NOT NULL DEFAULT '[]',
            size_bytes INTEGER NOT NULL DEFAULT 0,
            sha256 TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            created_at TEXT NOT NULL)""",
        """INSERT OR IGNORE INTO role_permissions (role_id, permission)
           SELECT r.id, p.perm FROM roles r JOIN (
             SELECT 'lake.view' AS perm UNION SELECT 'lake.upload' UNION SELECT 'lake.delete' UNION SELECT 'lake.ai') p
           WHERE r.name = 'SOC Manager'""",
        """INSERT OR IGNORE INTO role_permissions (role_id, permission)
           SELECT r.id, p.perm FROM roles r JOIN (
             SELECT 'lake.view' AS perm UNION SELECT 'lake.upload' UNION SELECT 'lake.ai') p WHERE r.name = 'L2 Analyst'""",
        """INSERT OR IGNORE INTO role_permissions (role_id, permission)
           SELECT r.id, p.perm FROM roles r JOIN (SELECT 'lake.view' AS perm UNION SELECT 'lake.ai') p WHERE r.name = 'L1 Analyst'""",
        """INSERT OR IGNORE INTO role_permissions (role_id, permission)
           SELECT id, 'lake.view' FROM roles WHERE name = 'Viewer'""",
    ]),
    (6, [
        """CREATE TABLE lake_datasets_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            table_name TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            tags TEXT NOT NULL DEFAULT '',
            source_filename TEXT NOT NULL,
            rows INTEGER NOT NULL DEFAULT 0,
            columns_json TEXT NOT NULL DEFAULT '[]',
            size_bytes INTEGER NOT NULL DEFAULT 0,
            sha256 TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            info_json TEXT NOT NULL DEFAULT '{}')""",
        """INSERT INTO lake_datasets_new (id, name, table_name, kind, description, tags, source_filename, rows, columns_json,
               size_bytes, sha256, uploaded_by, created_at)
           SELECT id, name, table_name, kind, description, tags, source_filename, rows, columns_json,
               size_bytes, sha256, uploaded_by, created_at FROM lake_datasets""",
        "DROP TABLE lake_datasets",
        "ALTER TABLE lake_datasets_new RENAME TO lake_datasets",
    ]),
]


def _seed(con: sqlite3.Connection) -> None:
    now = utcnow()
    # Roles and their initial permissions (existing roles are never overwritten)
    for name, (desc, perms) in constants.DEFAULT_ROLES.items():
        row = con.execute("SELECT id FROM roles WHERE name = ?", (name,)).fetchone()
        if row is None:
            rid = con.execute(
                "INSERT INTO roles (name, description, is_system) VALUES (?, ?, 1)", (name, desc)
            ).lastrowid
            for p in perms:
                con.execute("INSERT OR IGNORE INTO role_permissions VALUES (?, ?)", (rid, p))
        else:
            rid = row["id"]
        if name == constants.SUPER_ADMIN:  # always holds every permission, including future ones
            for p in constants.PERMISSIONS:
                con.execute("INSERT OR IGNORE INTO role_permissions VALUES (?, ?)", (rid, p))

    defaults = dict(constants.DEFAULT_SETTINGS)
    env_overrides = {
        "sentinel.subscription_id": config.SENTINEL_SUBSCRIPTION_ID,
        "sentinel.resource_group": config.SENTINEL_RESOURCE_GROUP,
        "sentinel.workspace_name": config.SENTINEL_WORKSPACE_NAME,
        "sentinel.workspace_id": config.SENTINEL_WORKSPACE_ID,
    }
    for k, v in env_overrides.items():
        if v:
            defaults[k] = v
    for k, v in defaults.items():
        con.execute(
            "INSERT OR IGNORE INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, 'system')",
            (k, v, now),
        )

    con.execute(
        """INSERT OR IGNORE INTO containment_actions
           (key, label, description, source, url_env, trigger_name, payload_template, risk_level, enabled, created_at, updated_at)
           VALUES ('incident_containment', 'Run incident containment playbook',
                   'Calls the incident containment Logic App with the incident ARM id, name, id and entities.',
                   'env', 'LOGICAPP_INCIDENT_URL', 'When_an_HTTP_request_is_received', ?, 'high', 1, ?, ?)""",
        (constants.DEFAULT_PAYLOAD_TEMPLATE, now, now),
    )


def init_db() -> None:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    raw = sqlite3.connect(config.DB_PATH)
    raw.execute("PRAGMA journal_mode=WAL")
    raw.close()
    with connect(write=True) as con:
        con.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        current = con.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()["v"] or 0
        for version, statements in MIGRATIONS:
            if version > current:
                for stmt in statements:
                    con.execute(stmt)
                con.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
        _seed(con)
