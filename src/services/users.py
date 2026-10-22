"""Users, roles and role permissions."""
import sqlite3

from src.core import constants
from src.core.database import connect, utcnow


def _norm(email: str) -> str:
    return (email or "").strip().lower()


def _roles_by_user(con: sqlite3.Connection) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for r in con.execute(
        "SELECT ur.user_id, r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id ORDER BY r.name"
    ):
        out.setdefault(r["user_id"], []).append(r["name"])
    return out


def list_users() -> list[dict]:
    with connect() as con:
        roles = _roles_by_user(con)
        rows = con.execute("SELECT * FROM users ORDER BY email").fetchall()
    return [{**dict(r), "roles": roles.get(r["id"], [])} for r in rows]


def get_user(email: str) -> dict | None:
    with connect() as con:
        row = con.execute("SELECT * FROM users WHERE email = ?", (_norm(email),)).fetchone()
        if row is None:
            return None
        roles = [r["name"] for r in con.execute(
            "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? ORDER BY r.name",
            (row["id"],),
        )]
    return {**dict(row), "roles": roles}


def _assign_roles(con: sqlite3.Connection, user_id: int, roles: list[str]) -> None:
    con.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
    for name in roles:
        rid = con.execute("SELECT id FROM roles WHERE name = ?", (name,)).fetchone()
        if rid is None:
            raise ValueError(f"Unknown role: {name}")
        con.execute("INSERT OR IGNORE INTO user_roles VALUES (?, ?)", (user_id, rid["id"]))


def _assert_super_admin_remains(con: sqlite3.Connection) -> None:
    n = con.execute(
        """SELECT COUNT(DISTINCT u.id) AS n FROM users u
           JOIN user_roles ur ON ur.user_id = u.id JOIN roles r ON r.id = ur.role_id
           WHERE u.status = 'active' AND r.name = ?""",
        (constants.SUPER_ADMIN,),
    ).fetchone()["n"]
    if n < 1:
        raise ValueError("This change would leave the platform without an active Super Admin.")


def create_user(email: str, display_name: str = "", status: str = "active",
                roles: list[str] | None = None, created_by: str = "system") -> None:
    email = _norm(email)
    if "@" not in email:
        raise ValueError("A valid email address is required.")
    with connect(write=True) as con:
        if con.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
            raise ValueError(f"User already exists: {email}")
        uid = con.execute(
            "INSERT INTO users (email, display_name, status, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
            (email, display_name or "", status, utcnow(), created_by),
        ).lastrowid
        _assign_roles(con, uid, roles or [])


def update_user(email: str, *, status: str | None = None, display_name: str | None = None,
                roles: list[str] | None = None) -> None:
    email = _norm(email)
    with connect(write=True) as con:
        row = con.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if row is None:
            raise ValueError("User not found.")
        if status is not None:
            con.execute("UPDATE users SET status = ? WHERE id = ?", (status, row["id"]))
        if display_name is not None:
            con.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, row["id"]))
        if roles is not None:
            _assign_roles(con, row["id"], roles)
        _assert_super_admin_remains(con)


def delete_user(email: str) -> None:
    with connect(write=True) as con:
        con.execute("DELETE FROM users WHERE email = ?", (_norm(email),))
        _assert_super_admin_remains(con)


def record_login(email: str, display_name: str = "") -> None:
    with connect(write=True) as con:
        con.execute(
            "UPDATE users SET last_login_at = ?, display_name = CASE WHEN COALESCE(display_name,'') = '' THEN ? ELSE display_name END WHERE email = ?",
            (utcnow(), display_name or "", _norm(email)),
        )


# ---- roles -----------------------------------------------------------------
def list_roles() -> list[dict]:
    with connect() as con:
        return [dict(r) for r in con.execute("SELECT id, name, description, is_system FROM roles ORDER BY id")]


def all_role_permissions() -> dict[str, set[str]]:
    with connect() as con:
        out: dict[str, set[str]] = {r["name"]: set() for r in con.execute("SELECT name FROM roles")}
        for r in con.execute(
            "SELECT r.name, rp.permission FROM role_permissions rp JOIN roles r ON r.id = rp.role_id"
        ):
            out[r["name"]].add(r["permission"])
    return out


def create_role(name: str, description: str, permissions: set[str]) -> None:
    name = (name or "").strip()
    if not name:
        raise ValueError("Role name is required.")
    unknown = set(permissions) - set(constants.PERMISSIONS)
    if unknown:
        raise ValueError(f"Unknown permissions: {sorted(unknown)}")
    with connect(write=True) as con:
        if con.execute("SELECT 1 FROM roles WHERE name = ?", (name,)).fetchone():
            raise ValueError("A role with this name already exists.")
        rid = con.execute(
            "INSERT INTO roles (name, description, is_system) VALUES (?, ?, 0)", (name, description or "")
        ).lastrowid
        for p in permissions:
            con.execute("INSERT INTO role_permissions VALUES (?, ?)", (rid, p))


def set_role_permissions(name: str, permissions: set[str]) -> None:
    if name == constants.SUPER_ADMIN:
        raise ValueError("The Super Admin role always has every permission.")
    unknown = set(permissions) - set(constants.PERMISSIONS)
    if unknown:
        raise ValueError(f"Unknown permissions: {sorted(unknown)}")
    with connect(write=True) as con:
        row = con.execute("SELECT id FROM roles WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise ValueError("Role not found.")
        con.execute("DELETE FROM role_permissions WHERE role_id = ?", (row["id"],))
        for p in permissions:
            con.execute("INSERT INTO role_permissions VALUES (?, ?)", (row["id"], p))


def delete_role(name: str) -> None:
    with connect(write=True) as con:
        row = con.execute("SELECT id, is_system FROM roles WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise ValueError("Role not found.")
        if row["is_system"]:
            raise ValueError("Built-in roles cannot be deleted.")
        if con.execute("SELECT 1 FROM user_roles WHERE role_id = ?", (row["id"],)).fetchone():
            raise ValueError("Role is still assigned to users. Remove it from them first.")
        con.execute("DELETE FROM roles WHERE id = ?", (row["id"],))
