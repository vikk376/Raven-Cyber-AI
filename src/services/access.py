"""Decide whether a Microsoft-authenticated person may enter the platform."""
from dataclasses import dataclass

from src.core import config, constants
from src.core.database import connect, utcnow
from src.services import audit, settings, users


@dataclass
class LoginResult:
    ok: bool
    kind: str  # success | pending | denied
    message: str
    email: str


def authorize_login(email: str, name: str = "") -> LoginResult:
    email = (email or "").strip().lower()
    allowed = [d.lower().lstrip("@") for d in settings.get_list("login.allowed_domains")]
    domain = email.split("@")[-1] if "@" in email else ""
    if allowed and domain not in allowed:
        audit.log(email, "auth", "login.denied", outcome="denied", details={"reason": "domain_not_allowed"})
        return LoginResult(False, "denied", "Your email domain is not allowed to use this platform.", email)

    created_pending = bootstrapped = False
    with connect(write=True) as con:
        row = con.execute("SELECT id, status FROM users WHERE email = ?", (email,)).fetchone()
        total = con.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        admins = con.execute(
            """SELECT COUNT(DISTINCT u.id) AS n FROM users u JOIN user_roles ur ON ur.user_id = u.id
               JOIN roles r ON r.id = ur.role_id WHERE u.status = 'active' AND r.name = ?""",
            (constants.SUPER_ADMIN,),
        ).fetchone()["n"]
        # Bootstrap: the configured owner may always claim Super Admin while none exists.
        # Without a configured owner, only the very first person to sign in can.
        can_bootstrap = admins == 0 and (
            config.BOOTSTRAP_ADMIN_EMAIL == email if config.BOOTSTRAP_ADMIN_EMAIL else total == 0 and row is None)
        if can_bootstrap:
            if row is None:
                uid = con.execute(
                    "INSERT INTO users (email, display_name, status, created_at, created_by) VALUES (?, ?, 'active', ?, 'bootstrap')",
                    (email, name, utcnow()),
                ).lastrowid
            else:
                uid = row["id"]
                con.execute("UPDATE users SET status = 'active' WHERE id = ?", (uid,))
            rid = con.execute("SELECT id FROM roles WHERE name = ?", (constants.SUPER_ADMIN,)).fetchone()["id"]
            con.execute("INSERT OR IGNORE INTO user_roles VALUES (?, ?)", (uid, rid))
            bootstrapped = True
            status = "active"
        elif row is None:
            if settings.get("access.self_registration", "request") == "request":
                con.execute(
                    "INSERT INTO users (email, display_name, status, created_at, created_by) VALUES (?, ?, 'pending', ?, 'self')",
                    (email, name, utcnow()),
                )
                created_pending = True
                status = "pending"
            else:
                status = "unknown"
        else:
            status = row["status"]

    if bootstrapped:
        audit.log(email, "auth", "bootstrap.super_admin", outcome="success",
                  details={"note": "First sign-in became Super Admin"})
    if created_pending:
        audit.log(email, "auth", "access.requested", outcome="pending")
    if status == "active":
        users.record_login(email, name)
        audit.log(email, "auth", "login", outcome="success")
        return LoginResult(True, "success", "Signed in.", email)
    if status == "pending":
        return LoginResult(False, "pending", f"Your access request is waiting for administrator approval. Signed in as: {email}", email)
    audit.log(email, "auth", "login.denied", outcome="denied", details={"status": status})
    if status == "disabled":
        return LoginResult(False, "denied", "Your account is disabled. Contact an administrator.", email)
    return LoginResult(False, "denied", "You are not authorized. Ask an administrator to add your account.", email)
