"""Server-side application sessions (survive browser refresh, expire on idle)."""
import secrets
from datetime import datetime, timedelta, timezone

from src.core import security
from src.core.database import connect, utcnow
from src.services import settings

ABSOLUTE_MAX_HOURS = 12
TOUCH_INTERVAL_SECONDS = 30


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def create(email: str) -> str:
    sid = secrets.token_urlsafe(32)
    now = utcnow()
    with connect(write=True) as con:
        con.execute("INSERT INTO sessions (sid_hash, email, created_at, last_seen) VALUES (?, ?, ?, ?)",
                    (security.sha256_hex(sid), email.lower(), now, now))
    return sid


def validate(sid: str | None) -> str | None:
    """Return the session's email if valid; enforce idle and absolute timeouts."""
    if not sid:
        return None
    key = security.sha256_hex(sid)
    with connect() as con:
        row = con.execute("SELECT * FROM sessions WHERE sid_hash = ?", (key,)).fetchone()
    if row is None:
        return None
    now = datetime.now(timezone.utc)
    idle = timedelta(minutes=settings.get_int("session.timeout_minutes", 60))
    if now - _parse(row["last_seen"]) > idle or now - _parse(row["created_at"]) > timedelta(hours=ABSOLUTE_MAX_HOURS):
        revoke(sid)
        return None
    if (now - _parse(row["last_seen"])).total_seconds() > TOUCH_INTERVAL_SECONDS:
        with connect(write=True) as con:
            con.execute("UPDATE sessions SET last_seen = ? WHERE sid_hash = ?", (utcnow(), key))
    return row["email"]


def revoke(sid: str | None) -> None:
    if not sid:
        return
    with connect(write=True) as con:
        con.execute("DELETE FROM sessions WHERE sid_hash = ?", (security.sha256_hex(sid),))


def revoke_all_for(email: str) -> None:
    with connect(write=True) as con:
        con.execute("DELETE FROM sessions WHERE email = ? COLLATE NOCASE", (email,))


def purge_expired() -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=ABSOLUTE_MAX_HOURS)).isoformat(timespec="seconds")
    with connect(write=True) as con:
        return con.execute("DELETE FROM sessions WHERE created_at < ?", (cutoff,)).rowcount
