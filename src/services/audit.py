"""Tamper-evident audit log.

Every record stores the SHA-256 hash of the previous record, forming a chain.
Editing or deleting a row breaks the chain, which verify_chain() detects.
"""
import json
import logging
from datetime import datetime, timedelta, timezone

from src.core import security
from src.core.database import connect, utcnow

log_ = logging.getLogger(__name__)
GENESIS = "0" * 64
MAX_DETAILS = 8000


def _digest(prev: str, ts: str, actor: str, panel: str, action: str, target: str, outcome: str, details: str) -> str:
    return security.sha256_hex("|".join([prev, ts, actor, panel, action, target, outcome, details]))


def log(actor: str, panel: str, action: str, target: str | None = None, outcome: str = "success",
        details: dict | None = None, strict: bool = False) -> bool:
    """Append an audit record. Returns False on failure unless strict=True (then raises)."""
    try:
        clean = json.dumps(security.scrub(details or {}), sort_keys=True, default=str)[:MAX_DETAILS]
        ts = utcnow()
        target = target or ""
        with connect(write=True) as con:
            row = con.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = row["hash"] if row else GENESIS
            h = _digest(prev, ts, actor, panel, action, target, outcome, clean)
            con.execute(
                """INSERT INTO audit_log (ts, actor, panel, action, target, outcome, details, prev_hash, hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, actor, panel, action, target, outcome, clean, prev, h),
            )
        return True
    except Exception:  # noqa: BLE001
        log_.exception("Failed to write audit record %s/%s", panel, action)
        if strict:
            raise
        return False


def _where(panel=None, actor=None, action=None, outcome=None, since=None, until=None, text=None):
    clauses, args = [], []
    if panel and panel != "all":
        clauses.append("panel = ?"); args.append(panel)
    if actor and actor != "all":
        clauses.append("actor = ? COLLATE NOCASE"); args.append(actor)
    if action:
        clauses.append("action LIKE ?"); args.append(f"%{action}%")
    if outcome and outcome != "all":
        clauses.append("outcome = ?"); args.append(outcome)
    if since:
        clauses.append("ts >= ?"); args.append(since)
    if until:
        clauses.append("ts <= ?"); args.append(until)
    if text:
        clauses.append("(target LIKE ? OR details LIKE ? OR action LIKE ?)"); args += [f"%{text}%"] * 3
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def query(limit: int = 500, offset: int = 0, **filters) -> list[dict]:
    where, args = _where(**filters)
    with connect() as con:
        rows = con.execute(
            f"SELECT id, ts, actor, panel, action, target, outcome, details FROM audit_log{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            (*args, limit, offset),
        ).fetchall()
    return [dict(r) for r in rows]


def count(**filters) -> int:
    where, args = _where(**filters)
    with connect() as con:
        return con.execute(f"SELECT COUNT(*) AS n FROM audit_log{where}", args).fetchone()["n"]


def counts_by_panel(since: str | None = None) -> dict[str, int]:
    where, args = _where(since=since)
    with connect() as con:
        rows = con.execute(f"SELECT panel, COUNT(*) AS n FROM audit_log{where} GROUP BY panel", args).fetchall()
    return {r["panel"]: r["n"] for r in rows}


def actors() -> list[str]:
    with connect() as con:
        return [r["actor"] for r in con.execute("SELECT DISTINCT actor FROM audit_log ORDER BY actor")]


def count_recent(actor: str, action: str, minutes: int = 60) -> int:
    since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    return count(actor=actor, action=action, since=since)


def verify_chain() -> dict:
    """Recompute every hash. Returns {ok, checked, first_bad_id, reason}."""
    prev = GENESIS
    checked = 0
    with connect() as con:
        for r in con.execute("SELECT * FROM audit_log ORDER BY id"):
            expected = _digest(r["prev_hash"], r["ts"], r["actor"], r["panel"], r["action"],
                               r["target"] or "", r["outcome"], r["details"] or "")
            if r["prev_hash"] != prev:
                return {"ok": False, "checked": checked, "first_bad_id": r["id"],
                        "reason": "Chain link broken (a record was removed or reordered)."}
            if r["hash"] != expected:
                return {"ok": False, "checked": checked, "first_bad_id": r["id"],
                        "reason": "Record content does not match its hash (edited)."}
            prev = r["hash"]
            checked += 1
    return {"ok": True, "checked": checked, "first_bad_id": None, "reason": ""}
