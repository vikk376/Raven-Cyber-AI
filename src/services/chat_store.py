"""Per-user chat history and sent-report log."""
import uuid

from src.core.database import connect, utcnow


def create_session(owner: str, title: str = "New chat") -> str:
    sid = uuid.uuid4().hex
    with connect(write=True) as con:
        con.execute("INSERT INTO chat_sessions (id, owner, title, created_at) VALUES (?, ?, ?, ?)",
                    (sid, owner.lower(), title, utcnow()))
    return sid


def owns(owner: str, session_id: str) -> bool:
    with connect() as con:
        return con.execute("SELECT 1 FROM chat_sessions WHERE id = ? AND owner = ?",
                           (session_id, owner.lower())).fetchone() is not None


def list_sessions(owner: str, limit: int = 40) -> list[dict]:
    with connect() as con:
        rows = con.execute("SELECT id, title, created_at FROM chat_sessions WHERE owner = ? ORDER BY created_at DESC LIMIT ?",
                           (owner.lower(), limit)).fetchall()
    return [dict(r) for r in rows]


def rename_session(owner: str, session_id: str, title: str) -> None:
    with connect(write=True) as con:
        con.execute("UPDATE chat_sessions SET title = ? WHERE id = ? AND owner = ?", (title[:60], session_id, owner.lower()))


def delete_session(owner: str, session_id: str) -> None:
    with connect(write=True) as con:
        con.execute("DELETE FROM chat_sessions WHERE id = ? AND owner = ?", (session_id, owner.lower()))


def add_message(session_id: str, role: str, content: str, tools_used: str | None = None) -> None:
    with connect(write=True) as con:
        con.execute("INSERT INTO chat_messages (session_id, role, content, tools_used, created_at) VALUES (?, ?, ?, ?, ?)",
                    (session_id, role, content, tools_used, utcnow()))


def get_messages(owner: str, session_id: str, limit: int | None = None) -> list[dict]:
    if not owns(owner, session_id):
        return []
    with connect() as con:
        rows = con.execute("SELECT role, content, tools_used, created_at FROM chat_messages WHERE session_id = ? ORDER BY id",
                           (session_id,)).fetchall()
    msgs = [dict(r) for r in rows]
    return msgs[-limit:] if limit else msgs


def search_messages(owner: str, query: str, limit: int = 8) -> list[dict]:
    with connect() as con:
        rows = con.execute(
            """SELECT m.role, m.content, m.created_at, s.title FROM chat_messages m
               JOIN chat_sessions s ON s.id = m.session_id
               WHERE s.owner = ? AND m.content LIKE ? ORDER BY m.id DESC LIMIT ?""",
            (owner.lower(), f"%{query}%", limit)).fetchall()
    return [dict(r) for r in rows]


def log_report(owner: str, subject: str, recipient: str, body_markdown: str, status: str, error: str | None = None) -> None:
    with connect(write=True) as con:
        con.execute(
            "INSERT INTO reports (owner, subject, recipient, body_markdown, status, error, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (owner.lower(), subject, recipient, body_markdown, status, error, utcnow()))


def list_reports(owner: str | None = None, limit: int = 20) -> list[dict]:
    with connect() as con:
        if owner:
            rows = con.execute("SELECT id, subject, recipient, status, error, created_at FROM reports WHERE owner = ? ORDER BY id DESC LIMIT ?",
                               (owner.lower(), limit)).fetchall()
        else:
            rows = con.execute("SELECT id, subject, recipient, status, error, created_at FROM reports ORDER BY id DESC LIMIT ?",
                               (limit,)).fetchall()
    return [dict(r) for r in rows]
