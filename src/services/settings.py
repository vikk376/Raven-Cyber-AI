"""Key/value platform settings stored in the database."""
import re

from src.core import constants
from src.core.database import connect, utcnow


def get(key: str, default: str = "") -> str:
    with connect() as con:
        row = con.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is not None:
        return row["value"]
    return constants.DEFAULT_SETTINGS.get(key, default)


def get_int(key: str, default: int) -> int:
    try:
        return int(get(key, str(default)))
    except ValueError:
        return default


def get_list(key: str) -> list[str]:
    """Split a comma or newline separated setting into clean, non-empty items."""
    raw = get(key, "")
    return [p.strip() for p in re.split(r"[,\n]", raw) if p.strip() and not p.strip().startswith("#")]


def set_value(key: str, value: str, actor: str = "system") -> None:
    with connect(write=True) as con:
        con.execute(
            """INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value,
               updated_at = excluded.updated_at, updated_by = excluded.updated_by""",
            (key, str(value), utcnow(), actor),
        )


def get_many(keys: list[str]) -> dict[str, str]:
    return {k: get(k) for k in keys}
