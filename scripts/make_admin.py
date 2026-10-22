"""Grant Super Admin from the command line.

  python scripts/make_admin.py                      list users
  python scripts/make_admin.py a@x.com [b@y.com]    make each address a Super Admin
                                                    (creates the user if missing)
Run from the project folder with the venv active. Stop nothing; the app can stay running.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.core import constants  # noqa: E402
from src.core.database import connect, init_db, utcnow  # noqa: E402


def main(emails: list[str]) -> None:
    init_db()
    if not emails:
        with connect() as con:
            rows = con.execute("SELECT email, status FROM users ORDER BY id").fetchall()
        for r in rows:
            print(f"{r['email']:50} {r['status']}")
        if not rows:
            print("No users yet. Sign in once, or pass an email to create one.")
        return
    with connect(write=True) as con:
        rid = con.execute("SELECT id FROM roles WHERE name = ?", (constants.SUPER_ADMIN,)).fetchone()["id"]
        for e in (x.strip().lower() for x in emails):
            row = con.execute("SELECT id FROM users WHERE email = ?", (e,)).fetchone()
            if row is None:
                uid = con.execute(
                    "INSERT INTO users (email, display_name, status, created_at, created_by) "
                    "VALUES (?, '', 'active', ?, 'cli')", (e, utcnow())).lastrowid
            else:
                uid = row["id"]
                con.execute("UPDATE users SET status = 'active' WHERE id = ?", (uid,))
            con.execute("INSERT OR IGNORE INTO user_roles VALUES (?, ?)", (uid, rid))
            print(f"Super Admin: {e}")


if __name__ == "__main__":
    main(sys.argv[1:])
