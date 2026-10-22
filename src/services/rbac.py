"""Role based access control: resolve a user's effective permissions."""
from dataclasses import dataclass

from src.core import constants
from src.core.database import connect


class PermissionDenied(Exception):
    pass


@dataclass(frozen=True)
class UserCtx:
    email: str
    name: str
    status: str
    roles: tuple[str, ...]
    perms: frozenset[str]

    def can(self, permission: str) -> bool:
        return permission in self.perms

    def can_any(self, *permissions: str) -> bool:
        return any(p in self.perms for p in permissions)

    @property
    def is_super_admin(self) -> bool:
        return constants.SUPER_ADMIN in self.roles


def load_user(email: str) -> UserCtx | None:
    """Load the user with the union of permissions of all assigned roles."""
    with connect() as con:
        row = con.execute("SELECT * FROM users WHERE email = ?", ((email or "").strip().lower(),)).fetchone()
        if row is None:
            return None
        roles = [r["name"] for r in con.execute(
            "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id WHERE ur.user_id = ? ORDER BY r.name",
            (row["id"],),
        )]
        perms = {r["permission"] for r in con.execute(
            """SELECT DISTINCT rp.permission FROM user_roles ur
               JOIN role_permissions rp ON rp.role_id = ur.role_id WHERE ur.user_id = ?""",
            (row["id"],),
        )}
    if constants.SUPER_ADMIN in roles:
        perms = set(constants.PERMISSIONS)
    return UserCtx(
        email=row["email"], name=row["display_name"] or row["email"], status=row["status"],
        roles=tuple(roles), perms=frozenset(perms),
    )


def require(user: UserCtx, permission: str) -> None:
    if not user.can(permission):
        raise PermissionDenied(f"Missing permission: {permission}")
