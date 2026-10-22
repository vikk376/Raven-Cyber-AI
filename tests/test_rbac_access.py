import pytest

from src.core import config, constants
from src.services import access, rbac, sessions, settings, users


def test_default_roles_seeded(db):
    names = {r["name"] for r in users.list_roles()}
    assert {"Super Admin", "SOC Manager", "L2 Analyst", "L1 Analyst", "Viewer", "Auditor"} <= names


def test_first_login_becomes_super_admin(db):
    r = access.authorize_login("boss@corp.com", "Boss")
    assert r.ok
    u = rbac.load_user("boss@corp.com")
    assert u.is_super_admin and u.perms == frozenset(constants.PERMISSIONS)


def test_second_user_is_pending_until_approved(db):
    access.authorize_login("boss@corp.com")
    r = access.authorize_login("new@corp.com")
    assert not r.ok and r.kind == "pending"
    users.update_user("new@corp.com", status="active", roles=["L1 Analyst"])
    assert access.authorize_login("new@corp.com").ok


def test_self_registration_deny(db):
    access.authorize_login("boss@corp.com")
    settings.set_value("access.self_registration", "deny")
    r = access.authorize_login("stranger@corp.com")
    assert not r.ok and r.kind == "denied"
    assert users.get_user("stranger@corp.com") is None


def test_domain_allowlist(db):
    settings.set_value("login.allowed_domains", "corp.com")
    assert not access.authorize_login("x@other.com").ok
    assert access.authorize_login("x@corp.com").ok


def test_bootstrap_restricted_to_configured_email(db, monkeypatch):
    monkeypatch.setattr(config, "BOOTSTRAP_ADMIN_EMAIL", "owner@corp.com")
    assert access.authorize_login("intruder@corp.com").kind == "pending"
    assert access.authorize_login("owner@corp.com").ok
    assert rbac.load_user("owner@corp.com").is_super_admin


def test_multiple_roles_union_permissions(db):
    access.authorize_login("boss@corp.com")
    users.create_user("a@corp.com", roles=["L1 Analyst", "Auditor"])
    u = rbac.load_user("a@corp.com")
    assert u.can("investigation.comment") and u.can("audit.view")
    assert not u.can("containment.run") and not u.can("admin.users")


def test_disabled_user_denied(db):
    access.authorize_login("boss@corp.com")
    users.create_user("d@corp.com", roles=["Viewer"])
    users.update_user("d@corp.com", status="disabled")
    assert access.authorize_login("d@corp.com").kind == "denied"


def test_cannot_remove_last_super_admin(db):
    access.authorize_login("boss@corp.com")
    with pytest.raises(ValueError):
        users.update_user("boss@corp.com", status="disabled")
    with pytest.raises(ValueError):
        users.update_user("boss@corp.com", roles=["Viewer"])
    with pytest.raises(ValueError):
        users.delete_user("boss@corp.com")
    assert rbac.load_user("boss@corp.com").is_super_admin  # rolled back


def test_role_permission_edit_and_delete_rules(db):
    access.authorize_login("boss@corp.com")
    users.create_role("Hunter", "Threat hunters", {"chat.use", "dashboard.view"})
    users.create_user("h@corp.com", roles=["Hunter"])
    assert rbac.load_user("h@corp.com").perms == frozenset({"chat.use", "dashboard.view"})
    users.set_role_permissions("Hunter", {"chat.use"})
    assert rbac.load_user("h@corp.com").perms == frozenset({"chat.use"})
    with pytest.raises(ValueError):
        users.delete_role("Hunter")  # still assigned
    with pytest.raises(ValueError):
        users.delete_role("Viewer")  # built in
    with pytest.raises(ValueError):
        users.set_role_permissions("Super Admin", {"chat.use"})


def test_sessions_validate_and_revoke(db):
    sid = sessions.create("a@corp.com")
    assert sessions.validate(sid) == "a@corp.com"
    assert sessions.validate("bogus") is None
    sessions.revoke(sid)
    assert sessions.validate(sid) is None


def test_session_idle_timeout(db):
    from src.core.database import connect
    sid = sessions.create("a@corp.com")
    with connect(write=True) as con:
        con.execute("UPDATE sessions SET last_seen = '2000-01-01T00:00:00+00:00'")
    assert sessions.validate(sid) is None
