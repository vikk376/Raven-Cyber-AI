"""Raven Cyber AI: Streamlit entry point (sign-in gate, RBAC navigation)."""
import streamlit as st

from src.core import config, constants
from src.core.database import init_db
from src.core.logging_setup import setup_logging

from src.ui import theme  # noqa: E402

theme.setup()
setup_logging()
init_db()

from src.services import access, audit, auth, rbac, sessions  # noqa: E402  (after init so the DB exists)
from src.ui import (  # noqa: E402
    admin, audit_view, chat, containment_view, home, hunting_view, investigation_view, lake_view, login,
    support_view, tools_view,
)

missing = config.missing_settings()
if missing:
    st.error("Missing settings in .env: " + ", ".join(missing))
    st.stop()


def _flash(kind: str, text: str) -> None:
    st.session_state["auth_msg"] = (kind, text)


# ---------------------------------------------------------------- OAuth callback
params = st.query_params
if "error" in params:
    _flash("error", f"Microsoft returned: {params.get('error_description', params['error'])}")
    st.query_params.clear()
    st.rerun()

if "code" in params:
    if not auth.consume_state(params.get("state")):
        _flash("error", "Sign-in expired or was already used. Click Sign in again.")
        st.query_params.clear()
        st.rerun()
    outcome = auth.complete_login(params["code"])
    if not outcome.ok:
        _flash("error", f"Sign-in failed: {outcome.error}")
        st.query_params.clear()
        st.rerun()
    result = access.authorize_login(outcome.email, outcome.name)
    if result.ok:
        sid = sessions.create(result.email)
        st.session_state["sid"] = sid
        st.query_params.clear()
        st.query_params["sid"] = sid
    else:
        auth.drop_cache(outcome.email)  # do not keep tokens for people who are not admitted
        _flash("pending" if result.kind == "pending" else "error", result.message)
        st.query_params.clear()
    st.rerun()

# ---------------------------------------------------------------- session gate
sid = st.session_state.get("sid") or st.query_params.get("sid")
email = sessions.validate(sid) if sid else None
if not email:
    st.session_state.pop("sid", None)
    login.render(st.session_state.pop("auth_msg", None))
    st.stop()

user = rbac.load_user(email)
if user is None or user.status != "active":
    sessions.revoke(sid)
    st.session_state.pop("sid", None)
    login.render(("error", "Your access was removed or disabled."))
    st.stop()

st.session_state["sid"] = sid
st.session_state["_user"] = user
if st.query_params.get("sid") != sid:
    st.query_params["sid"] = sid

# ---------------------------------------------------------------- navigation filtered by RBAC
theme.inject()
theme.sidebar_logo()
# (key, permission, function, title, icon, url path, sidebar section)
catalog = [
    ("home", None, home.render, "Home", "🏠", "", "Overview"),
    ("investigation", "investigation.view", investigation_view.render, "Incidents", "🔎", "investigation", "Investigate"),
    ("hunting", "hunting.use", hunting_view.render, "Hunting", "🎯", "hunting", "Investigate"),
    ("chat", "chat.use", chat.render, "Chat Assistant", "💬", "chat", "Investigate"),
    ("containment", "containment.view", containment_view.render, "Containment", "🛡️", "containment", "Respond"),
    ("lake", "lake.view", lake_view.render, "Data Lake", "🌊", "data-lake", "Data"),
    ("tools", None, tools_view.render, "Tools", "🧰", "tools", "Platform"),
    ("audit", "audit.view", audit_view.render, "Audit Logs", "📜", "audit", "Platform"),
]
sections: dict[str, list] = {}
page_map = {}
for key, perm, fn, title, icon, path, section in catalog:
    if perm is None or user.can(perm):
        pg = st.Page(fn, title=title, icon=icon, url_path=path or None, default=(key == "home"))
        sections.setdefault(section, []).append(pg)
        page_map[key] = pg
if user.can_any("admin.users", "admin.roles", "admin.settings", "admin.workspace", "admin.containment"):
    pg = st.Page(admin.render, title="Admin", icon="⚙️", url_path="admin")
    sections.setdefault("Platform", []).append(pg)
    page_map["admin"] = pg
pg = st.Page(support_view.render, title="Support", icon="📚", url_path="support")
sections.setdefault("Help", []).append(pg)  # last section of the sidebar
page_map["support"] = pg
st.session_state["_pages"] = page_map

if len(page_map) <= 3:
    st.warning("Your account is active but has few permissions yet. Ask an administrator to assign a role.")

nav = st.navigation(sections)
with st.sidebar:
    st.markdown(f"**{user.name}**")
    st.caption(user.email.replace("@", "@\u200b"))
    st.caption("Roles: " + (", ".join(user.roles) or "none"))
    if st.button("Sign out"):
        audit.log(user.email, "auth", "logout")
        sessions.revoke(sid)
        auth.drop_cache(user.email)
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.query_params.clear()
        st.rerun()
    st.caption(f"{constants.APP_NAME} v{constants.APP_VERSION}")
nav.run()
