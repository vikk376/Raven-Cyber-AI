"""Admin panel: users, roles, sign-in, Sentinel workspace, containment and system health."""
import os
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

from src.core import config, constants
from src.core.database import connect
from src.services import arm, audit, auth, containment, sessions, settings, users
from src.ui import common, theme


def _a(user, action, target=None, outcome="success", details=None):
    audit.log(user.email, "admin", action, target, outcome, details)


# ------------------------------------------------------------------ users
def _users_tab(me) -> None:
    if not me.can("admin.users"):
        st.info("You do not have permission to manage users.")
        return
    all_users = users.list_users()
    role_names = [r["name"] for r in users.list_roles()]

    pending = [u for u in all_users if u["status"] == "pending"]
    if pending:
        st.subheader(f"Pending access requests ({len(pending)})")
        for u in pending:
            with st.expander(f"{u['email']}  ({u['display_name'] or 'no name'})"):
                roles = st.multiselect("Roles to grant", role_names, default=["Viewer"] if "Viewer" in role_names else [],
                                       key=f"pend_roles_{u['email']}")
                a, b = st.columns(2)
                if a.button("Approve", key=f"approve_{u['email']}"):
                    users.update_user(u["email"], status="active", roles=roles)
                    _a(me, "user.approved", u["email"], details={"roles": roles})
                    st.rerun()
                if b.button("Reject", key=f"reject_{u['email']}"):
                    users.delete_user(u["email"])
                    _a(me, "user.rejected", u["email"])
                    st.rerun()

    st.subheader("Users")
    df = pd.DataFrame([{"Email": u["email"], "Name": u["display_name"], "Status": u["status"],
                        "Roles": ", ".join(u["roles"]), "Last login": u["last_login_at"]} for u in all_users])
    st.dataframe(df, hide_index=True)

    editable = [u for u in all_users if u["status"] != "pending"]
    if editable:
        sel = st.selectbox("Edit user", [u["email"] for u in editable])
        cur = next(u for u in editable if u["email"] == sel)
        with st.form(f"edit_user_{sel}"):
            name = st.text_input("Display name", cur["display_name"] or "")
            status = st.selectbox("Status", ["active", "disabled"], index=0 if cur["status"] == "active" else 1)
            roles = st.multiselect("Roles (permissions are combined)", role_names, default=cur["roles"])
            save, delete = st.columns(2)
            do_save = save.form_submit_button("Save changes")
            do_delete = delete.form_submit_button("Delete user")
        if do_save:
            try:
                users.update_user(sel, status=status, display_name=name, roles=roles)
                if sel != me.email and (status == "disabled" or set(roles) != set(cur["roles"])):
                    sessions.revoke_all_for(sel)  # force the other user to sign in again
                _a(me, "user.updated", sel, details={"status": status, "roles": roles})
                st.success("Saved.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
        if do_delete:
            if sel == me.email:
                st.error("You cannot delete your own account.")
            else:
                try:
                    users.delete_user(sel)
                    sessions.revoke_all_for(sel)
                    auth.drop_cache(sel)
                    _a(me, "user.deleted", sel)
                    st.rerun()
                except ValueError as exc:
                    st.error(str(exc))

    st.subheader("Add user")
    with st.form("add_user", clear_on_submit=True):
        email = st.text_input("Work email (the Microsoft sign-in address)")
        name = st.text_input("Display name")
        roles = st.multiselect("Roles", role_names, key="add_roles")
        if st.form_submit_button("Add user"):
            try:
                users.create_user(email, name, "active", roles, created_by=me.email)
                _a(me, "user.created", email, details={"roles": roles})
                st.success(f"Added {email}.")
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))


# ------------------------------------------------------------------ roles
def _roles_tab(me) -> None:
    if not me.can("admin.roles"):
        st.info("You do not have permission to manage roles.")
        return
    perms = list(constants.PERMISSIONS)
    roles = users.list_roles()
    rp = users.all_role_permissions()
    data = {r["name"]: [(p in rp.get(r["name"], set())) or r["name"] == constants.SUPER_ADMIN for p in perms] for r in roles}
    df = pd.DataFrame(data, index=perms)
    df.insert(0, "Description", [constants.PERMISSIONS[p] for p in perms])
    st.caption("Tick the permissions each role grants. Users with several roles receive the combination. "
               "Super Admin always has everything.")
    edited = st.data_editor(df, disabled=["Description", constants.SUPER_ADMIN], key="role_matrix")
    if st.button("Save permission changes"):
        changed = []
        for r in roles:
            name = r["name"]
            if name == constants.SUPER_ADMIN:
                continue
            new = {p for p in perms if bool(edited.loc[p, name])}
            if new != rp.get(name, set()):
                users.set_role_permissions(name, new)
                changed.append(name)
                _a(me, "role.permissions_changed", name, details={"added": sorted(new - rp.get(name, set())),
                                                                   "removed": sorted(rp.get(name, set()) - new)})
        st.success(f"Updated: {', '.join(changed)}" if changed else "No changes.")
        if changed:
            st.rerun()

    st.subheader("Create role")
    with st.form("create_role", clear_on_submit=True):
        name = st.text_input("Role name")
        desc = st.text_input("Description")
        chosen = st.multiselect("Permissions", perms, format_func=lambda p: f"{p}: {constants.PERMISSIONS[p]}")
        if st.form_submit_button("Create role"):
            try:
                users.create_role(name, desc, set(chosen))
                _a(me, "role.created", name, details={"permissions": chosen})
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))

    custom = [r["name"] for r in roles if not r["is_system"]]
    if custom:
        st.subheader("Delete custom role")
        victim = st.selectbox("Role", custom)
        if st.button("Delete role"):
            try:
                users.delete_role(victim)
                _a(me, "role.deleted", victim)
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))


# ------------------------------------------------------------------ sign-in settings
def _signin_tab(me) -> None:
    if not me.can("admin.settings"):
        st.info("You do not have permission to change sign-in settings.")
        return
    with st.form("signin_settings"):
        title = st.text_input("Login page title", settings.get("login.title"))
        message = st.text_area("Login page message", settings.get("login.message"), height=90)
        domains = st.text_input("Allowed email domains (comma separated, empty allows any)", settings.get("login.allowed_domains"))
        reg_options = ["request", "deny"]
        reg = st.selectbox("Unknown users", reg_options, index=reg_options.index(settings.get("access.self_registration", "request")),
                           format_func=lambda v: {"request": "Create an access request for admin approval",
                                                  "deny": "Deny sign-in completely"}[v])
        timeout = st.number_input("Idle session timeout (minutes)", 5, 480, settings.get_int("session.timeout_minutes", 60))
        if st.form_submit_button("Save sign-in settings"):
            before = settings.get_many(["login.title", "login.message", "login.allowed_domains",
                                        "access.self_registration", "session.timeout_minutes"])
            new = {"login.title": title, "login.message": message, "login.allowed_domains": domains,
                   "access.self_registration": reg, "session.timeout_minutes": str(int(timeout))}
            for k, v in new.items():
                settings.set_value(k, v, me.email)
            _a(me, "settings.signin_changed", details={k: [before[k], v] for k, v in new.items() if before[k] != v})
            st.success("Saved. The login page uses these values immediately.")
    st.subheader("Sessions")
    with connect() as con:
        n = con.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"]
    st.write(f"Active sessions: **{n}**")
    if st.button("Sign out all other users"):
        with connect(write=True) as con:
            con.execute("DELETE FROM sessions WHERE email <> ? COLLATE NOCASE", (me.email,))
        _a(me, "sessions.revoked_all_others")
        st.rerun()


# ------------------------------------------------------------------ sentinel workspace
def _workspace_tab(me) -> None:
    if not me.can("admin.workspace"):
        st.info("You do not have permission to configure the workspace.")
        return
    cur = common.workspace_cfg()
    if cur:
        st.success(f"Current: {cur['workspace_name']} (resource group {cur['resource_group']}, subscription {cur['subscription_id']})")
    else:
        st.warning("No workspace configured yet.")

    st.subheader("Discover from Azure")
    st.caption("Uses your own Azure permissions (Reader on the subscription is enough to list workspaces).")
    if st.button("Load my subscriptions"):
        token, err = auth.acquire(me.email, config.ARM_SCOPE)
        if not token:
            st.error(f"No Azure token: {err}")
        else:
            try:
                st.session_state["ws_subs"] = arm.list_subscriptions(token)
            except arm.AzureError as exc:
                st.error(str(exc))
    subs = st.session_state.get("ws_subs", [])
    if subs:
        sub = st.selectbox("Subscription", subs, format_func=lambda s: f"{s['name']} ({s['id']})")
        if st.button("Find Sentinel workspaces in this subscription"):
            token, err = auth.acquire(me.email, config.ARM_SCOPE)
            if not token:
                st.error(f"No Azure token: {err}")
            else:
                try:
                    st.session_state["ws_list"] = arm.list_workspaces(token, sub["id"])
                    st.session_state["ws_sub"] = sub["id"]
                except arm.AzureError as exc:
                    st.error(str(exc))
    wss = st.session_state.get("ws_list", [])
    if wss:
        ws = st.selectbox("Workspace", wss, format_func=lambda w: f"{w['name']}  ({w['resource_group']}, {w['location']})")
        if st.button("Use this workspace", type="primary"):
            vals = {"sentinel.subscription_id": st.session_state["ws_sub"], "sentinel.resource_group": ws["resource_group"],
                    "sentinel.workspace_name": ws["name"], "sentinel.workspace_id": ws["customer_id"]}
            for k, v in vals.items():
                settings.set_value(k, v, me.email)
            common.load_incidents.clear()
            _a(me, "workspace.configured", ws["name"], details=vals)
            st.success("Saved.")
            st.rerun()

    st.subheader("Or enter manually")
    with st.form("ws_manual"):
        sub = st.text_input("Subscription ID", settings.get("sentinel.subscription_id"))
        rg = st.text_input("Resource group", settings.get("sentinel.resource_group"))
        name = st.text_input("Workspace name", settings.get("sentinel.workspace_name"))
        wid = st.text_input("Workspace ID (optional)", settings.get("sentinel.workspace_id"))
        if st.form_submit_button("Save"):
            vals = {"sentinel.subscription_id": sub.strip(), "sentinel.resource_group": rg.strip(),
                    "sentinel.workspace_name": name.strip(), "sentinel.workspace_id": wid.strip()}
            for k, v in vals.items():
                settings.set_value(k, v, me.email)
            common.load_incidents.clear()
            _a(me, "workspace.configured", name, details=vals)
            st.rerun()


# ------------------------------------------------------------------ containment
def _containment_tab(me) -> None:
    if not me.can("admin.containment"):
        st.info("You do not have permission to manage containment.")
        return
    st.info("Logic App and API targets for IP, URL and device actions are managed in Containment > Manage Targets. "
            "This tab holds the incident playbook action and the safety rules for every containment action.")
    acts = containment.list_actions()
    if acts:
        st.dataframe(pd.DataFrame([{
            "Key": a["key"], "Label": a["label"], "Source": a["source"], "Risk": a["risk_level"],
            "Enabled": bool(a["enabled"]),
            "URL configured": ("yes" if os.environ.get(a["url_env"] or "") else "NO") if a["source"] == "env" else "via Azure",
        } for a in acts]), hide_index=True)

    st.subheader("Add or edit an action")
    options = ["(new action)"] + [a["key"] for a in acts]
    pick = st.selectbox("Action", options)
    cur = containment.get_action(pick) if pick != options[0] else None
    cur = cur or {"key": "", "label": "", "description": "", "source": "env", "url_env": "", "workflow_id": "",
                  "trigger_name": "When_an_HTTP_request_is_received", "risk_level": "standard", "enabled": 1,
                  "payload_template": constants.DEFAULT_PAYLOAD_TEMPLATE}
    with st.form(f"action_form_{pick}"):
        key = st.text_input("Key (lowercase, digits, underscore)", cur["key"], disabled=bool(cur["key"]))
        label = st.text_input("Label", cur["label"])
        desc = st.text_input("Description", cur["description"] or "")
        src = st.selectbox("Where is the Logic App URL?", ["env", "arm"], index=0 if cur["source"] == "env" else 1,
                           format_func=lambda s: {"env": "Environment variable in .env (recommended)",
                                                  "arm": "Fetch from Azure at run time (needs Logic App Contributor)"}[s])
        url_env = st.text_input("Environment variable name (env source)", cur["url_env"] or "", placeholder="LOGICAPP_ISOLATE_URL")
        wf = st.text_input("Logic App resource id (Azure source)", cur["workflow_id"] or "")
        trig = st.text_input("Trigger name (Azure source)", cur["trigger_name"])
        risk_level = st.selectbox("Impact", ["standard", "high"], index=0 if cur["risk_level"] == "standard" else 1,
                                  help="High impact needs the containment.run_high permission and a typed confirmation.")
        enabled = st.checkbox("Enabled", bool(cur["enabled"]))
        tmpl = st.text_area("Payload template (JSON)", cur["payload_template"], height=240)
        st.caption("Placeholders: " + ", ".join("{{" + p + "}}" for p in constants.PLACEHOLDERS))
        c1, c2 = st.columns(2)
        do_save = c1.form_submit_button("Save action")
        do_delete = c2.form_submit_button("Delete action", disabled=not cur["key"])
    if do_save:
        check = containment.validate_template(tmpl)
        if check["unknown"]:
            st.warning("Unknown placeholders will be sent as null or empty: " + ", ".join(check["unknown"]))
        try:
            containment.save_action({"key": cur["key"] or key, "label": label, "description": desc, "source": src,
                                     "url_env": url_env.strip() or None, "workflow_id": wf.strip() or None,
                                     "trigger_name": trig.strip(), "payload_template": tmpl, "risk_level": risk_level,
                                     "enabled": enabled})
            _a(me, "containment.action_saved", cur["key"] or key, details={"risk": risk_level, "enabled": enabled, "source": src})
            st.success("Saved.")
            st.rerun()
        except ValueError as exc:
            st.error(str(exc))
    if do_delete:
        containment.delete_action(cur["key"])
        _a(me, "containment.action_deleted", cur["key"])
        st.rerun()

    st.subheader("Safety rules")
    with st.form("safety"):
        protected = st.text_area("Protected entities (one per line, wildcards allowed, lines starting with # are comments)",
                                 settings.get("containment.protected_entities"), height=140,
                                 help="Break-glass accounts, executives, critical servers. Actions are blocked when any entity matches.",
                                 placeholder="breakglass@corp.com\n*@executives.corp.com\nDC01*")
        rate = st.number_input("Max containment actions per user per hour", 1, 500, settings.get_int("containment.rate_limit_per_hour", 20))
        priv = st.checkbox("Allow private network and plain http targets (lab only)",
                           value=settings.get("containment.allow_private_targets", "false") == "true",
                           help="Off by default. When off, URLs that resolve to internal addresses are refused (SSRF protection).")
        if st.form_submit_button("Save safety rules"):
            settings.set_value("containment.protected_entities", protected, me.email)
            settings.set_value("containment.rate_limit_per_hour", str(int(rate)), me.email)
            settings.set_value("containment.allow_private_targets", "true" if priv else "false", me.email)
            _a(me, "containment.safety_changed", details={"rate": int(rate), "protected_lines": len(protected.splitlines()),
                                                          "allow_private": priv})
            st.success("Saved.")

    with st.expander("Discover Logic Apps in Azure"):
        cfg = common.workspace_cfg()
        sub = cfg["subscription_id"] if cfg else st.text_input("Subscription ID", key="la_sub")
        if sub and st.button("List Logic Apps"):
            token, err = auth.acquire(me.email, config.ARM_SCOPE)
            if not token:
                st.error(err)
            else:
                try:
                    st.session_state["la_list"] = arm.list_logic_apps(token, sub)
                except arm.AzureError as exc:
                    st.error(str(exc))
        if st.session_state.get("la_list"):
            st.dataframe(pd.DataFrame(st.session_state["la_list"]), hide_index=True)
            st.caption("Copy a resource id into an action using the 'Azure' source.")


# ------------------------------------------------------------------ dashboard
def _dashboard_tab(me) -> None:
    import altair as alt
    all_users = users.list_users()
    cols = st.columns(4)
    theme.kpi(cols[0], "Total users", len(all_users))
    theme.kpi(cols[1], "Active users", sum(u["status"] == "active" for u in all_users))
    theme.kpi(cols[2], "Super Admins", sum("Super Admin" in u["roles"] for u in all_users))
    theme.kpi(cols[3], "Pending requests", sum(u["status"] == "pending" for u in all_users))

    left, right = st.columns([3, 2])
    with left:
        st.markdown("##### Activity, last 30 days")
        since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(timespec="seconds")
        rows = audit.query(limit=5000, since=since)
        if rows:
            df = pd.DataFrame(rows)
            df["day"] = pd.to_datetime(df["ts"], utc=True).dt.date
            df["type"] = df["action"].map(lambda a: "Logins" if a == "login" else "Actions")
            agg = df.groupby(["day", "type"]).size().reset_index(name="count")
            st.altair_chart(alt.Chart(agg).mark_line(point=True).encode(
                x=alt.X("day:T", title=None), y=alt.Y("count:Q", title="Events"), color=alt.Color("type:N", scale=alt.Scale(range=theme.PALETTE), title=None),
                tooltip=["day", "type", "count"]), width="stretch")
        else:
            st.caption("No activity yet.")
    with right:
        st.markdown("##### Role distribution")
        counts: dict[str, int] = {}
        for u in all_users:
            for r in u["roles"]:
                counts[r] = counts.get(r, 0) + 1
        if counts:
            rd = pd.DataFrame({"role": list(counts), "users": list(counts.values())})
            st.altair_chart(alt.Chart(rd).mark_arc(innerRadius=55).encode(
                theta="users:Q", color=alt.Color("role:N", scale=alt.Scale(range=theme.PALETTE), title=None),
                tooltip=["role", "users"]), width="stretch")
        else:
            st.caption("No roles assigned.")

    st.markdown("##### Recent admin activities")
    adm = audit.query(panel="admin", limit=10)
    if adm:
        st.dataframe(pd.DataFrame(adm)[["ts", "actor", "action", "target", "outcome"]], hide_index=True)
    else:
        st.caption("None yet.")


# ------------------------------------------------------------------ integrations
def _integrations_tab(me) -> None:
    from src.tools import registry
    counts = registry.summary()
    cols = st.columns(2)
    theme.kpi(cols[0], "Configured", counts["configured"], "tools ready", "✅")
    theme.kpi(cols[1], "Needs setup", counts["missing"], "built-in, not configured", "🛠️")
    rows = []
    for t in registry.all_tools():
        state, detail = t.status()
        rows.append({"Tool": t.name, "Category": t.category, "State": state, "Detail": detail})
    st.dataframe(pd.DataFrame(rows), hide_index=True)
    st.caption("Cards, live tests and the add-a-tool guide are on the Tools page in the sidebar.")


# ------------------------------------------------------------------ system
def _system_tab(me) -> None:
    st.write(f"**{constants.APP_NAME}** v{constants.APP_VERSION}")
    checks = {
        "Azure app (client id and secret)": bool(config.AZURE_CLIENT_ID and config.AZURE_CLIENT_SECRET),
        "Tenant id": bool(config.AZURE_TENANT_ID) and not config.AZURE_TENANT_ID.startswith("PUT-"),
        "Azure OpenAI": bool(config.AZURE_OPENAI_API_KEY and config.AZURE_OPENAI_ENDPOINT),
        "SMTP email": bool(config.SMTP_USER and config.SMTP_PASSWORD and config.EMAIL_TO),
        "LOGICAPP_INCIDENT_URL": bool(os.environ.get("LOGICAPP_INCIDENT_URL")),
        "Sentinel workspace": common.workspace_cfg() is not None,
    }
    st.dataframe(pd.DataFrame({"Check": list(checks), "OK": ["✅" if v else "❌" for v in checks.values()]}), hide_index=True)
    for w in config.warnings():
        st.warning(w)
    with connect() as con:
        stats = {t: con.execute(f"SELECT COUNT(*) AS n FROM {t}").fetchone()["n"]
                 for t in ("users", "roles", "audit_log", "chat_sessions", "chat_messages", "containment_actions", "containment_targets", "hunting_queries", "sessions")}
    st.dataframe(pd.DataFrame({"Table": list(stats), "Rows": list(stats.values())}), hide_index=True)
    st.caption(f"Database: {config.DB_PATH}")
    if st.button("Purge expired sessions"):
        st.success(f"Removed {sessions.purge_expired()} expired session(s).")


def render() -> None:
    me = common.current_user()
    if not me.can_any("admin.users", "admin.roles", "admin.settings", "admin.workspace", "admin.containment"):
        st.error("You do not have permission to use this panel.")
        st.stop()
    theme.header("Admin Dashboard", "Manage users, access, integrations and platform settings.")
    tabs = st.tabs(["Overview", "Users", "Roles and permissions", "Sign-in settings", "Sentinel workspace",
                    "Containment", "Integrations", "System"])
    for tab, fn in zip(tabs, (_dashboard_tab, _users_tab, _roles_tab, _signin_tab, _workspace_tab,
                              _containment_tab, _integrations_tab, _system_tab)):
        with tab:
            fn(me)
