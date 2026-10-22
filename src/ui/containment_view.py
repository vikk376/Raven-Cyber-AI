"""Containment panels: one page each for IP Blocking, URL Blocking, Device Isolation and Advanced Actions,
plus the incident playbook and target management. Targets are Logic Apps or APIs registered by an admin."""
import json
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

from src.core import constants
from src.services import arm, audit, containment, indicators, investigation, targets
from src.ui import common, connector_editor, theme

_PANELS = {
    "ip_block": {"icon": "🧱", "title": "IP Blocking", "emoji": "🚫",
                 "sub": "Block malicious IP addresses and ranges with Logic App or API automation.",
                 "placeholder": "203.0.113.45 or 203.0.113.0/24", "result": "Block and record"},
    "url_block": {"icon": "🔗", "title": "URL Blocking", "emoji": "🚫",
                  "sub": "Block malicious URLs and domains through your proxy, firewall or secure web gateway.",
                  "placeholder": "https://malicious.example/path or malicious.example", "result": "Block and record"},
    "device_isolation": {"icon": "💻", "title": "Device Isolation", "emoji": "🧊",
                         "sub": "Isolate compromised devices from the network through your EDR or Logic App.",
                         "placeholder": "LAPTOP-01", "result": "Isolate and record"},
    "domain_block": {"icon": "🌐", "title": "Domain Blocking", "emoji": "🚫",
                     "sub": "Block a whole domain in your DNS filter, proxy or secure web gateway.",
                     "placeholder": "malicious.example", "result": "Block and record"},
    "user_disable": {"icon": "👤", "title": "User Disable", "emoji": "🔒",
                     "sub": "Disable a compromised account and revoke its sessions through Entra ID, a Logic App or your IAM API.",
                     "placeholder": "alice@corp.com", "result": "Disable and record"},
    "password_reset": {"icon": "🔑", "title": "Password Reset", "emoji": "🔑",
                       "sub": "Force a password reset and sign-out for a user through Entra ID, a Logic App or your IAM API.",
                       "placeholder": "alice@corp.com", "result": "Reset and record"},
    "advanced": {"icon": "🧪", "title": "Custom Action", "emoji": "⚡",
                 "sub": "Custom response actions: disable accounts, revoke sessions, open tickets or anything your API supports.",
                 "placeholder": "user@corp.com, device id or any value your action needs", "result": "Run and record"},
}
ORDER = ("ip_block", "url_block", "domain_block", "device_isolation", "user_disable", "password_reset", "advanced")
PANELS = {k: _PANELS[k] for k in ORDER}


def _detect() -> None:
    found = indicators.parse_prompt(st.session_state.get("ct_prompt", ""))
    if not found["indicator"]:
        st.session_state["ct_detect_msg"] = ("warning", "No IP, URL, domain or device found in that sentence. Type the value below.")
        return
    st.session_state["ct_prefill"] = {"category": found["category"], "indicator": found["indicator"], "reason": found["reason"]}
    st.session_state["ct_type"] = found["category"]
    st.session_state["ct_detect_msg"] = ("success", f"Detected {found['type']} {found['indicator']}.")


def _apply_prefill(cat: str) -> None:
    pre = st.session_state.get("ct_prefill")
    if pre and pre["category"] == cat:
        st.session_state[f"ct_{cat}_ind"] = pre["indicator"]
        if pre.get("reason"):
            st.session_state[f"ct_{cat}_why"] = pre["reason"]
        st.session_state.pop("ct_prefill")


def _prompt_bar() -> None:
    c1, c2 = st.columns([6, 1])
    c1.text_input("Describe the action", key="ct_prompt", label_visibility="collapsed",
                  placeholder="Describe it: block IP 203.0.113.45 because of C2 beacons  |  isolate LAPTOP-01 because of ransomware")
    c2.button("Detect", key="ct_detect", on_click=_detect, width="stretch")
    msg = st.session_state.pop("ct_detect_msg", None)
    if msg:
        {"success": st.success, "warning": st.warning}[msg[0]](msg[1])


def _select(sel_key: str, tid: int) -> None:
    st.session_state[sel_key] = tid


def _connector_cell(user, cat: str, label: str, t: dict | None, can_manage: bool, sel_key: str) -> None:
    if t is None:
        with st.container(border=True, key=f"rvadd_{cat}"):
            st.markdown(theme.add_tile_html("Add custom connector", f"Logic App or API for {label}: name, URL, headers, body."),
                        unsafe_allow_html=True)
            if st.button("Add connector", key=f"ct_{cat}_add", width="stretch"):
                connector_editor.editor(cat)
        return
    selected = st.session_state.get(sel_key) == t["id"]
    kind = "Logic App" if t["kind"] == "logicapp" else "API"
    with st.container(border=True, key=f"rvtile_{'sel_' if selected else ''}{cat}_{t['id']}"):
        st.markdown(theme.tool_card_html(
            "⚙️" if t["kind"] == "logicapp" else "🔌", t["name"], t["host"], t.get("description") or f"{kind} connector for {label.lower()}.",
            "Enabled" if t["enabled"] else "Disabled", "ok" if t["enabled"] else "muted", [kind, t["method"]] if t["kind"] == "api" else [kind],
            bare=True, extra=("High impact", "warn") if t["risk_level"] == "high" else None), unsafe_allow_html=True)
        b1, b2 = st.columns(2)
        if t["enabled"]:
            b1.button("Selected" if selected else "Use", key=f"ct_{cat}_use_{t['id']}", disabled=selected, width="stretch",
                      type="primary" if selected else "secondary", on_click=_select, args=(sel_key, t["id"]))
        if can_manage and b2.button("Edit", key=f"ct_{cat}_edit_{t['id']}", width="stretch"):
            connector_editor.editor(cat, t["id"])


def _stats(rows: list[dict]) -> dict:
    cut = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    recent = [r for r in rows if r["Time"] >= cut]
    done = [r for r in recent if r["Status"] in ("Executed", "Failed")]
    ok = [r for r in done if r["Status"] == "Executed"]
    return {"runs": len(done), "rate": f"{round(100 * len(ok) / len(done))}%" if done else "n/a",
            "blocked": sum(1 for r in recent if r["Status"] == "Blocked"), "last": rows[0]["Time"][5:16].replace("T", " ") if rows else "never"}


def _panel(user, cat: str) -> None:
    meta = PANELS[cat]
    label, noun = constants.CONTAINMENT_CATEGORIES[cat]
    _apply_prefill(cat)
    st.caption(meta["sub"])

    can_manage = user.can("containment.manage_targets")
    all_items = targets.list_targets(cat, enabled_only=not can_manage)
    items = [t for t in all_items if t["enabled"]]
    rows = targets.history(cat, limit=200)
    st_ = _stats(rows)
    k = st.columns(4)
    theme.kpi(k[0], "Connectors ready", len(items), "Logic Apps and APIs", "🔌")
    theme.kpi(k[1], "Actions, 24h", st_["runs"], f"success {st_['rate']}", "⚡")
    theme.kpi(k[2], "Stopped by safety rules", st_["blocked"], "protected, rate limit, permission", "🛡️")
    theme.kpi(k[3], "Last action", st_["last"], "UTC", "🕒")

    theme.section("Connectors")
    sel_key = f"ct_{cat}_sel"
    if st.session_state.get(sel_key) not in [t["id"] for t in items]:
        st.session_state[sel_key] = items[0]["id"] if items else None
    cells = [*all_items, *([None] if can_manage else [])]
    if not cells:
        st.info("No connector is set up for this panel yet. Ask an administrator to add one.")
    for row in range(0, len(cells), 3):
        for col, t in zip(st.columns(3), cells[row:row + 3]):
            with col:
                _connector_cell(user, cat, label, t, can_manage, sel_key)
    if not items:
        return
    target = next(t for t in items if t["id"] == st.session_state[sel_key])

    def allowed(t: dict) -> bool:
        return user.can("containment.run_high" if t["risk_level"] == "high" else "containment.run")

    left, right = st.columns([3, 2], gap="large")
    with left, theme.card(f"{cat}_run"):
        st.markdown(f"##### {meta['emoji']} {label} action")
        st.caption(f"Using **{target['name']}** ({'Logic App' if target['kind'] == 'logicapp' else 'API'}). Pick another connector above.")
        if not allowed(target):
            st.error("Your roles do not allow this target.")
        value = st.text_input(noun, key=f"ct_{cat}_ind", placeholder=meta["placeholder"])
        why = st.text_area("Justification (required, min 10 characters)", key=f"ct_{cat}_why", height=80)
        with st.expander("Extra fields (optional)"):
            st.caption("One key=value per line. Use them in the body or URL as {{param.key}}.")
            extra = st.text_area("Fields", key=f"ct_{cat}_extra", height=70, label_visibility="collapsed")
        params = {}
        for line in (extra or "").splitlines():
            if "=" in line:
                kx, vx = line.split("=", 1)
                if kx.strip():
                    params[kx.strip()] = vx.strip()

        ok, norm, err = indicators.validate(cat, value) if value.strip() else (False, "", "")
        if value.strip() and not ok:
            st.error(err)
        protected = ok and targets.is_protected(norm)
        if protected:
            st.error(f"{norm} matches a protected entity and will be blocked.")
        if ok:
            with st.expander("Preview the request (secrets hidden)"):
                try:
                    full = targets.get_target(target["id"], secrets_included=True)
                    ctx = targets.build_context(user.email, full, norm, "ip" if cat == "ip_block" else "value",
                                                why or "(justification)", st.session_state.get("ct_prompt", ""), params)
                    st.json(targets.preview(full, ctx))
                except Exception as exc:  # noqa: BLE001
                    st.error(f"Cannot build the request: {exc}")

        confirm_ok = True
        if target["risk_level"] == "high":
            confirm_ok = st.text_input("High impact. Type CONFIRM to enable the button.", key=f"ct_{cat}_confirm").strip() == "CONFIRM"
        ready = allowed(target) and ok and len(why.strip()) >= 10 and confirm_ok and not protected
        if st.button(f"Run on {target['name']}", type="primary", disabled=not ready, key=f"ct_{cat}_run"):
            with st.spinner("Sending..."):
                res = targets.run_target(user, target["id"], value, why.strip(), st.session_state.get("ct_prompt", ""), params)
            (st.success if res["ok"] else st.error)(res["message"])
        if not ready:
            st.caption("The button unlocks with permission, a valid value, a justification" + (" and CONFIRM." if target["risk_level"] == "high" else "."))

    with right:
        with theme.card(f"{cat}_flow"):
            st.markdown("##### Automation flow")
            kind_icon = "⚙️" if target["kind"] == "logicapp" else "🔌"
            st.markdown(theme.flow_html([
                ("📥", "Request", "Analyst submits"), ("🛡️", "Validate", "Protected list, rate limit"),
                (kind_icon, target["name"][:22], "Logic App" if target["kind"] == "logicapp" else "API call"),
                (meta["emoji"], meta["result"], "Audit log entry")], active=2), unsafe_allow_html=True)

    theme.section(f"Recent {label} actions")
    if rows:
        st.dataframe(pd.DataFrame(rows[:15]), hide_index=True)
    else:
        st.caption("Nothing yet.")


TYPE_OPTIONS = [*PANELS, "incident"]


def _type_label(c: str) -> str:
    return "📘 Incident Playbook" if c == "incident" else f"{PANELS[c]['icon']} {PANELS[c]['title']}"


def render() -> None:
    user = common.current_user()
    common.require_perm(user, "containment.view")
    theme.header("Containment", "Every response action in one place: block IPs, URLs and domains, isolate devices, disable users, "
                 "reset passwords, run custom actions or an incident playbook.", icon="🛡️", crumb="Respond")
    _prompt_bar()
    st.session_state.setdefault("ct_type", "ip_block")
    st.segmented_control("Action", TYPE_OPTIONS, format_func=_type_label, key="ct_type", label_visibility="collapsed", width="stretch")
    chosen = st.session_state.get("ct_type") or "ip_block"
    if chosen == "incident":
        _incident_playbook(user)
    else:
        _panel(user, chosen)


def _activity() -> None:
    st.subheader("Recent containment activity")
    rows = audit.query(panel="containment", limit=25)
    if not rows:
        st.caption("No activity yet.")
        return
    st.dataframe(pd.DataFrame(rows)[["ts", "actor", "action", "outcome", "target"]], hide_index=True)


def _incident_playbook(user) -> None:
    st.caption("Runs the incident containment Logic App with the incident ARM id, name, id and entities.")
    cfg = common.need_workspace()
    token = common.arm_token(user)

    actions = containment.list_actions(enabled_only=True)
    if not actions:
        st.info("No containment actions are enabled. An administrator can add them in Admin > Containment.")
        return

    def allowed(a: dict) -> bool:
        return user.can("containment.run_high" if a["risk_level"] == "high" else "containment.run")

    label = lambda a: f"{'🔒 ' if not allowed(a) else ''}{'⚠️ ' if a['risk_level'] == 'high' else ''}{a['label']}"  # noqa: E731
    action = st.selectbox("Action", actions, format_func=label)
    if action.get("description"):
        st.caption(action["description"])
    if not allowed(action):
        st.error("Your roles do not allow this action. You can still preview it.")

    st.markdown("#### 1. Incident")
    inc = common.incident_picker(user, cfg, token, key="con", default_statuses=("New", "Active"))
    if not inc:
        _activity()
        return

    st.markdown("#### 2. Entities in scope")
    cache_key = f"con_ents_{inc['id']}"
    if cache_key not in st.session_state:
        try:
            with st.spinner("Loading entities..."):
                st.session_state[cache_key] = arm.get_incident_entities(token, inc["id"])
        except arm.AzureError as exc:
            st.error(str(exc))
            st.session_state[cache_key] = []
    entities = st.session_state[cache_key]
    if not entities:
        st.warning("This incident has no entities. The Logic App will receive an empty entity list.")
    labels = {e.get("id", str(i)): f"{e.get('kind', '')}: {investigation.entity_label(e)}" for i, e in enumerate(entities)}
    chosen = st.multiselect("Entities to include", list(labels), default=list(labels), format_func=lambda k: labels[k],
                            key=f"con_pick_{inc['id']}")
    scoped = [e for i, e in enumerate(entities) if e.get("id", str(i)) in chosen]

    protected = containment.find_protected(scoped)
    if protected:
        st.error("Protected entities are in scope and the action will be blocked: " + ", ".join(protected)
                 + ". Deselect them above if this is intentional.")

    st.markdown("#### 3. Justification and confirmation")
    why = st.text_area("Why is this action needed? (required, min 10 characters)", key="con_why", height=90)
    add_comment = st.checkbox("Also add a comment to the Sentinel incident", value=True,
                              disabled=not user.can("investigation.comment"), key="con_comment")

    with st.expander("Preview payload sent to the Logic App"):
        ctx = containment.build_context(inc, scoped, user.email, why or "(justification)")
        try:
            st.code(json.dumps(containment.render_payload(action["payload_template"], ctx), indent=2, default=str), language="json")
        except Exception as exc:  # noqa: BLE001
            st.error(f"Payload template error: {exc}")

    confirm_ok = True
    if action["risk_level"] == "high":
        typed = st.text_input("High impact action. Type CONFIRM to enable the button.", key="con_confirm")
        confirm_ok = typed.strip() == "CONFIRM"
    ready = allowed(action) and len((why or "").strip()) >= 10 and confirm_ok and not protected

    if st.button("Run containment action", type="primary", disabled=not ready, key="con_run"):
        with st.spinner("Calling the Logic App..."):
            res = containment.run_action(user, action, inc, scoped, why.strip(), token, comment=add_comment)
        (st.success if res["ok"] else st.error)(res["message"])
        if res["comment"]:
            st.info(res["comment"])
        if res["blocked"]:
            st.caption("The attempt was blocked and recorded in the audit log.")
    if not ready:
        st.caption("The run button unlocks when you have permission, a justification, no protected entities"
                   + (" and the typed confirmation." if action["risk_level"] == "high" else "."))
    _activity()
