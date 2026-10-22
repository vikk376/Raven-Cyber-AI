"""A containment request typed in plain language (Home, Chat, Data Lake): review, then one Continue button.

The card shows the indicator, the justification and the connector it will use. When all three are in place the analyst
only presses Continue. "Change details" lets them edit the type, connector, value or justification first.
"""
import streamlit as st

from src.core import constants
from src.services import arm, audit, incident_tools, indicators, targets
from src.ui import common, theme

HELP = ("Try: block IP 203.0.113.45 because of C2 beacons, block URL https://bad.example because of phishing, "
        "isolate LAPTOP-01 because of ransomware, disable user alice@corp.com because of impossible travel.")
ORDER = tuple(constants.CONTAINMENT_CATEGORIES)


def _incident_card(user, action: dict, k: str) -> None:
    with theme.card(f"act_{k}"):
        st.markdown("##### 🤖 Proposed action: Incident Playbook")
        st.caption("The incident playbook needs an incident from your queue. Open it with your justification pre-filled.")
        st.button("Open Incident Playbook", type="primary", key=f"{k}_open", on_click=common.go, args=("incident",))


def _comment_card(user, action: dict, k: str) -> None:
    number = action["incident"]
    with theme.card(f"act_{k}"):
        st.markdown(f"##### 💬 Proposed action: Comment on incident #{number}")
        if not user.can("investigation.comment"):
            st.error("Your roles do not include posting incident comments.")
            return
        cfg = common.workspace_cfg()
        token, err = common.soft_arm_token(user) if cfg else (None, None)
        if not (cfg and token):
            st.warning("Set the Sentinel workspace in Admin and sign in again to get an Azure token." + (f" ({err})" if err else ""))
            return
        try:
            inc = incident_tools.find_incident(token, cfg["arm_id"], number)
        except arm.AzureError as exc:
            st.error(str(exc))
            return
        if not inc:
            st.error(f"Incident #{number} was not found in this workspace (searched the last 365 days).")
            return
        p = inc["properties"]
        st.markdown(f"**Incident:** #{number} {p.get('title', '')}  ·  {p.get('severity', '')}  ·  {p.get('status', '')}")
        st.session_state.setdefault(f"{k}_ct", action.get("text", ""))
        done = st.session_state.get(f"{k}_done")
        text = st.session_state[f"{k}_ct"].strip()
        if text:
            st.markdown("**Comment:**")
            st.markdown("> " + text.replace("\n", "\n> "))
        with st.expander("Change details" if text else "Write the comment", expanded=not text):
            text = st.text_area("Comment (plain text)", key=f"{k}_ct", height=110).strip()
        if st.button("Continue", type="primary", disabled=bool(done) or len(text) < 3, key=f"{k}_run"):
            body = f"{text}\n\nPosted via Raven Cyber AI by {user.email}"
            try:
                arm.add_incident_comment(token, inc["id"], body)
                audit.log(user.email, "investigation", "incident.comment_added", inc["id"], details={"chars": len(text), "source": "chat"})
                res = {"ok": True, "message": f"Comment posted to incident #{number}."}
            except arm.AzureError as exc:
                audit.log(user.email, "investigation", "incident.comment_added", inc["id"], "failed", {"error": str(exc)[:300]})
                res = {"ok": False, "message": str(exc)}
            st.session_state[f"{k}_done"] = res
            st.rerun()  # redraw with Continue disabled so it cannot run twice
        if done:
            (st.success if done["ok"] else st.error)(done["message"])
        elif len(text) < 3:
            st.caption("Write the comment to enable Continue.")


def render(user, action: dict, prefix: str) -> None:
    """action: {category, indicator, reason, prompt, n}. n makes widget keys unique per request."""
    k = f"{prefix}{action['n']}"
    cat = action.get("category")
    if cat == "comment":
        return _comment_card(user, action, k)
    if cat == "incident":
        return _incident_card(user, action, k)
    if not action.get("indicator") or not cat:
        st.info("I can run that, but I need the value to act on. " + HELP)
        return
    with theme.card(f"act_{k}"):
        cat = st.session_state.get(f"{k}_cat", cat)
        label, noun = constants.CONTAINMENT_CATEGORIES[cat]
        st.markdown(f"##### 🤖 Proposed action: {label}")
        if not user.can("containment.view"):
            st.error("Your roles do not include containment.")
            return
        summary = st.container()
        with st.expander("Change details"):
            cat = st.selectbox("Action", ORDER, index=ORDER.index(cat), key=f"{k}_cat",
                               format_func=lambda c: constants.CONTAINMENT_CATEGORIES[c][0])
            label, noun = constants.CONTAINMENT_CATEGORIES[cat]
            items = targets.list_targets(cat, enabled_only=True)

            def allowed(t: dict) -> bool:
                return user.can("containment.run_high" if t["risk_level"] == "high" else "containment.run")

            items = sorted(items, key=lambda t: (not allowed(t), t["risk_level"] == "high", t["name"]))
            hint = (action.get("connector_hint") or "").lower()
            start = next((i for i, t in enumerate(items) if hint and hint in t["name"].lower() and allowed(t)), 0)
            target = st.selectbox("Connector", items, index=start, key=f"{k}_t", format_func=lambda t: (
                f"{'🔒 ' if not allowed(t) else ''}{'⚠️ ' if t['risk_level'] == 'high' else ''}{t['name']}")) if items else None
            st.session_state.setdefault(f"{k}_v", action["indicator"])
            st.session_state.setdefault(f"{k}_w", action.get("reason", ""))
            value = st.text_input(noun, key=f"{k}_v")
            why = st.text_area("Justification (min 10 characters)", key=f"{k}_w", height=80)

        value, why = value.strip(), why.strip()
        with summary:
            st.markdown(f"**{noun}:** `{value or '(empty)'}`")
            if why:
                st.markdown(f"**Justification:** {why}")
            elif not st.session_state.get(f"{k}_done"):
                why = st.text_input("Justification", key=f"{k}_wq", placeholder="Why is this needed? (min 10 characters)").strip()
            if target:
                st.markdown(f"**Connector:** {target['name']}" + ("  ⚠️ high impact" if target["risk_level"] == "high" else ""))
        ok, norm, err = indicators.validate(cat, value) if value else (False, "", "")
        protected = ok and targets.is_protected(norm)
        done = st.session_state.get(f"{k}_done")
        if value and not ok:
            st.error(err)
        if protected:
            st.error(f"{norm} matches a protected entity and will be blocked.")
        if not items:
            st.warning(f"No {label.lower()} connector is set up yet.")
            st.button(f"Open {label}", key=f"{k}_open", on_click=common.go, args=(cat,))
            return
        if not allowed(target):
            st.error("Your roles do not allow this connector.")
        confirm_ok = True
        if target["risk_level"] == "high" and not done:
            confirm_ok = st.text_input("High impact. Type CONFIRM to continue.", key=f"{k}_c").strip() == "CONFIRM"
        ready = allowed(target) and ok and len(why) >= 10 and confirm_ok and not protected and not done
        if st.button("Continue", type="primary", disabled=not ready, key=f"{k}_run"):
            with st.spinner("Sending..."):
                res = targets.run_target(user, target["id"], norm, why, action.get("prompt", ""), {})
            st.session_state[f"{k}_done"] = res
            st.rerun()  # redraw with Continue disabled so it cannot run twice
        if done:
            (st.success if done["ok"] else st.error)(done["message"])
        elif not ready and ok and len(why) < 10:
            st.caption("Add a justification of at least 10 characters to enable Continue.")


def log_proposal(user, action: dict, source: str) -> None:
    audit.log(user.email, "containment", "chat.action_proposed", action.get("category") or "unknown",
              details={"prompt": (action.get("prompt") or "")[:300], "indicator": action.get("indicator", ""), "source": source})
