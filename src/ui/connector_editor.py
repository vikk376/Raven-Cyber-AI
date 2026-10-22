"""Add, edit and delete a custom connector (Logic App or API) from a dialog, so it can be done inside any Respond panel."""
import streamlit as st

from src.core import constants
from src.services import audit, targets
from src.ui import common

ENRICH_HINT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{{indicator}}"
ENRICH_HINT_HEADERS = "x-apikey: {{env.CONTAINMENT_VT_KEY}}"


@st.dialog("Custom connector", width="large")
def editor(default_category: str, target_id: int | None = None) -> None:
    user = common.current_user()
    if not user.can("containment.manage_targets"):
        st.error("Your roles do not allow managing connectors.")
        return
    cur = targets.get_target(target_id) if target_id else {}
    cur = cur or {}
    sfx = f"{cur.get('id', 'new')}_{default_category}"
    st.caption("URLs and headers are encrypted and never shown again. Keep API keys in `.env` as `CONTAINMENT_NAME=...` "
               "and refer to them as `{{env.CONTAINMENT_NAME}}`.")
    c1, c2, c3 = st.columns(3)
    kind = c1.selectbox("Type", ["logicapp", "api"], index=0 if cur.get("kind", "logicapp") == "logicapp" else 1,
                        format_func=lambda k_: "Logic App" if k_ == "logicapp" else "API", key=f"ce_kind_{sfx}")
    cats = list(constants.TARGET_CATEGORIES)
    category = c2.selectbox("Shows in", cats, index=cats.index(cur.get("category", default_category)),
                            format_func=lambda c: constants.TARGET_CATEGORIES[c][0], key=f"ce_cat_{sfx}")
    risk = c3.selectbox("Impact", ["standard", "high"], index=0 if cur.get("risk_level", "standard") == "standard" else 1,
                        key=f"ce_risk_{sfx}")
    enrich = category == "enrichment"
    with st.form(f"ce_form_{sfx}"):
        name = st.text_input("Name", cur.get("name", ""), placeholder="VirusTotal IP lookup" if enrich else "Block IP on Azure Firewall")
        desc = st.text_input("Description", cur.get("description", ""))
        url = st.text_input("URL" + (" (leave blank to keep the stored URL)" if cur else ""), type="password",
                            placeholder=ENRICH_HINT_URL if enrich else "https://prod-11.northcentralus.logic.azure.com:443/workflows/.../invoke?...sig=...")
        default_method = "GET" if enrich else cur.get("method", "POST")
        method = st.selectbox("HTTP method (API only)", list(targets.METHODS), index=list(targets.METHODS).index(default_method))
        headers = st.text_area("Headers (API only)" + (" (leave blank to keep stored headers)" if cur.get("has_headers") else ""),
                               height=90, placeholder=ENRICH_HINT_HEADERS if enrich else
                               "Authorization: Bearer {{env.CONTAINMENT_API_KEY}}\nContent-Type: application/json")
        if enrich:
            body_default = cur.get("body_template", "")
        else:
            body_default = cur.get("body_template") or (targets.DEFAULT_LOGICAPP_BODY if kind == "logicapp" else targets.DEFAULT_API_BODY)
        body_format = st.radio("Body format", ["json", "text"], horizontal=True, index=0 if cur.get("body_format", "json") == "json" else 1)
        body = st.text_area("Body template (empty for GET lookups)" if enrich else "Body template", body_default, height=160)
        enabled = st.checkbox("Enabled", value=bool(cur.get("enabled", 1)))
        save = st.form_submit_button("Save connector", type="primary")
    with st.expander("Placeholders for the URL (path and query only), headers and body"):
        st.markdown("`{{indicator}}` `{{indicator_type}}` `{{category}}` `{{target_name}}` `{{justification}}` "
                    "`{{prompt}}` `{{timestamp}}` `{{user.email}}` `{{param.name}}` `{{env.CONTAINMENT_NAME}}`\n\n"
                    "In the URL, values are URL-encoded automatically. Only environment variables that start with `CONTAINMENT_` can be used.")
    if save:
        try:
            tid = targets.save_target({"id": cur.get("id"), "name": name, "kind": kind, "category": category,
                                       "description": desc, "url": url, "method": method, "headers": headers,
                                       "body_format": body_format, "body_template": body, "risk_level": risk,
                                       "enabled": enabled}, user.email)
            audit.log(user.email, "containment", "containment.target_saved", name, details={
                "id": tid, "kind": kind, "category": category, "risk": risk, "enabled": enabled,
                "url_changed": bool(url.strip()), "headers_changed": bool(headers.strip())})
            st.rerun()
        except targets.TargetError as exc:
            st.error(str(exc))
    if cur and st.button("Delete this connector", key=f"ce_del_{sfx}"):
        targets.delete_target(cur["id"])
        audit.log(user.email, "containment", "containment.target_deleted", cur["name"])
        st.rerun()
