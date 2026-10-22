"""Shared Streamlit helpers for all panels."""
import html
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

from src.core import config
from src.services import arm, auth, risk, settings
from src.services.rbac import UserCtx

SEVERITY_COLORS = {"Informational": "#78909c", "Low": "#2e7d32", "Medium": "#f9a825", "High": "#ef6c00"}


def current_user() -> UserCtx:
    return st.session_state["_user"]


def require_perm(user: UserCtx, permission: str) -> None:
    if not user.can(permission):
        st.error("You do not have permission to use this panel.")
        st.stop()


def badge(text: str, color: str) -> str:
    return (f'<span style="background:{html.escape(color)};color:#fff;padding:3px 11px;border-radius:12px;'
            f'font-weight:600;font-size:0.85rem;white-space:nowrap">{html.escape(text)}</span>')


def risk_header(inc: dict, result: risk.RiskResult) -> str:
    p = inc.get("properties", {}) or {}
    return f"""
<div style="border-left:8px solid {result.color};padding:14px 18px;background:rgba(127,127,127,.09);border-radius:8px">
  <div style="font-size:.85rem;opacity:.75">Incident #{html.escape(str(p.get('incidentNumber', '?')))}
     &middot; {html.escape(str(p.get('severity', '')))} &middot; {html.escape(str(p.get('status', '')))}</div>
  <div style="font-size:1.35rem;font-weight:700;margin:2px 0 8px">{html.escape(str(p.get('title', '')))}</div>
  <span style="font-size:2.4rem;font-weight:800;color:{result.color}">{result.score:.1f}</span>
  <span style="font-size:1.1rem;opacity:.7"> / 10</span>&nbsp;&nbsp;{badge(result.band.upper(), result.color)}
  {'<span style="font-size:.8rem;opacity:.7">&nbsp; estimated (entities not loaded)</span>' if result.estimated else ''}
</div>"""


def workspace_cfg() -> dict | None:
    sub = settings.get("sentinel.subscription_id")
    rg = settings.get("sentinel.resource_group")
    ws = settings.get("sentinel.workspace_name")
    if not (sub and rg and ws):
        return None
    return {"subscription_id": sub, "resource_group": rg, "workspace_name": ws,
            "workspace_id": settings.get("sentinel.workspace_id"),
            "arm_id": arm.workspace_arm_id(sub, rg, ws)}


def need_workspace() -> dict:
    cfg = workspace_cfg()
    if not cfg:
        st.info("The Sentinel workspace is not configured yet. An administrator can set it in "
                "Admin > Sentinel workspace (it can discover subscriptions and workspaces automatically).")
        st.stop()
    return cfg


def soft_arm_token(user: UserCtx) -> tuple[str | None, str | None]:
    """Like arm_token but never stops the page (used by Home)."""
    return auth.acquire(user.email, config.ARM_SCOPE)


def arm_token(user: UserCtx) -> str:
    token, err = auth.acquire(user.email, config.ARM_SCOPE)
    if not token:
        st.error("Could not get an Azure Resource Manager token. Sign out and sign in again. "
                 "If it keeps failing, an admin must grant consent for 'Azure Service Management / user_impersonation'.")
        if err:
            st.caption(f"Details: {err}")
        st.stop()
    return token


@st.cache_data(ttl=120, show_spinner=False)
def load_incidents(user_key: str, workspace_arm: str, since_iso: str, statuses: tuple, severities: tuple,
                   _token: str) -> list[dict]:
    """Cached per user and filter. The token is excluded from the cache key."""
    return arm.list_incidents(_token, workspace_arm, since_iso=since_iso, statuses=statuses, severities=severities)


def since_iso(days: int) -> str:
    """Rounded to the hour so the cache key is stable."""
    t = (datetime.now(timezone.utc) - timedelta(days=days)).replace(minute=0, second=0, microsecond=0)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def incident_picker(user: UserCtx, cfg: dict, token: str, key: str, default_statuses=("New", "Active")) -> dict | None:
    """Filterable incident list. Returns the selected raw Sentinel incident or None."""
    from src.services import metrics

    c1, c2, c3, c4 = st.columns([1, 1.4, 1.4, 0.8], vertical_alignment="bottom")
    days = c1.selectbox("Created in", [1, 7, 30, 90], index=1, format_func=lambda d: f"Last {d} day(s)", key=f"{key}_days")
    statuses = c2.multiselect("Status", ["New", "Active", "Closed"], default=list(default_statuses), key=f"{key}_st")
    sevs = c3.multiselect("Severity", ["High", "Medium", "Low", "Informational"], default=[], key=f"{key}_sev")
    if c4.button("Refresh", key=f"{key}_refresh", width="stretch"):
        load_incidents.clear()
    try:
        items = load_incidents(user.email, cfg["arm_id"], since_iso(days), tuple(statuses), tuple(sevs), token)
    except arm.AzureError as exc:
        st.error(str(exc))
        return None
    if not items:
        st.info("No incidents match these filters.")
        return None

    df = metrics.build_frame(items)
    search = st.text_input("Search title or number", key=f"{key}_q")
    if search:
        mask = df["title"].str.contains(search, case=False, na=False) | df["number"].astype(str).str.contains(search)
        df = df[mask]
        items = [i for i in items if i.get("id") in set(df["id"])]
    if df.empty:
        st.info("Nothing matches the search.")
        return None

    show = df.assign(risk_band=df["band"].map(lambda b: f"{risk.BAND_EMOJI.get(b, '')} {b}"))[
        ["number", "title", "severity", "status", "risk", "risk_band", "created", "owner", "alerts"]]
    st.dataframe(show, hide_index=True)
    by_id = {i["id"]: i for i in items}
    default_id = st.session_state.get("selected_incident")
    ids = list(df["id"])
    index = ids.index(default_id) if default_id in ids else 0
    label = lambda i: (f"#{by_id[i]['properties'].get('incidentNumber')} | {by_id[i]['properties'].get('severity')} | "  # noqa: E731
                       f"{by_id[i]['properties'].get('status')} | {str(by_id[i]['properties'].get('title', ''))[:90]}")
    chosen = st.selectbox("Select incident", ids, index=index, format_func=label, key=f"{key}_sel")
    st.session_state["selected_incident"] = chosen
    return by_id.get(chosen)


def frame_from_rows(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows) if rows else pd.DataFrame()


_CONTAINMENT_TYPES = ("ip_block", "url_block", "domain_block", "device_isolation", "user_disable", "password_reset", "advanced", "incident")


def go(key: str) -> None:
    """Switch page by catalog key. The old per-action keys open Containment with that action preselected."""
    pages = st.session_state.get("_pages", {})
    if key in _CONTAINMENT_TYPES or key == "playbook":
        st.session_state["ct_type"] = "incident" if key == "playbook" else key
        key = "containment"
    page = pages.get(key)
    if page is not None:
        st.switch_page(page)
