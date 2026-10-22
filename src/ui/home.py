"""Home: the Cyber AI hub. Assistant prompt, quick actions, connected tools, live overview."""
import altair as alt
import pandas as pd
import streamlit as st

from src.services import arm, attachments, audit, indicators, metrics
from src.tools import registry
from src.ui import action_card, common, theme

# key, icon, title, text, permission, page key
ACTIONS = [
    ("investigation", "🔎", "Investigate incidents", "Risk score out of 10, entity history and correlation", "investigation.view", "investigation"),
    ("hunting", "🎯", "Hunt threats", "Natural language or KQL across your data", "hunting.use", "hunting"),
    ("contain", "🛡️", "Contain a threat", "Block IPs, URLs, domains, isolate devices, reset passwords", "containment.view", "containment"),
    ("lake", "🌊", "Data Lake", "Upload data and ask the AI about it", "lake.view", "lake"),
    ("chat", "💬", "Ask the assistant", "Questions about your security data", "chat.use", "chat"),
]




def _ask() -> None:
    q = (st.session_state.get("home_q") or "").strip()
    gen = st.session_state.get("home_files_gen", 0)
    files = st.session_state.get(f"home_files_{gen}") or []
    if not q and not files:
        return
    st.session_state["home_q"] = ""
    user = common.current_user()
    act = None
    if q and not files:
        cm = indicators.parse_single_comment(q) if user.can("investigation.comment") else None
        if cm:
            act = {"category": "comment", "indicator": f"incident {cm['incident']}", **cm}
        elif user.can("containment.view"):
            act = indicators.parse_single_action(q)
    if act:  # one containment request is handled right here: review the card and press Continue
        n = st.session_state.get("home_action_n", 0) + 1
        st.session_state["home_action_n"] = n
        st.session_state["home_action"] = {**act, "prompt": q, "n": n}
        action_card.log_proposal(user, st.session_state["home_action"], "home")
        return
    st.session_state["pending_prompt"] = q
    st.session_state["pending_files"] = [(f.name, f.getvalue()) for f in files]
    st.session_state["home_files_gen"] = gen + 1
    common.go("chat")


@st.fragment(run_every="30s")
def _activity() -> None:
    rows = audit.query(limit=8)
    if rows:
        st.dataframe(pd.DataFrame(rows)[["ts", "actor", "panel", "action", "outcome"]], hide_index=True)
    else:
        st.caption("No activity yet.")


def _overview(user) -> None:
    cfg = common.workspace_cfg()
    if not (user.can("dashboard.view") and cfg):
        st.caption("Set the Sentinel workspace in Admin to see live numbers here." if not cfg else "Your role does not include the dashboard.")
        return
    token, err = common.soft_arm_token(user)
    items = []
    if token:
        try:
            items = common.load_incidents(user.email, cfg["arm_id"], common.since_iso(30), (), (), token)
        except arm.AzureError as exc:
            st.error(str(exc))
    else:
        st.warning("Live numbers need an Azure token. Sign out and in again, and ask an admin to grant consent for "
                   "'Azure Service Management / user_impersonation'." + (f" ({err})" if err else ""))
    df = metrics.build_frame(items)
    k = metrics.kpis(df)
    cols = st.columns(4)
    theme.kpi(cols[0], "Total incidents", k["total"], "last 30 days", "📊")
    theme.kpi(cols[1], "Open", k["open"], f"{k['open_high']} high severity", "🚨")
    theme.kpi(cols[2], "Unassigned open", k["unassigned_open"], "need an owner", "👤")
    theme.kpi(cols[3], "Avg open risk", f"{k['avg_open_risk']} / 10" if k["avg_open_risk"] is not None else "n/a", "estimated", "🔥")
    if df.empty:
        return
    left, right = st.columns([2, 3])
    with left:
        sev = metrics.severity_counts(df)
        st.altair_chart(alt.Chart(sev).mark_arc(innerRadius=58).encode(
            theta="count:Q", color=alt.Color("severity:N", scale=alt.Scale(domain=list(theme.SEVERITY), range=list(theme.SEVERITY.values())), title=None),
            tooltip=["severity", "count"]).properties(title="Incidents by severity", height=230), width="stretch")
    with right:
        trend = metrics.daily_trend(df)
        if not trend.empty:
            long = trend.melt("date", var_name="series", value_name="incidents")
            st.altair_chart(alt.Chart(long).mark_area(opacity=.35, line=True).encode(
                x=alt.X("date:T", title=None), y=alt.Y("incidents:Q", title=None),
                color=alt.Color("series:N", scale=alt.Scale(range=theme.PALETTE[:2]), title=None),
                tooltip=["date", "series", "incidents"]).properties(title="Created vs closed", height=230), width="stretch")


def render() -> None:
    user = common.current_user()
    with st.container(key="rvhero"):
        st.markdown('<div class="rv-hero-k">Raven Cyber AI</div><div class="rv-hero-t">Your AI Security Operations Assistant</div>'
                    '<div class="rv-hero-s">Investigate. Respond. Automate. One place for every security tool you connect.</div>',
                    unsafe_allow_html=True)
        if user.can("chat.use"):
            c1, c2, c3 = st.columns([8, 1.3, 1])
            c1.text_input("Ask Raven", key="home_q", label_visibility="collapsed", on_change=_ask,
                          placeholder="Ask a question, block an IP with a reason, or say: comment on incident 123: confirmed phishing")
            with c2.popover("📎 Attach", width="stretch"):
                st.file_uploader("Files to analyse", accept_multiple_files=True, type=attachments.FILE_TYPES,
                                 key=f"home_files_{st.session_state.get('home_files_gen', 0)}",
                                 help="CSV, Excel, JSON, text, PDF, Word and images. Up to 5 files, 10 MB each.")
            c3.button("Ask", type="primary", key="home_ask", on_click=_ask, width="stretch")

    act = st.session_state.get("home_action")
    if act:
        action_card.render(user, act, "home_act")
        if st.button("Dismiss", key="home_act_dismiss"):
            st.session_state.pop("home_action")
            st.rerun()

    visible = [a for a in ACTIONS if user.can(a[4])]
    if visible:
        theme.section("Quick actions")
        for start in range(0, len(visible), 5):
            cols = st.columns(5)
            for col, (key, icon, title, text, _perm, page) in zip(cols, visible[start:start + 5]):
                with col, st.container(border=True, key=f"rvtile_{key}"):
                    st.markdown(theme.tile_html(icon, title, text), unsafe_allow_html=True)
                    st.button("Open", key=f"home_go_{key}", on_click=common.go, args=(page,), width="stretch")

    theme.section("Connected tools")
    tools = [t for t in registry.all_tools() if t.status()[0] == "configured"]
    if tools:
        for row in range(0, len(tools), 4):
            for col, t in zip(st.columns(4), tools[row:row + 4]):
                with col, st.container(border=True, key=f"rvtile_tool_{t.key}"):
                    st.markdown(theme.tool_card_html(t.icon, t.name, t.vendor, t.description, "Configured", "ok",
                                                     [c.capitalize() for c in t.capabilities][:3], bare=True), unsafe_allow_html=True)
    else:
        st.info("No tools are configured yet.")
    st.button("See all tools", key="home_tools", on_click=common.go, args=("tools",))

    theme.section("Security overview (last 30 days)")
    _overview(user)

    if user.can("audit.view"):
        theme.section("Recent platform activity")
        _activity()
