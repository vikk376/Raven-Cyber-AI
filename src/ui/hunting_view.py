"""Threat hunting: natural language or KQL, run through the Sentinel MCP agent with the user's own permissions."""
import pandas as pd
import streamlit as st

from src.services import agent, audit, hunting
from src.ui import common, theme


def _run(user, kind: str, text: str, state_key: str) -> None:
    try:
        prompt = hunting.build_kql_prompt(text) if kind == "kql" else hunting.build_nl_prompt(text)
    except hunting.HuntError as exc:
        st.error(str(exc))
        return
    try:
        with st.spinner("Hunting in Sentinel..."):
            answer, tools = agent.ask(user.email, prompt, [], allow_email=False)
        outcome = "success"
    except Exception as exc:  # noqa: BLE001
        answer, tools, outcome = f"Error: {exc}", [], "failed"
    st.session_state[state_key] = {"answer": answer, "tools": tools, "text": text, "kind": kind}
    audit.log(user.email, "hunting", f"hunting.{kind}", None, outcome, {"query": text[:500], "tools": tools})


def _show(state_key: str) -> None:
    res = st.session_state.get(state_key)
    if not res:
        return
    st.markdown("##### Results")
    st.markdown(res["answer"])
    if res["tools"]:
        st.caption("Tools: " + ", ".join(res["tools"]))
    st.download_button("Download as Markdown", res["answer"], file_name="hunt_results.md", key=f"{state_key}_dl")


def _save_box(user, kind: str, text: str, key: str) -> None:
    if not user.can("hunting.save"):
        return
    with st.expander("Save this query"):
        name = st.text_input("Name", key=f"{key}_name")
        shared = st.checkbox("Share with all hunters", key=f"{key}_shared")
        if st.button("Save", key=f"{key}_save"):
            try:
                hunting.save_query(user.email, name, kind, text, shared)
                audit.log(user.email, "hunting", "hunting.saved", name, details={"kind": kind, "shared": shared})
                st.success("Saved.")
            except hunting.HuntError as exc:
                st.error(str(exc))


def render() -> None:
    user = common.current_user()
    common.require_perm(user, "hunting.use")
    theme.header("Threat Hunting", "Search, hunt and analyze threats using natural language or KQL.")
    st.caption("Queries run through the Sentinel MCP server with your own Microsoft permissions. "
               "Only read queries are allowed. Every run is recorded in the audit log.")

    tab_nl, tab_kql, tab_saved, tab_pb = st.tabs(["Natural Language", "KQL Editor", "Saved Queries", "Hunting Playbooks"])

    with tab_nl:
        q = st.text_area("Describe what you want to search for", key="hunt_nl", height=100,
                         placeholder="e.g. show all failed login attempts from a suspicious country in the last 7 days")
        if st.button("Run hunt", type="primary", key="hunt_nl_run"):
            _run(user, "nl", q, "hunt_nl_res")
        _save_box(user, "nl", q, "hunt_nl_sv")
        _show("hunt_nl_res")

    with tab_kql:
        k = st.text_area("KQL query", key="hunt_kql", height=220, placeholder="SigninLogs\n| where TimeGenerated > ago(24h)\n| take 10")
        if st.button("Run query", type="primary", key="hunt_kql_run"):
            _run(user, "kql", k, "hunt_kql_res")
        _save_box(user, "kql", k, "hunt_kql_sv")
        _show("hunt_kql_res")

    with tab_saved:
        rows = hunting.list_queries(user.email)
        if not rows:
            st.caption("No saved queries yet.")
        else:
            st.dataframe(pd.DataFrame([{"Name": r["name"], "Type": r["kind"].upper(), "Owner": r["owner"],
                                        "Shared": bool(r["shared"]), "Saved": r["created_at"]} for r in rows]), hide_index=True)
            pick = st.selectbox("Open a saved query", rows, format_func=lambda r: f"{r['name']} ({r['kind'].upper()})", key="hunt_pick")
            st.code(pick["text"], language="kql" if pick["kind"] == "kql" else "text")
            c1, c2 = st.columns(2)
            if c1.button("Run it", key="hunt_pick_run", type="primary"):
                _run(user, pick["kind"], pick["text"], "hunt_saved_res")
            mine = pick["owner"].lower() == user.email.lower()
            if (mine or user.is_super_admin) and c2.button("Delete", key="hunt_pick_del"):
                hunting.delete_query(user.email, pick["id"], is_admin=user.is_super_admin)
                st.rerun()
            _show("hunt_saved_res")

    with tab_pb:
        st.caption("Starter hunts. Check table names and connectors in your workspace before relying on a result.")
        for i, pb in enumerate(hunting.PLAYBOOKS):
            with st.expander(f"{pb['name']}  ({pb['kind'].upper()})"):
                st.write(pb["why"])
                st.code(pb["text"], language="kql" if pb["kind"] == "kql" else "text")
                if st.button("Run this hunt", key=f"hunt_pb_{i}"):
                    _run(user, pb["kind"], pb["text"], "hunt_pb_res")
        _show("hunt_pb_res")
