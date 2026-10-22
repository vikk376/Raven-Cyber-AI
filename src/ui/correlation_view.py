"""Entity history and correlation tab of the Incidents panel."""
import json

import altair as alt
import pandas as pd
import streamlit as st

from src.services import audit, investigation, targets
from src.ui import theme

SEV_ORDER = ["Informational", "Low", "Medium", "High"]


def rerun_correlation(user, token: str, inv: dict, days: int) -> None:
    with st.spinner(f"Checking entity history for the last {days} days..."):
        investigation.add_correlation(inv["ctx"], token, days)
        inv["risk"] = investigation.compute_risk(inv["ctx"])
    corr = inv["ctx"].get("correlation") or {}
    audit.log(user.email, "investigation", "investigation.correlation", inv["id"], details={
        "days": days, "related": len(corr.get("related", [])), "scanned": corr.get("scanned"), "failed": corr.get("failed")})


def _matrix(corr: dict) -> None:
    rel = corr["related"][:12]
    ents = [e for e in corr["entities"] if e["incidents"]][:12]
    if not rel or not ents:
        return
    cells = [{"Entity": e["entity"], "Incident": f"#{r['number']}", "Shared": 1} for r in rel for e in ents if e["entity"] in r["shared"]]
    if not cells:
        return
    st.altair_chart(alt.Chart(pd.DataFrame(cells)).mark_rect(cornerRadius=4).encode(
        x=alt.X("Incident:N", sort=[f"#{r['number']}" for r in rel], title="Earlier incident"),
        y=alt.Y("Entity:N", sort=[e["entity"] for e in ents], title=None),
        color=alt.value(theme.SKY), tooltip=["Entity", "Incident"]).properties(height=max(120, 28 * len(ents))), width="stretch")


def _timeline(inv: dict, corr: dict) -> None:
    cur = inv["ctx"]["incident"].get("properties", {}) or {}
    rows = [{"created": r["created"], "incident": f"#{r['number']} {r['title'][:40]}", "severity": r["severity"] or "Low",
             "shared": len(r["shared"]), "kind": "Earlier"} for r in corr["related"] if r["created"]]
    if cur.get("createdTimeUtc"):
        rows.append({"created": cur["createdTimeUtc"], "incident": f"#{cur.get('incidentNumber')} (this incident)",
                     "severity": cur.get("severity", "Medium"), "shared": 3, "kind": "This incident"})
    if len(rows) < 2:
        return
    df = pd.DataFrame(rows)
    df["created"] = pd.to_datetime(df["created"], utc=True, errors="coerce")
    st.altair_chart(alt.Chart(df).mark_circle(opacity=.85, stroke="white", strokeWidth=1).encode(
        x=alt.X("created:T", title=None), y=alt.Y("severity:N", sort=SEV_ORDER, title=None),
        size=alt.Size("shared:Q", legend=None, scale=alt.Scale(range=[120, 520])),
        color=alt.Color("kind:N", scale=alt.Scale(domain=["Earlier", "This incident"], range=[theme.BLUE, "#ef4444"]), title=None),
        tooltip=["incident", "severity", "created", "shared"]).properties(height=220), width="stretch")


def _intel(user, corr: dict) -> None:
    theme.section("Threat intelligence lookup")
    tools = targets.list_targets("enrichment", enabled_only=True)
    if not tools:
        st.info("No enrichment tool is registered. Add a threat intelligence API (for example VirusTotal or AbuseIPDB) in "
                "Targets and Tools, category Enrichment, and look up any entity here.")
        return
    options = [e["entity"] for e in corr.get("entities", [])] if corr else []
    c1, c2 = st.columns(2)
    tool = c1.selectbox("Tool", tools, format_func=lambda t: t["name"], key="intel_tool")
    pick = c2.selectbox("Entity", options or ["(type below)"], key="intel_entity")
    value = st.text_input("Indicator", value="" if pick == "(type below)" else pick, key=f"intel_value_{pick}")
    if st.button("Look up", key="intel_run", type="primary", disabled=not value.strip()):
        res = targets.run_enrichment(user, tool["id"], value)
        (st.success if res["ok"] else st.error)(res["message"])
        if res["data"] is not None:
            flat = res["data"] if isinstance(res["data"], dict) else {"result": res["data"]}
            st.json(flat, expanded=False)
        elif res["text"]:
            st.code(res["text"][:2000])


def render(user, token: str, inv: dict) -> None:
    ctx = inv["ctx"]
    corr = ctx.get("correlation")
    c1, c2, c3 = st.columns([1, 1, 3])
    days = c1.selectbox("Look back", [7, 30, 90], index=1, format_func=lambda d: f"{d} days", key="inv_corr_days")
    if c2.button("Correlate" if not corr else "Refresh", key="inv_corr_run", type="primary"):
        rerun_correlation(user, token, inv, days)
        st.rerun()
    c3.caption("Looks for earlier incidents with the same accounts, hosts, IP addresses, URLs, domains and file hashes. "
               "Process and bare file names are ignored because they match too much.")
    if not corr:
        st.info("Correlation has not been run for this investigation. Press Correlate.")
        _intel(user, {})
        return
    for msg in corr.get("errors", []):
        st.warning(msg)

    repeat = sum(1 for e in corr["entities"] if e["incidents"] >= 2)
    tp = sum(1 for e in corr["entities"] if e["true_positive"])
    k = st.columns(4)
    theme.kpi(k[0], "Related incidents", len(corr["related"]), f"last {corr['days']} days", "🔗")
    theme.kpi(k[1], "Repeat entities", repeat, "in 2 or more earlier incidents", "🔁")
    theme.kpi(k[2], "Past true positives", tp, "entities with confirmed history", "⚠️")
    theme.kpi(k[3], "Incidents checked", corr["scanned"], f"{corr['failed']} unreadable", "🔍")

    for flag in corr["flags"]:
        (st.warning if ("TruePositive" in flag or "two or more" in flag) else st.info)(flag)

    theme.section("Entity history")
    if corr["entities"]:
        df = pd.DataFrame([{
            "Entity": e["entity"], "Kind": e["kind"], "Earlier incidents": e["incidents"], "First seen": e["first_seen"][:10],
            "Last seen": e["last_seen"][:10], "True positive": e["true_positive"], "False positive": e["false_positive"],
            "Benign": e["benign"], "Highest severity": e["max_severity"], "Flag": e["flag"],
            "Incidents": ", ".join(f"#{n}" for n in e["incident_numbers"])} for e in corr["entities"]])
        st.dataframe(df, hide_index=True, column_config={
            "Earlier incidents": st.column_config.ProgressColumn("Earlier incidents", min_value=0, max_value=max(5, int(df["Earlier incidents"].max())), format="%d")})

    theme.section("Related incidents")
    if corr["related"]:
        rel = pd.DataFrame([{
            "#": r["number"], "Title": r["title"], "Severity": r["severity"], "Status": r["status"],
            "Classification": r["classification"] or "-", "Created": r["created"][:16].replace("T", " "),
            "Shared entities": ", ".join(r["shared"][:4]), "Match score": r["score"], "Portal": r["url"] or None} for r in corr["related"]])
        st.dataframe(rel, hide_index=True, column_config={
            "Match score": st.column_config.ProgressColumn("Match score", min_value=0, max_value=max(6.0, float(rel["Match score"].max())), format="%.1f"),
            "Portal": st.column_config.LinkColumn("Portal", display_text="Open")})
        left, right = st.columns(2)
        with left:
            st.markdown("**Which entities connect which incidents**")
            _matrix(corr)
        with right:
            st.markdown("**When it happened**")
            _timeline(inv, corr)
        if corr["tactics"]:
            st.caption("Tactics shared with this incident: " + ", ".join(f"{t['tactic']} ({t['incidents']})" for t in corr["tactics"]))
    else:
        st.caption("No related incidents in this window.")
    with st.expander("Raw correlation data"):
        st.code(json.dumps({k_: v for k_, v in corr.items() if k_ != "related"}, indent=2, default=str)[:4000], language="json")
    _intel(user, corr)
