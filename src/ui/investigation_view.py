"""Investigation portal: evidence, colour-coded risk score out of 10, comment, email, export."""
import pandas as pd
import streamlit as st

from src.core import config
from src.services import agent, arm, audit, chat_store, emailer, investigation, risk, settings
from src.ui import common, correlation_view, theme


def _run(user, token, inc: dict, use_ai: bool, corr_days: int | None = None) -> None:
    with st.spinner("Collecting incident, alerts and entities from Sentinel..."):
        ctx = investigation.collect(token, inc["id"])
    if corr_days and ctx.get("entities"):
        with st.spinner(f"Checking entity history for the last {corr_days} days..."):
            try:
                investigation.add_correlation(ctx, token, corr_days)
            except Exception as exc:  # noqa: BLE001
                ctx["errors"]["correlation"] = str(exc)[:200]
    result = investigation.compute_risk(ctx)
    ai_text, ai_error = None, None
    if use_ai:
        with st.spinner("Writing the AI analysis..."):
            try:
                ai_text = investigation.ai_analysis(ctx, result)
            except Exception as exc:  # noqa: BLE001
                ai_error = str(exc)[:300]
    st.session_state["inv"] = {"id": inc["id"], "ctx": ctx, "risk": result, "ai": ai_text,
                               "ai_error": ai_error, "enrich": None}
    audit.log(user.email, "investigation", "investigation.run", inc["id"], details={
        "number": inc["properties"].get("incidentNumber"), "score": result.score, "band": result.band,
        "ai": bool(ai_text), "errors": list(ctx["errors"]),
        "related": len((ctx.get("correlation") or {}).get("related", []))})


def _breakdown(result: risk.RiskResult) -> None:
    df = pd.DataFrame(result.components).rename(columns={"name": "Component", "points": "Points", "max": "Max", "detail": "Why"})
    st.dataframe(df, hide_index=True, column_config={
        "Points": st.column_config.ProgressColumn("Points", min_value=0, max_value=4.0, format="%.2f"),
    })
    if result.modifier:
        st.caption(result.modifier)
    st.caption("Score bands: 0 to 3.9 Low (green), 4 to 6.9 Medium (amber), 7 to 8.9 High (orange), 9 to 10 Critical (red). "
               "The score is calculated from incident evidence, not by the AI.")


def _actions(user, token, inv: dict) -> None:
    ctx, result, inc_id = inv["ctx"], inv["risk"], inv["id"]
    p = ctx["incident"].get("properties", {})
    md = investigation.build_report(ctx, result, inv.get("ai"), inv.get("enrich"), user.email)

    st.subheader("Actions")
    a, b, c = st.columns(3)
    with a:
        if user.can("investigation.comment"):
            with st.expander("📝 Comment on Sentinel incident", expanded=False):
                text = st.text_area("Comment (plain text)", investigation.comment_text(ctx, result, user.email, inv.get("ai")),
                                    height=260, key="inv_comment_text")
                if st.button("Post comment to incident", key="inv_comment_btn"):
                    try:
                        arm.add_incident_comment(token, inc_id, text)
                        audit.log(user.email, "investigation", "incident.comment_added", inc_id, details={"chars": len(text)})
                        st.success("Comment added to the incident in Sentinel.")
                    except arm.AzureError as exc:
                        audit.log(user.email, "investigation", "incident.comment_added", inc_id, "failed", {"error": str(exc)[:300]})
                        st.error(str(exc))
        else:
            st.caption("Commenting is not enabled for your roles.")
    with b:
        if user.can("investigation.email"):
            with st.expander("📧 Email report"):
                subject = st.text_input("Subject", f"[Sentinel] Incident #{p.get('incidentNumber')} {p.get('title', '')[:60]} - Risk {result.label}",
                                        key="inv_mail_subject")
                to = st.text_input("Recipient", settings.get("email.default_recipient") or config.EMAIL_TO, key="inv_mail_to")
                if st.button("Send report", key="inv_mail_btn"):
                    try:
                        sent = emailer.send_report(subject, md, to, badge=(result.label, result.color))
                        chat_store.log_report(user.email, subject, sent, md, "sent")
                        audit.log(user.email, "investigation", "email.report_sent", inc_id, details={"to": sent})
                        st.success(f"Report sent to {sent}")
                    except Exception as exc:  # noqa: BLE001
                        chat_store.log_report(user.email, subject, to, md, "failed", str(exc))
                        audit.log(user.email, "investigation", "email.report_sent", inc_id, "failed", {"error": str(exc)[:300]})
                        st.error(f"Email failed: {exc}")
        else:
            st.caption("Emailing is not enabled for your roles.")
    with c:
        with st.expander("⬇️ Export"):
            st.download_button("Download HTML", emailer.render_html(f"Incident #{p.get('incidentNumber')}", md, (result.label, result.color)),
                               file_name=f"incident_{p.get('incidentNumber')}.html", mime="text/html")
            st.download_button("Download Markdown", md, file_name=f"incident_{p.get('incidentNumber')}.md", mime="text/markdown")
        if user.can("containment.view"):
            st.caption("To contain, open the Containment panel. This incident stays selected.")


def _show(user, token, inv: dict) -> None:
    ctx, result = inv["ctx"], inv["risk"]
    st.markdown(common.risk_header(ctx["incident"], result), unsafe_allow_html=True)
    for section, msg in ctx["errors"].items():
        st.warning(f"Could not load {section}: {msg}")
    if inv.get("ai_error"):
        st.warning(f"AI analysis unavailable: {inv['ai_error']}")

    t_risk, t_hist, t_ent, t_alert, t_ai, t_mcp, t_com, t_rep = st.tabs(
        ["Risk breakdown", "Entity history", "Entities", "Alerts and timeline", "AI analysis", "Log enrichment (MCP)", "Comments", "Report"])
    with t_hist:
        correlation_view.render(user, token, inv)
    with t_risk:
        _breakdown(result)
        p = ctx["incident"].get("properties", {})
        st.markdown(f"**Description:** {p.get('description') or 'None'}")
    with t_ent:
        ents = ctx.get("entities") or []
        if ents:
            rows = [{"Kind": s["kind"], "Entity": s["name"],
                     "Details": "; ".join(f"{k}={v}" for k, v in s["details"].items())}
                    for s in map(investigation.summarize_entity, ents)]
            st.dataframe(pd.DataFrame(rows), hide_index=True)
        else:
            st.info("No entities for this incident.")
    with t_alert:
        tl = investigation.timeline(ctx)
        if tl:
            st.dataframe(pd.DataFrame(tl), hide_index=True)
        else:
            st.info("No alerts found.")
    with t_ai:
        if inv.get("ai"):
            st.markdown(inv["ai"])
        else:
            st.info("Run the investigation with 'Include AI analysis' ticked to generate this section.")
    with t_mcp:
        st.caption("Asks the Sentinel MCP assistant to pull related log evidence for the entities. Can take a minute.")
        if st.button("Run log enrichment", key="inv_enrich"):
            try:
                with st.spinner("Querying Sentinel logs through MCP..."):
                    text, tools = agent.ask(user.email, investigation.enrichment_prompt(ctx), [], allow_email=False)
                inv["enrich"] = text
                audit.log(user.email, "investigation", "investigation.enrichment", inv["id"], details={"tools": tools})
            except Exception as exc:  # noqa: BLE001
                audit.log(user.email, "investigation", "investigation.enrichment", inv["id"], "failed", {"error": str(exc)[:300]})
                st.error(str(exc))
        if inv.get("enrich"):
            st.markdown(inv["enrich"])
    with t_com:
        comments = ctx.get("comments") or []
        if comments:
            for cm in comments:
                cp = cm.get("properties", {})
                st.markdown(f"**{(cp.get('author') or {}).get('userPrincipalName') or (cp.get('author') or {}).get('name') or 'Unknown'}** "
                            f"· {cp.get('createdTimeUtc', '')}")
                st.text(cp.get("message", ""))
        else:
            st.info("No comments yet.")
    with t_rep:
        st.markdown(investigation.build_report(ctx, result, inv.get("ai"), inv.get("enrich"), user.email))
    _actions(user, token, inv)


def render() -> None:
    user = common.current_user()
    common.require_perm(user, "investigation.view")
    theme.header("Incidents", "Full investigation with a risk score out of 10, Sentinel comment, email and containment.")
    cfg = common.need_workspace()
    token = common.arm_token(user)

    inc = common.incident_picker(user, cfg, token, key="inv")
    if inc:
        c1, c2, c3, c4 = st.columns([1, 2, 2, 1])
        use_ai = c2.checkbox("Include AI analysis (adds about 10 to 30 seconds)", value=True, key="inv_ai")
        use_corr = c3.checkbox("Correlate entity history", value=True, key="inv_corr")
        days = c4.selectbox("Window", [7, 30, 90], index=1, format_func=lambda d: f"{d} d", key="inv_corr_window",
                            label_visibility="collapsed")
        if c1.button("Investigate", type="primary", key="inv_run"):
            try:
                _run(user, token, inc, use_ai, days if use_corr else None)
            except arm.AzureError as exc:
                st.error(str(exc))
                audit.log(user.email, "investigation", "investigation.run", inc.get("id"), "failed", {"error": str(exc)[:300]})

    inv = st.session_state.get("inv")
    if inv:
        st.divider()
        _show(user, token, inv)
