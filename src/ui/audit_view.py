"""Audit panel: panel-wise and user-wise activity with integrity verification."""
from datetime import date, datetime, time, timezone

import pandas as pd
import streamlit as st

from src.core import constants
from src.services import audit
from src.ui import common, theme


def render() -> None:
    user = common.current_user()
    common.require_perm(user, "audit.view")
    theme.header("Audit Logs", "Panel-wise and user-wise activity with integrity verification.")

    counts = audit.counts_by_panel()
    cols = st.columns(len(constants.PANELS))
    for col, panel in zip(cols, constants.PANELS):
        col.metric(panel.capitalize(), counts.get(panel, 0))

    panel = st.radio("Panel", ["all", *constants.PANELS], horizontal=True, format_func=str.capitalize)
    c1, c2, c3, c4 = st.columns(4)
    actor = c1.selectbox("User", ["all", *audit.actors()])
    outcome = c2.selectbox("Outcome", ["all", "success", "failed", "denied", "pending"])
    start = c3.date_input("From", value=date.today().replace(day=1))
    end = c4.date_input("To", value=date.today())
    c5, c6 = st.columns([2, 1])
    text = c5.text_input("Search action, target or details")
    limit = c6.selectbox("Rows", [200, 500, 1000, 5000], index=1)

    since = datetime.combine(start, time.min, tzinfo=timezone.utc).isoformat(timespec="seconds")
    until = datetime.combine(end, time.max, tzinfo=timezone.utc).isoformat(timespec="seconds")
    rows = audit.query(limit=limit, panel=panel, actor=actor, outcome=outcome, since=since, until=until, text=text or None)
    st.caption(f"{len(rows)} record(s) shown.")
    df = pd.DataFrame(rows, columns=["id", "ts", "actor", "panel", "action", "target", "outcome", "details"])
    st.dataframe(df, hide_index=True)

    left, right = st.columns(2)
    with left:
        if user.can("audit.export"):
            st.download_button("Download CSV", df.to_csv(index=False), file_name="audit_log.csv", mime="text/csv")
    with right:
        if user.can("audit.verify"):
            if st.button("Verify log integrity"):
                res = audit.verify_chain()
                if res["ok"]:
                    st.success(f"Chain intact: {res['checked']} record(s) verified.")
                else:
                    st.error(f"Integrity problem at record #{res['first_bad_id']}: {res['reason']}")
                audit.log(user.email, "audit", "audit.verify", outcome="success" if res["ok"] else "failed",
                          details={"checked": res["checked"], "first_bad_id": res["first_bad_id"]})
