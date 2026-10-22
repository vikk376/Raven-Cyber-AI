"""Support: the product documentation, readable inside the app."""
import re
from pathlib import Path

import streamlit as st

from src.ui import common, theme

DOCS = Path(__file__).resolve().parents[2] / "docs"
# title, file, needs an admin permission
GUIDES = [
    ("Feature and support guide", "FEATURES.md", False),
    ("Runbook and troubleshooting", "RUNBOOK.md", False),
    ("Admin guide", "ADMIN_GUIDE.md", True),
    ("Security", "SECURITY.md", True),
    ("Architecture", "ARCHITECTURE.md", True),
    ("Adding a tool", "ADDING_A_TOOL.md", True),
]
QUICK = """
| Say in chat | What you get |
|---|---|
| `block IP 203.0.113.45 because of C2 beacons` | IP card, press Continue |
| `block URL https://bad.example because phishing` | URL card |
| `block domain evil.example because malware` | Domain card |
| `isolate LAPTOP-01 because ransomware` | Device isolation card |
| `disable user alice@corp.com because impossible travel` | User disable card |
| `reset password for alice@corp.com because credentials leaked` | Password reset card |
| `comment on incident 123: confirmed phishing, user reset` | Sentinel comment card |
| `contain this incident because ransomware` | Opens the Incident Playbook |
| attach a CSV, PDF, Word or image | Analysis with indicators and containment cards |
"""


def _admin(user) -> bool:
    return user.can_any("admin.users", "admin.roles", "admin.settings", "admin.workspace", "admin.containment")


def _sections(text: str) -> list[tuple[str, str]]:
    parts = re.split(r"(?m)^(?=## )", text)
    return [(p.splitlines()[0].lstrip("# ").strip(), p) for p in parts if p.strip()]


def render() -> None:
    user = common.current_user()
    theme.header("Support", "Every feature, role and setting explained, with fixes for common problems.", icon="📚", crumb="Help")
    guides = [g for g in GUIDES if not g[2] or _admin(user)]
    with st.expander("Quick reference: chat commands", expanded=False):
        st.markdown(QUICK)
    c1, c2 = st.columns([3, 2])
    title = c1.selectbox("Guide", [g[0] for g in guides], key="support_doc")
    query = c2.text_input("Search this guide", key="support_q", placeholder="for example: attach, Continue, embeddings").strip()
    _, fname, _ = next(g for g in guides if g[0] == title)
    path = DOCS / fname
    if not path.exists():
        st.warning("This guide is not included in this installation.")
        return
    text = path.read_text(encoding="utf-8")
    st.download_button("Download this guide (Markdown)", text, file_name=fname, mime="text/markdown", key="support_dl")
    if query:
        hits = [(h, body) for h, body in _sections(text) if query.lower() in body.lower()]
        st.caption(f"{len(hits)} section(s) match '{query}'.")
        for heading, body in hits:
            with st.expander(heading or title, expanded=len(hits) <= 3):
                st.markdown(body)
        return
    with st.container(border=True, key="support_body"):
        st.markdown(text)
