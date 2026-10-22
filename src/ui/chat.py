"""Chat panel: ask anything about Sentinel, your Data Lake and attached files, and prepare containment in one click."""
import streamlit as st

from src.core import config
from src.services import agent, attachments, audit, chat_store, emailer, indicators
from src.ui import action_card, common, theme

DEFAULT_FILE_PROMPT = ("Analyse the attached file(s): say what they are, list the notable findings and any indicators of "
                       "compromise, and suggest next steps.")


def _pinned(sid: str) -> list[dict]:
    return st.session_state.setdefault("chat_files", {}).setdefault(sid, [])


def _files_panel(user, sid: str) -> None:
    files = _pinned(sid)
    if not files:
        return
    with st.expander(f"📎 Files in this chat ({len(files)})"):
        for i, f in enumerate(files):
            c1, c2 = st.columns([8, 1])
            found = attachments.ioc_summary(f)
            c1.markdown(f"**{f['name']}** · {f['size'] / 1024:.0f} KB · {f['kind']}" + (f" · found {found}" if found else ""))
            if c2.button("✕", key=f"cf_rm_{sid}_{i}", help="Remove from this chat"):
                files.pop(i)
                st.rerun()
        iocs = {k: [v for f in files for v in f["iocs"].get(k, [])] for k in ("ips", "urls", "domains", "emails")}
        total = sum(len(set(v)) for v in iocs.values())
        if total and user.can("containment.view"):
            why = st.text_input("Justification for all", key=f"cf_why_{sid}", placeholder="Why should these be contained? (min 10 characters)")
            if st.button(f"Prepare containment cards for {min(total, 10)} indicators", key=f"cf_prep_{sid}"):
                props = []
                for cat, key in (("ip_block", "ips"), ("url_block", "urls"), ("domain_block", "domains"), ("user_disable", "emails")):
                    for v in dict.fromkeys(iocs[key]):
                        props.append({"category": cat, "indicator": v, "reason": why.strip()})
                _set_proposals(user, sid, props[:10], "attachment", "Prepared from indicators found in attached files.")
                st.rerun()


def _set_proposals(user, sid: str, props: list[dict], source: str, prompt: str) -> None:
    n = st.session_state.get("chat_action_n", 0)
    items = []
    for p in props:
        n += 1
        a = {**p, "prompt": prompt, "n": n}
        items.append(a)
        action_card.log_proposal(user, a, source)
    st.session_state["chat_action_n"] = n
    st.session_state["chat_actions"] = {"sid": sid, "items": items}


def _email_box(user, history) -> None:
    last = next((m for m in reversed(history) if m["role"] == "assistant"), None)
    if not (last and user.can("investigation.email")):
        return
    with st.expander("📧 Email the last answer as a report"):
        subject = st.text_input("Subject", "Microsoft Sentinel Security Report", key="chat_mail_subject")
        to = st.text_input("Recipient", config.EMAIL_TO, key="chat_mail_to")
        if st.button("Send email", key="chat_mail_send"):
            try:
                sent = emailer.send_report(subject, last["content"], to)
                chat_store.log_report(user.email, subject, sent, last["content"], "sent")
                audit.log(user.email, "chat", "email.report_sent", sent, details={"subject": subject})
                st.success(f"Sent to {sent}")
            except Exception as exc:  # noqa: BLE001
                chat_store.log_report(user.email, subject, to, last["content"], "failed", str(exc))
                audit.log(user.email, "chat", "email.report_sent", to, "failed", {"error": str(exc)[:300]})
                st.error(f"Email failed: {exc}")


def _handle(user, sid: str, history: list, text: str, raw_files: list[tuple[str, bytes]]) -> None:
    """Process one submitted message: attachments, direct containment cards, or the assistant."""
    new_atts, errors = attachments.prepare_many(raw_files) if raw_files else ([], [])
    for a in new_atts:
        audit.log(user.email, "chat", "chat.attachment", a["name"], details={"sha256": a["sha256"], "bytes": a["size"], "kind": a["kind"]})
        _pinned(sid).append(a)
    if errors:
        st.session_state["chat_notes"] = errors
    prompt = text.strip() or (DEFAULT_FILE_PROMPT if new_atts else "")
    if not prompt:
        st.rerun()
    shown = prompt + ("\n\n📎 " + ", ".join(a["name"] for a in new_atts) if new_atts else "")

    act = None
    if not new_atts:
        cm = indicators.parse_single_comment(prompt) if user.can("investigation.comment") else None
        if cm:
            act = {"category": "comment", "indicator": f"incident {cm['incident']}", **cm}
        elif user.can("containment.view"):
            act = indicators.parse_single_action(prompt)
    prior = chat_store.get_messages(user.email, sid, limit=12)
    chat_store.add_message(sid, "user", shown)
    if not history:
        chat_store.rename_session(user.email, sid, prompt)
    if act:
        _set_proposals(user, sid, [act], "prompt", prompt)
        chat_store.add_message(sid, "assistant", "I prepared an action from your request. Review the card and press Continue.")
        st.rerun()

    pinned_text = [a for a in _pinned(sid) if a["kind"] == "text" and a not in new_atts]
    proposals: list[dict] | None = [] if user.can("containment.view") or user.can("investigation.comment") else None
    try:
        with st.spinner("Working on it..."):
            answer, tools = agent.ask(user.email, prompt, prior, allow_email=user.can("investigation.email"),
                                      files=[*pinned_text, *new_atts] or None, proposals=proposals,
                                      allow_lake=user.can("lake.ai"))
        outcome = "success"
    except Exception as exc:  # noqa: BLE001
        answer, tools, outcome = f"Error: {exc}", [], "failed"
    if proposals:
        _set_proposals(user, sid, proposals, "assistant", prompt)
        answer += f"\n\nI prepared {len(proposals)} action card(s) below. Nothing runs until you press Continue."
    chat_store.add_message(sid, "assistant", answer, ", ".join(tools) if tools else None)
    audit.log(user.email, "chat", "chat.prompt", sid, outcome, {"prompt": prompt[:300], "tools": tools, "files": len(new_atts)})
    st.rerun()


def render() -> None:
    user = common.current_user()
    common.require_perm(user, "chat.use")
    theme.header("Chat Assistant", "Ask about incidents, your data lake and files. Contain threats in one click.", icon="💬", crumb="Assistant")
    st.caption("Ask about Sentinel, your Data Lake, or attach CSV, Excel, JSON, text, PDF, Word and images for analysis. "
               "Say 'block IP 203.0.113.45 because of C2' and press Continue. Sentinel is queried with your own Microsoft permissions.")

    sid = st.session_state.get("chat_sid")
    if not sid or not chat_store.owns(user.email, sid):
        existing = chat_store.list_sessions(user.email, 1)
        sid = existing[0]["id"] if existing else chat_store.create_session(user.email)
        st.session_state["chat_sid"] = sid

    left, right = st.columns([1, 3])
    with left:
        if st.button("➕ New chat"):
            st.session_state["chat_sid"] = chat_store.create_session(user.email)
            st.rerun()
        for s in chat_store.list_sessions(user.email):
            c1, c2 = st.columns([5, 1])
            if c1.button(("● " if s["id"] == sid else "") + s["title"][:28], key=f"cs_{s['id']}"):
                st.session_state["chat_sid"] = s["id"]
                st.rerun()
            if c2.button("🗑", key=f"cd_{s['id']}"):
                chat_store.delete_session(user.email, s["id"])
                st.session_state.pop("chat_sid", None)
                st.session_state.get("chat_files", {}).pop(s["id"], None)
                st.rerun()

    history = chat_store.get_messages(user.email, sid)
    with right:
        for note in st.session_state.pop("chat_notes", []):
            st.warning(note)
        for m in history:
            with st.chat_message(m["role"]):
                st.markdown(m["content"])
                if m.get("tools_used"):
                    st.caption("Tools: " + m["tools_used"])

        acts = st.session_state.get("chat_actions")
        if acts and acts.get("sid") == sid:
            for a in acts["items"]:
                action_card.render(user, a, "chat_act")

        _files_panel(user, sid)
        _email_box(user, history)

        with st.expander("Sentinel MCP tools"):
            if st.button("Load tool list", key="chat_tools"):
                try:
                    for name, desc in agent.list_mcp_tools(user.email):
                        st.markdown(f"**{name}**  \n{desc}")
                except Exception as exc:  # noqa: BLE001
                    st.error(str(exc))

    value = st.chat_input("Ask a question, attach files, or say: block IP 203.0.113.45 because of C2 beacons",
                          accept_file="multiple", file_type=attachments.FILE_TYPES)
    text, raw = "", []
    if value:
        text = getattr(value, "text", None) or (value if isinstance(value, str) else "")
        raw = [(f.name, f.getvalue()) for f in (getattr(value, "files", None) or [])]
    pending = st.session_state.pop("pending_prompt", None)
    pending_files = st.session_state.pop("pending_files", [])
    if pending or pending_files:
        text, raw = text or pending or "", [*raw, *pending_files]
    if text or raw:
        _handle(user, sid, history, text, raw)
