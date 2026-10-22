"""Data Lake: upload structured and JSON data from your device, explore it with SQL, and ask the AI about it."""
import pandas as pd
import streamlit as st

from src.services import audit, lake, lake_agent
from src.ui import action_card, common, theme

SUGGESTIONS = ["Summarize every dataset and document in two lines each",
               "Which columns have missing values?",
               "Show the top 10 most frequent values in the main text column",
               "Find anything unusual or suspicious in this data"]


def _mb(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    return f"{n / 1024 / 1024:.1f} MB" if n >= 1024 * 1024 else f"{n / 1024:.0f} KB"


@st.dialog("Delete dataset")
def _confirm_delete(ds: dict) -> None:
    user = common.current_user()
    st.warning(f"Delete **{ds['name']}** and its stored file? This cannot be undone.")
    c1, c2 = st.columns(2)
    if c1.button("Delete", type="primary", key=f"lake_del_ok_{ds['id']}", width="stretch"):
        lake.delete(ds["id"])
        audit.log(user.email, "lake", "lake.deleted", ds["name"], details={"id": ds["id"], "rows": ds["rows"]})
        st.session_state.pop("lake_sel", None)
        st.rerun()
    if c2.button("Cancel", key=f"lake_del_no_{ds['id']}", width="stretch"):
        st.rerun()


def _card(d: dict) -> str:
    desc = d["description"] or d["source_filename"]
    chips = d["tag_list"][:3] or [_mb(d["size_bytes"])]
    if d["kind"] == "table":
        return theme.tool_card_html("📊", d["name"], d["source_filename"], desc, "Table", "info", chips, bare=True,
                                    extra=(f"{d['rows']:,} rows, {len(d['columns'])} cols", "muted"))
    if d["kind"] == "text":
        fmt = d["info"].get("format", "txt")
        icon = {"pdf": "📕", "docx": "📘"}.get(fmt, "📄")
        size = f"{d['info']['pages']} pages, " if d["info"].get("pages") else ""
        return theme.tool_card_html(icon, d["name"], d["source_filename"], desc, fmt.upper() + " (RAG)", "ok", chips, bare=True,
                                    extra=(f"{size}{d['rows']:,} passages", "muted"))
    return theme.tool_card_html("🧾", d["name"], d["source_filename"], desc, "JSON document", "warn", chips, bare=True,
                                extra=(_mb(d["size_bytes"]), "muted"))


def _upload_tab(user) -> None:
    if not user.can("lake.upload"):
        st.info("Your roles do not allow uploads.")
        return
    st.markdown("Upload files from your device. **Tables** (CSV, TSV, Excel, JSON arrays, JSONL) become SQL-queryable. "
                "**PDF, Word, text and Markdown** files are split into passages and indexed for search (RAG). "
                "Other **JSON documents** are stored whole and read by the AI.")
    files = st.file_uploader("Choose files", type=[e.lstrip(".") for e in lake.ALLOWED_EXT], accept_multiple_files=True,
                             key=f"lake_files_{st.session_state.get('lake_up_n', 0)}",
                             help=f"Up to {lake.MAX_BYTES // 1024 // 1024} MB per file. Excel files create one dataset per sheet.")
    c1, c2 = st.columns(2)
    desc = c1.text_input("Description (optional)", key="lake_desc", placeholder="Entra sign-in export, October")
    tags = c2.text_input("Tags (optional, comma separated)", key="lake_tags", placeholder="identity, sign-ins")
    if st.button("Add to the lake", type="primary", disabled=not files, key="lake_add"):
        msgs = []
        for f in files:
            try:
                made = lake.ingest(user.email, f.name, f.getvalue(), description=desc, tags=tags)
            except lake.LakeError as exc:
                msgs.append(("error", f"{f.name}: {exc}"))
                audit.log(user.email, "lake", "lake.uploaded", f.name, "failed", {"error": str(exc)[:200]})
                continue
            for ds in made:
                audit.log(user.email, "lake", "lake.uploaded", ds["name"], details={
                    "file": f.name, "kind": ds["kind"], "rows": ds["rows"], "bytes": ds["size_bytes"], "sha256": ds["sha256"][:16]})
                msgs.append(("success", f"Added **{ds['name']}** ({ds['rows']:,} rows)" if ds["kind"] == "table"
                             else f"Added JSON document **{ds['name']}**"))
        st.session_state["lake_msgs"] = msgs
        st.session_state["lake_up_n"] = st.session_state.get("lake_up_n", 0) + 1
        st.rerun()


def _datasets_tab(user) -> None:
    items = lake.list_datasets()
    if not items:
        st.info("The lake is empty. Open the Upload tab and add your first file.")
        return
    q = st.text_input("Filter by name or tag", key="lake_filter", label_visibility="collapsed", placeholder="Filter by name or tag")
    if q:
        items = [d for d in items if q.lower() in (d["name"] + " " + d["tags"] + " " + d["description"]).lower()]
    for row in range(0, len(items), 3):
        for col, d in zip(st.columns(3), items[row:row + 3]):
            with col, st.container(border=True, key=f"rvtile_lake_{d['id']}"):
                st.markdown(_card(d), unsafe_allow_html=True)
                b1, b2 = st.columns(2)
                if b1.button("Explore", key=f"lake_open_{d['id']}", width="stretch"):
                    st.session_state["lake_sel"] = d["id"]
                    st.toast(f"Selected {d['name']}. Open the Explore tab.")
                if user.can("lake.delete") and b2.button("Delete", key=f"lake_del_{d['id']}", width="stretch"):
                    _confirm_delete(d)


def _explore_tab(user) -> None:
    items = lake.list_datasets()
    if not items:
        st.info("Nothing to explore yet.")
        return
    ids = [d["id"] for d in items]
    if st.session_state.get("lake_sel") not in ids:
        st.session_state["lake_sel"] = ids[0]
    ds = st.selectbox("Dataset", items, format_func=lambda d: f"{d['name']} ({ {'table': 'table', 'text': 'document', 'document': 'JSON'}[d['kind']] })",
                      index=ids.index(st.session_state["lake_sel"]), key="lake_pick")
    st.session_state["lake_sel"] = ds["id"]
    raw = lake.raw_path(ds)
    if raw:
        st.download_button("Download original file", raw.read_bytes(), file_name=ds["source_filename"], key=f"lake_dl_{ds['id']}")
    if ds["kind"] == "text":
        _explore_text(user, ds)
        return
    if ds["kind"] == "document":
        st.caption(f"JSON document, {_mb(ds['size_bytes'])}. Outline: `{lake.document_outline(ds)[:300]}`")
        try:
            import json
            st.json(json.loads(lake.read_document(ds, 400_000)), expanded=1)
        except Exception:  # noqa: BLE001
            st.code(lake.read_document(ds, 20000))
        return
    st.caption(f"SQL table name: `{ds['table_name']}`  |  {ds['rows']:,} rows  |  uploaded by {ds['uploaded_by']}")
    left, right = st.columns([2, 3], gap="large")
    with left:
        theme.section("Schema")
        st.dataframe(pd.DataFrame(ds["columns"]).rename(columns={"name": "Column", "type": "Type"}), hide_index=True)
    with right:
        theme.section("Preview")
        try:
            st.dataframe(lake.preview(ds, 200), hide_index=True)
        except lake.LakeError as exc:
            st.error(str(exc))
    theme.section("SQL")
    st.caption("One read-only SELECT. You can join datasets by table name.")
    default = f'SELECT * FROM "{ds["table_name"]}" LIMIT 100'
    sql = st.text_area("Query", value=default, key=f"lake_sql_{ds['id']}", height=100, label_visibility="collapsed")
    if st.button("Run query", type="primary", key="lake_run_sql"):
        try:
            df = lake.query(sql, 1000)
            st.session_state["lake_result"] = df
            audit.log(user.email, "lake", "lake.query", ds["name"], details={"sql": sql[:400], "rows": len(df)})
        except lake.LakeError as exc:
            st.session_state.pop("lake_result", None)
            st.error(str(exc))
            audit.log(user.email, "lake", "lake.query", ds["name"], "failed", {"sql": sql[:400], "error": str(exc)[:200]})
    res = st.session_state.get("lake_result")
    if res is not None:
        st.dataframe(res, hide_index=True)
        st.download_button("Download result as CSV", res.to_csv(index=False).encode(), "lake_result.csv", "text/csv", key="lake_res_dl")


def _explore_text(user, ds: dict) -> None:
    info = ds["info"]
    pg = f"{info['pages']} pages, " if info.get("pages") else ""
    st.caption(f"{info.get('format', 'text').upper()} document, {pg}{info.get('words', 0):,} words, {ds['rows']:,} passages. "
               + ("Semantic search is on for this document." if info.get("semantic") else "Indexed for keyword search."))
    if info.get("note"):
        st.warning(info["note"])
    theme.section("Search this document")
    q = st.text_input("Search", key=f"lake_rag_q_{ds['id']}", label_visibility="collapsed", placeholder="Search for a topic, name or phrase")
    if q.strip():
        hits = lake.search_passages(q, [ds], 6)
        audit.log(user.email, "lake", "lake.search", ds["name"], details={"query": q[:200], "hits": len(hits)})
        if not hits:
            st.info("No matching passages.")
        for h in hits:
            with st.container(border=True):
                st.caption(f"{ds['name']}{', page ' + str(h['page']) if h['page'] else ''}  |  {h['mode']}  |  score {h['score']}")
                st.write(h["text"])
    theme.section("Passages")
    from src.services import rag
    rows = rag.chunk_rows(lake._lake_db(), ds["id"], 300)
    st.dataframe(pd.DataFrame(rows).rename(columns={"passage": "#", "page": "Page", "text": "Text"}), hide_index=True)


def _ask_tab(user) -> None:
    if not user.can("lake.ai"):
        st.info("Your roles do not allow asking the AI about the lake.")
        return
    items = lake.list_datasets()
    if not items:
        st.info("Upload data first, then ask questions about it here.")
        return
    chosen = items  # no manual selection: the AI reads the catalogue and picks the right dataset or document itself
    st.caption(f"The AI searches all {len(items)} dataset(s) and picks the relevant ones for each question. "
               "Search mode: " + lake.search_mode())
    hist = st.session_state.setdefault("lake_chat", [])
    for m in hist:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])
            if m.get("tools"):
                st.caption("Tools: " + ", ".join(m["tools"]))
    for a in st.session_state.get("lake_actions", []):
        action_card.render(user, a, "lake_act")
    if not hist:
        st.caption("Try one of these:")
        cols = st.columns(len(SUGGESTIONS))
        for i, (c, text) in enumerate(zip(cols, SUGGESTIONS)):
            if c.button(text, key=f"lake_sugg_{i}", width="stretch"):
                st.session_state["lake_pending"] = text
                st.rerun()
    prompt = st.chat_input("Ask about your data", key="lake_q") or st.session_state.pop("lake_pending", None)
    if st.button("Clear conversation", key="lake_clear") and hist:
        st.session_state["lake_chat"] = []
        st.rerun()
    if prompt:
        with st.chat_message("user"):
            st.markdown(prompt)
        try:
            with st.spinner("Analysing your data..."):
                props = [] if user.can("containment.view") else None
                answer, tools = lake_agent.ask(prompt, hist, [d["id"] for d in chosen], proposals=props)
            outcome = "success"
        except Exception as exc:  # noqa: BLE001
            answer, tools, outcome = f"Error: {exc}", [], "failed"
        if props:
            n = st.session_state.get("lake_action_n", 0)
            items = []
            for p in props:
                n += 1
                items.append({**p, "prompt": prompt, "n": n})
                action_card.log_proposal(user, items[-1], "lake")
            st.session_state["lake_action_n"] = n
            st.session_state["lake_actions"] = items
            answer += f"\n\nI prepared {len(items)} action card(s) below. Nothing runs until you press Continue."
        else:
            st.session_state.pop("lake_actions", None)
        hist += [{"role": "user", "content": prompt}, {"role": "assistant", "content": answer, "tools": tools}]
        audit.log(user.email, "lake", "lake.ask", ", ".join(d["name"] for d in chosen)[:200], outcome,
                  {"prompt": prompt[:300], "tools": tools})
        st.rerun()


def render() -> None:
    user = common.current_user()
    common.require_perm(user, "lake.view")
    theme.header("Data Lake", "Tables, JSON, PDF and Word in one place. Ask the AI and get answers with sources.", icon="🌊", crumb="Data")
    s = lake.stats()
    k = st.columns(4)
    theme.kpi(k[0], "Datasets", s["datasets"], f"{s['tables']} tables, {s['texts']} documents, {s['documents']} JSON", "🗂️")
    theme.kpi(k[1], "Table rows", f"{s['rows']:,}", "queryable with SQL", "📈")
    theme.kpi(k[2], "Searchable passages", f"{s['passages']:,}", "from PDF and Word (RAG)", "📚")
    theme.kpi(k[3], "Storage", _mb(s["bytes"]), "original files kept", "💾")
    for kind, text in st.session_state.pop("lake_msgs", []):
        (st.success if kind == "success" else st.error)(text)
    tabs = st.tabs(["Datasets", "Upload", "Explore", "Ask AI"])
    for tab, fn in zip(tabs, (_datasets_tab, _upload_tab, _explore_tab, _ask_tab)):
        with tab:
            fn(user)
