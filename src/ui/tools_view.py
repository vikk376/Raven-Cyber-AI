"""Tools hub: the products and services that are integrated into Raven Cyber AI."""
import streamlit as st

from src.services import audit, targets
from src.tools import registry
from src.ui import common, connector_editor, theme

STATE_LABEL = {"configured": ("Configured", "ok"), "missing": ("Not configured", "bad"), "custom": ("Custom", "info")}
CAP_LABEL = {"detect": "Detect", "investigate": "Investigate", "hunt": "Hunt", "contain": "Contain", "enrich": "Enrich",
             "notify": "Notify", "ai": "AI", "store": "Store"}




def _datasets() -> int:
    try:
        from src.services import lake
        return len(lake.list_datasets())
    except Exception:  # noqa: BLE001
        return 0


def render() -> None:
    user = common.current_user()
    theme.header("Tools", "Everything Raven Cyber AI can use, in one place. Add any REST API or Logic App without code.",
                 icon="🧰", crumb="Platform")

    counts = registry.summary()
    custom = [t for t in targets.list_targets()]
    k = st.columns(4)
    theme.kpi(k[0], "Configured", counts["configured"], "ready to use", "✅")
    theme.kpi(k[1], "Needs setup", counts["missing"], "built-in, not configured", "🛠️")
    theme.kpi(k[2], "Custom targets", len(custom), "Logic Apps, APIs, enrichment", "🔌")
    theme.kpi(k[3], "Data sets", _datasets(), "in the Data Lake", "🌊")
    st.caption("Configured means the settings exist. Use Test where offered to check a live connection.")

    can_manage = user.can("containment.manage_targets")
    for category, tools in registry.by_category().items():
        theme.section(category)
        for row_start in range(0, len(tools), 3):
            cols = st.columns(3)
            for col, t in zip(cols, tools[row_start:row_start + 3]):
                state, detail = t.status()
                label, kind = STATE_LABEL[state]
                with col, theme.card(f"tool_{t.key}"):
                    st.markdown(theme.tool_card_html(t.icon, t.name, t.vendor, t.description + (f"  ({detail})" if detail else ""),
                                                     label, kind, [CAP_LABEL.get(c, c) for c in t.capabilities], bare=True), unsafe_allow_html=True)
                    b1, b2 = st.columns(2)
                    if t.nav:
                        b1.button("Open", key=f"tool_open_{t.key}", on_click=common.go, args=(t.nav,), width="stretch")
                    if t.test and user.can("admin.settings") and state == "configured":
                        if b2.button("Test", key=f"tool_test_{t.key}", width="stretch"):
                            try:
                                st.success(t.test())
                                audit.log(user.email, "admin", "integration.tested", t.key)
                            except Exception as exc:  # noqa: BLE001
                                st.error(f"{t.name} test failed: {exc}")
                                audit.log(user.email, "admin", "integration.tested", t.key, "failed", {"error": str(exc)[:200]})

    theme.section("Your custom connectors")
    cells = [*custom, *([None] if can_manage else [])]
    if not cells:
        st.caption("None yet.")
    for row in range(0, len(cells), 3):
        for col, t in zip(st.columns(3), cells[row:row + 3]):
            with col:
                if t is None:
                    with st.container(border=True, key="rvadd_tools"):
                        st.markdown(theme.add_tile_html("Add custom connector", "Logic App or API for blocking, isolation, actions or threat intel lookups."),
                                    unsafe_allow_html=True)
                        if st.button("Add connector", key="tools_add", width="stretch"):
                            connector_editor.editor("ip_block")
                    continue
                with st.container(border=True, key=f"rvtile_cc_{t['id']}"):
                    st.markdown(theme.tool_card_html(
                        "⚙️" if t["kind"] == "logicapp" else "🔌", t["name"], t["host"], t.get("description") or "",
                        "Enabled" if t["enabled"] else "Disabled", "ok" if t["enabled"] else "muted",
                        [{"enrichment": "Enrich"}.get(t["category"], "Contain"), t["category"].replace("_", " ")], bare=True),
                        unsafe_allow_html=True)
                    if can_manage and st.button("Edit", key=f"tools_edit_{t['id']}", width="stretch"):
                        connector_editor.editor(t["category"], t["id"])
    with st.expander("How to add another tool"):
        st.markdown("**No code:** open a Respond panel (for example IP Blocking) and press Add connector, or use the tile above. "
                    "Containment connectors appear as cards in their Respond panel; enrichment connectors appear in the Entity history tab of each incident.\n\n"
                    "**With code:** see `docs/ADDING_A_TOOL.md` to register a new built-in tool in `src/tools/`.")
