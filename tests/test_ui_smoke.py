"""Render every panel with Streamlit's AppTest and a fake Azure layer."""
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

from src.core import config  # noqa: E402
from src.services import access, arm, audit, sessions, settings, users  # noqa: E402
from src.ui import common  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
WS = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
INC_ID = WS + "/providers/Microsoft.SecurityInsights/incidents/abc-123"


def _incident(num=1, sev="High", status="Active"):
    return {"id": INC_ID if num == 1 else f"{INC_ID}-{num}", "name": f"abc-{num}", "properties": {
        "title": f"Suspicious activity {num}", "severity": sev, "status": status, "incidentNumber": num,
        "createdTimeUtc": "2026-10-06T10:00:00Z", "description": "ransomware seen",
        "additionalData": {"alertsCount": 6, "tactics": ["InitialAccess", "Exfiltration"], "alertProductNames": ["MDE"]}}}


def page(mod: str, email: str):
    import importlib

    import streamlit as st

    from src.services import rbac
    st.session_state["_user"] = rbac.load_user(email)
    name, _, fn = mod.partition(":")
    getattr(importlib.import_module(name), fn or "render")()


@pytest.fixture()
def env(db, monkeypatch):
    access.authorize_login("boss@corp.com", "Boss")
    users.create_user("viewer@corp.com", roles=["Viewer"])
    for k, v in {"sentinel.subscription_id": "11111111-1111-1111-1111-111111111111",
                 "sentinel.resource_group": "rg", "sentinel.workspace_name": "ws"}.items():
        settings.set_value(k, v)
    monkeypatch.setattr(common, "arm_token", lambda user: "fake-token")
    monkeypatch.setattr(arm, "list_incidents", lambda *a, **k: [_incident(1), _incident(2, "Low", "New")])
    monkeypatch.setattr(arm, "get_incident", lambda t, i: _incident(1))
    monkeypatch.setattr(arm, "get_incident_alerts", lambda t, i: [{"properties": {
        "alertDisplayName": "Alert A", "severity": "High", "tactics": ["Exfiltration"], "timeGenerated": "2026-10-06T10:05:00Z"}}])
    monkeypatch.setattr(arm, "get_incident_entities", lambda t, i: [
        {"id": "e1", "kind": "Account", "properties": {"accountName": "alice", "upnSuffix": "corp.com"}},
        {"id": "e2", "kind": "Host", "properties": {"hostName": "PC01"}}])
    monkeypatch.setattr(arm, "get_incident_comments", lambda t, i: [])
    common.load_incidents.clear()
    return db


def run_page(mod, email="boss@corp.com", state=None):
    at = AppTest.from_function(page, kwargs={"mod": mod, "email": email}, default_timeout=30)
    for k, v in (state or {}).items():
        at.session_state[k] = v
    at.run()
    return at


@pytest.mark.parametrize("mod", ["src.ui.admin", "src.ui.audit_view", "src.ui.chat", "src.ui.home",
                                 "src.ui.hunting_view", "src.ui.investigation_view", "src.ui.tools_view",
                                 "src.ui.containment_view:render"])
def test_panel_renders_without_exception(env, mod):
    at = run_page(mod)
    assert not at.exception, [e.value for e in at.exception]


def test_viewer_cannot_open_admin_audit_containment(env):
    for mod in ("src.ui.admin", "src.ui.audit_view", "src.ui.containment_view:render"):
        at = run_page(mod, "viewer@corp.com")
        assert not at.exception
        assert any("permission" in e.value.lower() for e in at.error), mod


def test_investigation_flow_and_risk_header(env):
    at = run_page("src.ui.investigation_view")
    at.checkbox(key="inv_ai").uncheck()
    at.button(key="inv_run").click().run()
    assert not at.exception, [e.value for e in at.exception]
    html = " ".join(m.value for m in at.markdown)
    assert "/ 10" in html and "Suspicious activity 1" in html
    assert audit.query(action="investigation.run")


def test_post_comment_calls_sentinel(env, monkeypatch):
    posted = {}
    monkeypatch.setattr(arm, "add_incident_comment", lambda t, i, m: posted.update(id=i, msg=m) or {})
    at = run_page("src.ui.investigation_view")
    at.checkbox(key="inv_ai").uncheck()
    at.button(key="inv_run").click().run()
    at.button(key="inv_comment_btn").click().run()
    assert posted["id"] == INC_ID and "Risk score" in posted["msg"]
    assert audit.query(action="incident.comment_added")


def test_containment_run_requires_justification_and_confirm(env, monkeypatch):
    monkeypatch.setenv("LOGICAPP_INCIDENT_URL", "https://x.logic.azure.com/run?sig=ABC")
    calls = []

    class R:
        status_code, text = 202, "ok"

    from src.services import containment
    monkeypatch.setattr(containment.requests, "post", lambda url, json=None, **k: calls.append(json) or R())
    at = run_page("src.ui.containment_view:render", state={"ct_type": "incident"})
    assert at.button(key="con_run").disabled
    at.text_area(key="con_why").input("Contain compromised account now").run()
    assert at.button(key="con_run").disabled  # high impact still needs CONFIRM
    at.text_input(key="con_confirm").input("CONFIRM").run()
    assert not at.button(key="con_run").disabled
    at.button(key="con_run").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert len(calls) == 1
    assert calls[0]["incidentArmId"] == INC_ID and calls[0]["incidentName"] == "abc-1" and len(calls[0]["entities"]) == 2
    assert audit.verify_chain()["ok"]


def test_app_shows_login_when_signed_out(db, monkeypatch):
    monkeypatch.setattr(config, "missing_settings", lambda: [])
    from src.services import auth
    monkeypatch.setattr(auth, "get_login_url", lambda state: "https://login.example/authorize")
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    assert any("Sign in with Microsoft" in m.value for m in at.markdown)


def test_app_navigation_for_signed_in_user(db, monkeypatch):
    monkeypatch.setattr(config, "missing_settings", lambda: [])
    access.authorize_login("boss@corp.com", "Boss")
    sid = sessions.create("boss@corp.com")
    at = AppTest.from_file(str(ROOT / "app.py"), default_timeout=30)
    at.query_params["sid"] = sid
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    side = " ".join(m.value for m in [*at.sidebar.markdown, *at.sidebar.caption])
    assert "boss@corp.com" in side.replace("\u200b", "")


def test_containment_prompt_detect_and_ip_block_flow(env, monkeypatch):
    from src.services import targets
    calls = []

    class R:
        status_code, text = 200, "ok"

    monkeypatch.setattr(targets, "_resolve", lambda h, p: ["20.1.2.3"])
    monkeypatch.setattr(targets.requests, "request", lambda m, u, **k: calls.append((m, u, k["json"])) or R())
    targets.save_target({"name": "Firewall block IP", "kind": "api", "category": "ip_block", "method": "POST",
                         "url": "https://fw.example.com/block", "body_template": '{"ip": "{{indicator}}", "why": "{{justification}}"}'},
                        "boss@corp.com")
    at = run_page("src.ui.containment_view:render")
    assert not at.exception, [e.value for e in at.exception]
    assert at.button(key="ct_ip_block_run").disabled
    at.text_input(key="ct_prompt").input("block IP 203.0.113.45 because of C2 beacons seen today").run()
    at.button(key="ct_detect").click().run()
    assert at.text_input(key="ct_ip_block_ind").value == "203.0.113.45"
    assert "C2 beacons" in at.text_area(key="ct_ip_block_why").value
    at.button(key="ct_ip_block_run").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert calls == [("POST", "https://fw.example.com/block", {"ip": "203.0.113.45", "why": "C2 beacons seen today"})]
    assert audit.query(action="containment.executed")


def test_hunting_run_uses_agent_and_is_audited(env, monkeypatch):
    from src.services import agent
    seen = {}
    monkeypatch.setattr(agent, "ask", lambda owner, q, hist, allow_email=True: seen.update(q=q) or ("| a |\n|---|\n| 1 |", ["run_kql"]))
    at = run_page("src.ui.hunting_view")
    assert not at.exception
    at.text_area(key="hunt_kql").input("SigninLogs | take 5").run()
    at.button(key="hunt_kql_run").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert "SigninLogs | take 5" in seen["q"]
    assert audit.query(action="hunting.kql")
    at.text_area(key="hunt_kql").input(".drop table X").run()
    at.button(key="hunt_kql_run").click().run()
    assert any("Control commands" in e.value for e in at.error)


def test_investigation_correlates_entities_and_uplifts_risk(env):
    at = run_page("src.ui.investigation_view")
    at.checkbox(key="inv_ai").uncheck()
    at.button(key="inv_run").click().run()
    assert not at.exception, [e.value for e in at.exception]
    inv = at.session_state["inv"]
    corr = inv["ctx"]["correlation"]
    assert [r["number"] for r in corr["related"]] == [2]  # incident 2 shares alice and PC01 with incident 1
    assert {e["entity"] for e in corr["entities"]} == {"alice@corp.com", "PC01"}
    assert inv["risk"].components[-1]["name"] != "History and correlation"  # needs 2+ earlier incidents or a past TP
    assert audit.query(action="investigation.run")
    # a wider look-back can be re-run from the tab
    at.button(key="inv_corr_run").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert audit.query(action="investigation.correlation")
    assert "Entity history" in " ".join(t.label for t in at.tabs)


def test_tools_page_lists_registry(env):
    at = run_page("src.ui.tools_view")
    assert not at.exception
    html = " ".join(m.value for m in at.markdown)
    assert "Microsoft Sentinel (MCP)" in html and "Planned" not in html and "Data Lake" in html


def _fake_api(monkeypatch):
    from src.services import targets
    calls = []

    class R:
        status_code, text = 200, "ok"

    monkeypatch.setattr(targets, "_resolve", lambda h, p: ["20.1.2.3"])
    monkeypatch.setattr(targets.requests, "request", lambda m, u, **k: calls.append((m, u, k["json"])) or R())
    for name, cat in (("FW block", "ip_block"), ("Proxy block", "url_block")):
        targets.save_target({"name": name, "kind": "api", "category": cat, "method": "POST",
                             "url": f"https://fw.example.com/{cat}", "body_template": '{"v": "{{indicator}}", "why": "{{justification}}"}'},
                            "boss@corp.com")
    return calls


def test_home_chat_runs_containment_with_justification(env, monkeypatch):
    calls = _fake_api(monkeypatch)
    at = run_page("src.ui.home")
    at.text_input(key="home_q").input("block IP 203.0.113.45 because of C2 beacons seen today").run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.text_input(key="home_act1_v").value == "203.0.113.45"
    assert at.text_area(key="home_act1_w").value == "C2 beacons seen today"
    assert not at.button(key="home_act1_run").disabled  # justification came with the prompt: only Continue is left
    at.button(key="home_act1_run").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert calls == [("POST", "https://fw.example.com/ip_block", {"v": "203.0.113.45", "why": "C2 beacons seen today"})]
    assert audit.query(action="chat.action_proposed") and audit.query(action="containment.executed")


def test_home_chat_needs_justification_before_running(env, monkeypatch):
    _fake_api(monkeypatch)
    at = run_page("src.ui.home")
    at.text_input(key="home_q").input("block url https://bad.example/x").run()
    assert at.button(key="home_act1_run").disabled
    at.text_input(key="home_act1_wq").input("phishing landing page").run()
    assert not at.button(key="home_act1_run").disabled


def test_panel_grid_selects_connector_and_manager_sees_add_tile(env, monkeypatch):
    _fake_api(monkeypatch)
    from src.services import targets
    targets.save_target({"name": "Second FW", "kind": "api", "category": "ip_block", "method": "POST",
                         "url": "https://fw2.example.com/b", "body_template": "{}"}, "boss@corp.com")
    at = run_page("src.ui.containment_view:render")
    assert not at.exception, [e.value for e in at.exception]
    assert at.button(key="ct_ip_block_add")
    tid = next(t["id"] for t in targets.list_targets("ip_block") if t["name"] == "Second FW")
    at.button(key=f"ct_ip_block_use_{tid}").click().run()
    assert any("Second FW" in c.value for c in at.caption)


def test_containment_detect_switches_action_type(env, monkeypatch):
    _fake_api(monkeypatch)
    at = run_page("src.ui.containment_view:render")
    at.text_input(key="ct_prompt").input("block url https://bad.example/x because phishing page").run()
    at.button(key="ct_detect").click().run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.session_state["ct_type"] == "url_block"
    assert at.text_input(key="ct_url_block_ind").value == "https://bad.example/x"


@pytest.mark.parametrize("ctype", ["ip_block", "url_block", "domain_block", "device_isolation", "user_disable", "password_reset", "advanced"])
def test_every_containment_type_renders(env, ctype):
    at = run_page("src.ui.containment_view:render", state={"ct_type": ctype})
    assert not at.exception, [e.value for e in at.exception]


def test_password_reset_from_chat_text(env, monkeypatch):
    from src.services import targets
    calls = _fake_api(monkeypatch)
    targets.save_target({"name": "Entra reset", "kind": "api", "category": "password_reset", "method": "POST",
                         "url": "https://iam.example.com/reset", "body_template": '{"user": "{{indicator}}", "why": "{{justification}}"}'},
                        "boss@corp.com")
    at = run_page("src.ui.home")
    at.text_input(key="home_q").input("reset password for alice@corp.com because credentials leaked").run()
    assert not at.exception, [e.value for e in at.exception]
    assert at.text_input(key="home_act1_v").value == "alice@corp.com"
    at.button(key="home_act1_run").click().run()
    assert calls[-1] == ("POST", "https://iam.example.com/reset", {"user": "alice@corp.com", "why": "credentials leaked"})


def test_lake_page_and_ai_chat(env, monkeypatch):
    from src.services import lake, lake_agent
    lake.ingest("boss@corp.com", "logins.csv", b"user,n\nalice,3\n", description="Sign-in export", tags="identity")
    at = run_page("src.ui.lake_view")
    assert not at.exception, [e.value for e in at.exception]
    html = " ".join(m.value for m in at.markdown)
    assert "logins" in html and "1 rows" in html
    seen = {}
    monkeypatch.setattr(lake_agent, "ask", lambda q, h, ids, proposals=None: seen.update(q=q, ids=ids) or ("Alice has 3 sign-ins.", ["run_sql"]))
    at.chat_input[0].set_value("who signed in most?").run()
    assert not at.exception, [e.value for e in at.exception]
    assert seen["q"] == "who signed in most?" and len(seen["ids"]) == 1
    assert audit.query(action="lake.ask")


def test_viewer_can_view_lake_but_not_upload(env):
    from src.services import lake
    lake.ingest("boss@corp.com", "x.csv", b"a\n1\n")
    at = run_page("src.ui.lake_view", "viewer@corp.com")
    assert not at.exception, [e.value for e in at.exception]
    assert any("do not allow" in i.value for i in at.info)
