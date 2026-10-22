import json

import pytest

from src.core import constants
from src.services import access, audit, containment, rbac, settings, users

INC = {
    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws/providers/Microsoft.SecurityInsights/incidents/abc-123",
    "name": "abc-123",
    "properties": {"title": "Suspicious sign-in", "incidentNumber": 42, "severity": "High", "status": "Active"},
}
ENTS = [
    {"id": "e1", "kind": "Account", "properties": {"accountName": "alice", "upnSuffix": "corp.com"}},
    {"id": "e2", "kind": "Host", "properties": {"hostName": "PC01"}},
]


class FakeResp:
    def __init__(self, code=202, text="accepted"):
        self.status_code, self.text = code, text


@pytest.fixture()
def setup(db, monkeypatch):
    access.authorize_login("boss@corp.com")
    monkeypatch.setenv("LOGICAPP_INCIDENT_URL", "https://prod.logic.azure.com/workflows/x/triggers/t/paths/invoke?sig=SECRETSIG")
    return rbac.load_user("boss@corp.com"), containment.get_action("incident_containment")


def test_payload_contains_requested_fields(db):
    ctx = containment.build_context(INC, ENTS, "boss@corp.com", "because")
    payload = containment.render_payload(constants.DEFAULT_PAYLOAD_TEMPLATE, ctx)
    assert payload["incidentArmId"] == INC["id"]
    assert payload["incidentName"] == "abc-123"
    assert payload["incidentId"] == 42  # type preserved
    assert payload["entities"] == ENTS  # list preserved
    assert payload["triggeredBy"] == "boss@corp.com"


def test_inline_placeholder_and_missing(db):
    ctx = containment.build_context(INC, ENTS, "u@x.com", "j")
    out = containment.render_payload({"msg": "Incident {{incident.number}} by {{user.email}} {{nope.x}}"}, ctx)
    assert out["msg"] == "Incident 42 by u@x.com "


def test_validate_template():
    assert containment.validate_template("{bad")["error"]
    assert containment.validate_template("[1]")["error"]
    res = containment.validate_template('{"a": "{{incident.arm_id}}", "b": "{{made.up}}"}')
    assert res["error"] is None and res["unknown"] == ["made.up"]


def test_run_success_is_audited_without_url(setup, monkeypatch):
    user, action = setup
    sent = {}

    def fake_post(url, json=None, timeout=None, allow_redirects=None):
        sent.update(url=url, json=json)
        return FakeResp(202)

    monkeypatch.setattr(containment.requests, "post", fake_post)
    res = containment.run_action(user, action, INC, ENTS, "test run", None)
    assert res["ok"] and res["http_status"] == 202
    assert sent["json"]["incidentArmId"] == INC["id"]
    rows = audit.query(panel="containment")
    assert {r["action"] for r in rows} == {"containment.requested", "containment.executed"}
    assert all("SECRETSIG" not in (r["details"] or "") for r in rows)
    assert audit.verify_chain()["ok"]


def test_protected_entity_blocks(setup, monkeypatch):
    user, action = setup
    settings.set_value("containment.protected_entities", "# break glass\nalice@corp.com\n*-admin")
    called = []
    monkeypatch.setattr(containment.requests, "post", lambda *a, **k: called.append(1) or FakeResp())
    res = containment.run_action(user, action, INC, ENTS, "x", None)
    assert res["blocked"] and not called
    assert audit.query(action="containment.blocked")[0]["outcome"] == "denied"


def test_wildcard_protected(setup):
    settings.set_value("containment.protected_entities", "*@corp.com")
    assert containment.find_protected(ENTS) == ["alice@corp.com"]


def test_permission_denied_for_high_risk(db, monkeypatch):
    access.authorize_login("boss@corp.com")
    users.create_user("l2@corp.com", roles=["L2 Analyst"])  # has run, not run_high
    monkeypatch.setenv("LOGICAPP_INCIDENT_URL", "https://x.logic.azure.com/a?sig=1")
    monkeypatch.setattr(containment.requests, "post", lambda *a, **k: pytest.fail("must not call"))
    res = containment.run_action(rbac.load_user("l2@corp.com"), containment.get_action("incident_containment"), INC, ENTS, "x", None)
    assert res["blocked"]


def test_rate_limit(setup, monkeypatch):
    user, action = setup
    settings.set_value("containment.rate_limit_per_hour", "2")
    monkeypatch.setattr(containment.requests, "post", lambda *a, **k: FakeResp())
    assert containment.run_action(user, action, INC, ENTS, "1", None)["ok"]
    assert containment.run_action(user, action, INC, ENTS, "2", None)["ok"]
    third = containment.run_action(user, action, INC, ENTS, "3", None)
    assert third["blocked"] and "Rate limit" in third["message"]


def test_http_error_reported_failed(setup, monkeypatch):
    user, action = setup
    monkeypatch.setattr(containment.requests, "post", lambda *a, **k: FakeResp(400, "bad schema"))
    res = containment.run_action(user, action, INC, ENTS, "x", None)
    assert not res["ok"] and "400" in res["message"]
    assert audit.query(action="containment.executed")[0]["outcome"] == "failed"


def test_missing_env_url_reported(setup, monkeypatch):
    user, action = setup
    monkeypatch.delenv("LOGICAPP_INCIDENT_URL")
    res = containment.run_action(user, action, INC, ENTS, "x", None)
    assert not res["ok"] and "not set" in res["message"]


def test_save_action_validation(db):
    base = {"key": "isolate_host", "label": "Isolate", "source": "env", "url_env": "LOGICAPP_ISOLATE_URL",
            "payload_template": json.dumps({"a": "{{incident.arm_id}}"}), "risk_level": "high", "enabled": True}
    containment.save_action(base)
    assert containment.get_action("isolate_host")["risk_level"] == "high"
    with pytest.raises(ValueError):
        containment.save_action({**base, "key": "Bad Key"})
    with pytest.raises(ValueError):
        containment.save_action({**base, "url_env": "lower"})
    with pytest.raises(ValueError):
        containment.save_action({**base, "payload_template": "{bad"})
