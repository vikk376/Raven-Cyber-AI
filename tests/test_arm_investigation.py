import pytest

from src.services import arm, investigation, metrics

WS = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
INC_ID = WS + "/providers/Microsoft.SecurityInsights/incidents/abc-123"


def test_incident_id_validation():
    assert arm.is_incident_id(INC_ID)
    assert not arm.is_incident_id("/subscriptions/x/../../evil")
    assert not arm.is_incident_id(INC_ID + "/../../x")
    with pytest.raises(arm.AzureError):
        arm.get_incident("t", "https://evil.example/steal")


def test_refuses_non_arm_url():
    with pytest.raises(arm.AzureError):
        arm._request("GET", "https://evil.example/x", "token")


def test_comment_requires_text():
    with pytest.raises(arm.AzureError):
        arm.add_incident_comment("t", INC_ID, "   ")


def test_comment_request_shape(monkeypatch):
    seen = {}

    def fake(method, url, token, **kw):
        seen.update(method=method, url=url, body=kw.get("json_body"), params=kw.get("params"))
        return {}

    monkeypatch.setattr(arm, "_request", fake)
    arm.add_incident_comment("t", INC_ID, "hello")
    assert seen["method"] == "PUT" and "/comments/" in seen["url"]
    assert seen["body"] == {"properties": {"message": "hello"}}
    assert seen["params"]["api-version"] == arm.SENTINEL_API


def test_list_incidents_filter(monkeypatch):
    seen = {}
    monkeypatch.setattr(arm, "_get_all", lambda url, token, params=None, max_items=0: seen.update(url=url, params=params) or [])
    arm.list_incidents("t", WS, since_iso="2026-10-01T00:00:00Z", statuses=("New", "Active"), severities=("High",))
    f = seen["params"]["$filter"]
    assert "createdTimeUtc ge 2026-10-01T00:00:00Z" in f and "status eq 'New'" in f and "severity eq 'High'" in f


def test_entity_labels_and_identifiers():
    acc = {"kind": "Account", "properties": {"accountName": "alice", "upnSuffix": "corp.com"}}
    host = {"kind": "Host", "properties": {"hostName": "PC01", "dnsDomain": "corp.local"}}
    assert investigation.entity_label(acc) == "alice@corp.com"
    assert investigation.entity_label(host) == "PC01.corp.local"
    assert "alice@corp.com" in investigation.entity_identifiers(acc)
    assert "pc01" in investigation.entity_identifiers(host)


def test_report_and_comment_text():
    ctx = {
        "incident": {"id": INC_ID, "properties": {
            "title": "Bad | thing", "severity": "High", "status": "Active", "incidentNumber": 7,
            "additionalData": {"alertsCount": 2, "tactics": ["Exfiltration"]}}},
        "alerts": [{"properties": {"alertDisplayName": "A1", "severity": "High", "tactics": ["Exfiltration"], "timeGenerated": "2026-10-01T10:00:00Z"}}],
        "entities": [{"kind": "Ip", "properties": {"address": "1.2.3.4"}}],
        "comments": [], "errors": {},
    }
    r = investigation.compute_risk(ctx)
    md = investigation.build_report(ctx, r, ai_text="AI says hi")
    assert "Incident #7" in md and "1.2.3.4" in md and "AI says hi" in md and r.label in md
    txt = investigation.comment_text(ctx, r, "me@corp.com")
    assert "Risk score" in txt and "me@corp.com" in txt and "#" not in txt.split("\n")[0]


def test_metrics():
    incs = [
        {"id": "1", "properties": {"title": "a", "severity": "High", "status": "New", "incidentNumber": 1,
                                   "createdTimeUtc": "2026-10-01T10:00:00Z", "additionalData": {"alertsCount": 3, "tactics": ["Impact"]}}},
        {"id": "2", "properties": {"title": "b", "severity": "Low", "status": "Closed", "incidentNumber": 2,
                                   "createdTimeUtc": "2026-10-01T10:00:00Z", "closedTimeUtc": "2026-10-01T14:00:00Z",
                                   "owner": {"assignedTo": "x"}, "additionalData": {"alertsCount": 1}}},
    ]
    df = metrics.build_frame(incs)
    k = metrics.kpis(df)
    assert k["total"] == 2 and k["open"] == 1 and k["open_high"] == 1 and k["unassigned_open"] == 1 and k["mttr_hours"] == 4.0
    assert metrics.severity_counts(df).set_index("severity").loc["High", "count"] == 1
    assert not metrics.daily_trend(df).empty
    assert metrics.tactic_counts(df).iloc[0]["tactic"] == "Impact"
    assert metrics.kpis(metrics.build_frame([]))["total"] == 0
