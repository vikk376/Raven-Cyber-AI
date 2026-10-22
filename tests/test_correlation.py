from datetime import datetime, timezone

from src.services import arm, correlation, investigation, risk

WS = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"
NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


def inc(num, title="t", sev="Medium", status="Closed", cls="", created="2026-10-05T10:00:00Z", tactics=("Execution",)):
    p = {"title": title, "severity": sev, "status": status, "incidentNumber": num, "createdTimeUtc": created,
         "additionalData": {"alertsCount": 2, "tactics": list(tactics)}}
    if cls:
        p["classification"] = cls
    return {"id": f"{WS}/providers/Microsoft.SecurityInsights/incidents/i-{num}", "name": f"i-{num}", "properties": p}


def acct(name, suffix="corp.com"):
    return {"id": f"a-{name}", "kind": "Account", "properties": {"accountName": name, "upnSuffix": suffix}}


def host(name):
    return {"id": f"h-{name}", "kind": "Host", "properties": {"hostName": name}}


def ip(addr):
    return {"id": f"ip-{addr}", "kind": "Ip", "properties": {"address": addr}}


def proc(cmd):
    return {"id": "p", "kind": "Process", "properties": {"commandLine": cmd}}


def test_entity_keys_strong_only():
    assert correlation.entity_keys(acct("Alice")) == {"account:alice@corp.com"}
    assert correlation.entity_keys(host("PC01")) == {"host:pc01"}
    assert "domain:evil.example" in correlation.entity_keys({"kind": "Url", "properties": {"url": "https://Evil.example/a/"}})
    assert correlation.entity_keys(proc("cmd.exe /c whoami")) == set()
    assert correlation.entity_keys({"kind": "File", "properties": {"fileName": "svchost.exe"}}) == set()


def test_correlate_finds_related_and_flags(monkeypatch):
    current = inc(100, sev="High", status="Active", created="2026-10-09T08:00:00Z", tactics=("Execution", "Exfiltration"))
    pool = [
        (inc(90, cls="TruePositive", created="2026-10-02T08:00:00Z", tactics=("Execution",)), [acct("alice"), ip("203.0.113.5")]),
        (inc(91, cls="FalsePositive", created="2026-09-20T08:00:00Z"), [acct("ALICE"), host("pc01")]),
        (inc(92, created="2026-10-08T08:00:00Z"), [host("OTHER")]),
        (inc(93, created="2026-10-01T08:00:00Z"), [proc("cmd.exe")]),
    ]
    by_id = {i["id"]: ents for i, ents in pool}
    monkeypatch.setattr(arm, "list_incidents", lambda *a, **k: [current, *[i for i, _ in pool]])
    monkeypatch.setattr(arm, "get_incident_entities", lambda t, i: by_id[i])
    ents = [acct("alice"), host("PC01"), ip("198.51.100.9"), proc("cmd.exe")]
    corr = correlation.correlate("tok", current, ents, days=30, now=NOW)
    nums = [r["number"] for r in corr["related"]]
    assert set(nums) == {90, 91} and 92 not in nums and 93 not in nums and 100 not in nums
    by_entity = {e["entity"]: e for e in corr["entities"]}
    assert by_entity["alice@corp.com"]["incidents"] == 2 and by_entity["alice@corp.com"]["true_positive"] == 1
    assert by_entity["alice@corp.com"]["flag"] == "Previously confirmed malicious"
    assert by_entity["PC01"]["flag"] == "Earlier incidents were false positives"
    assert by_entity["198.51.100.9"]["incidents"] == 0
    assert corr["related"][0]["number"] == 90  # TruePositive, recent, shares tactic
    assert any("TruePositive" in f for f in corr["flags"])
    assert corr["tactics"][0]["tactic"] == "Execution"


def test_correlate_handles_failures_truncation_and_no_entities(monkeypatch):
    current = inc(1)
    others = [inc(n) for n in range(2, 8)]
    monkeypatch.setattr(arm, "list_incidents", lambda *a, **k: [current, *others])

    def get(t, i):
        if i.endswith("-3"):
            raise arm.AzureError("boom")
        return [host("PC01")]
    monkeypatch.setattr(arm, "get_incident_entities", get)
    corr = correlation.correlate("tok", current, [host("pc01")], max_incidents=4, now=NOW)
    assert corr["truncated"] and corr["scanned"] == 4 and corr["failed"] == 1
    assert len(corr["related"]) == 3
    empty = correlation.correlate("tok", current, [proc("x")], now=NOW)
    assert empty["errors"] and not empty["related"]

    def fail(*a, **k):
        raise arm.AzureError("denied")
    monkeypatch.setattr(arm, "list_incidents", fail)
    assert "denied" in correlation.correlate("tok", current, [host("a")], now=NOW)["errors"][0]


def test_uplift_and_risk_component(monkeypatch):
    corr = {"days": 30, "entities": [{"incidents": 3, "true_positive": 1}]}
    pts, why = correlation.risk_uplift(corr)
    assert pts == 1.0 and "TruePositive" in why
    assert correlation.risk_uplift({"days": 30, "entities": [{"incidents": 1, "true_positive": 0}]})[0] == 0.0
    base = risk.compute(inc(1, sev="Low"), [host("a")])
    up = risk.compute(inc(1, sev="Low"), [host("a")], history_points=1.0, history_detail=why)
    assert up.score == round(min(10, base.score + 1.0), 1)
    assert up.components[-1]["name"] == "History and correlation"
    ctx = {"incident": inc(1, sev="Low"), "entities": [host("a")], "alerts": [], "errors": {}, "correlation": corr}
    assert investigation.compute_risk(ctx).score == up.score
    md = investigation.build_report(ctx | {"correlation": {**corr, "flags": ["f"], "related": [], "entities": []}}, up)
    assert "Entity history and correlation" in md
