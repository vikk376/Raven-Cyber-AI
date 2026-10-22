import json

import pytest

from src.core import config
from src.services import access, audit, hunting, indicators, rbac, secrets, settings, targets, users

URL = "https://prod-11.northcentralus.logic.azure.com:443/workflows/abc/triggers/t/paths/invoke?sig=TOPSECRETSIG"


class Resp:
    def __init__(self, code=202, text="accepted"):
        self.status_code, self.text = code, text


@pytest.fixture()
def ctx(db, monkeypatch):
    access.authorize_login("boss@corp.com", "Boss")
    users.create_user("l1@corp.com", roles=["L1 Analyst"])
    monkeypatch.setattr(targets, "_resolve", lambda host, port: ["20.1.2.3"])
    sent = []
    monkeypatch.setattr(targets.requests, "request", lambda method, url, **kw: sent.append((method, url, kw)) or Resp())
    return rbac.load_user("boss@corp.com"), sent


def _logicapp(name="Block IP", category="ip_block", **kw):
    return targets.save_target({"name": name, "kind": "logicapp", "category": category, "url": URL,
                                "body_format": "json", "body_template": targets.DEFAULT_LOGICAPP_BODY, **kw}, "boss@corp.com")


# ---- indicators
def test_parse_prompt_ip_reason_and_defang():
    r = indicators.parse_prompt("block IP 203.0.113[.]45 because of C2 beacons")
    assert (r["indicator"], r["category"], r["reason"]) == ("203.0.113.45", "ip_block", "C2 beacons")


def test_parse_prompt_url_domain_device():
    assert indicators.parse_prompt("block hxxps://evil.example/x.php")["indicator"] == "https://evil.example/x.php"
    assert indicators.parse_prompt("block evil-site.xyz")["category"] == "domain_block"
    d = indicators.parse_prompt("isolate LAPTOP-01 because ransomware")
    assert (d["indicator"], d["category"]) == ("LAPTOP-01", "device_isolation")
    assert indicators.parse_prompt("hello there")["indicator"] == ""


@pytest.mark.parametrize("cat,val,ok", [
    ("ip_block", "203.0.113.45", True), ("ip_block", "10.0.0.0/8", False), ("ip_block", "127.0.0.1", False),
    ("ip_block", "300.1.1.1", False), ("ip_block", "203.0.113.0/24", True),
    ("url_block", "evil.example", True), ("url_block", "ftp://x.y", False), ("url_block", "not a url", False),
    ("device_isolation", "PC-01", True), ("device_isolation", "bad host!", False),
    ("advanced", "anything", True), ("advanced", "", False),
])
def test_validate(cat, val, ok):
    assert indicators.validate(cat, val)[0] is ok


# ---- secrets and storage
def test_secrets_roundtrip_and_url_not_stored_in_clear(db):
    assert secrets.decrypt(secrets.encrypt("hello")) == "hello"
    tid = _logicapp()
    import sqlite3
    raw = sqlite3.connect(config.DB_PATH).execute("SELECT url_enc FROM containment_targets WHERE id=?", (tid,)).fetchone()[0]
    assert "TOPSECRETSIG" not in raw and "logic.azure.com" not in raw
    pub = targets.get_target(tid)
    assert pub["host"] == "prod-11.northcentralus.logic.azure.com" and "url" not in pub and "url_enc" not in pub
    assert targets.get_target(tid, secrets_included=True)["url"] == URL


def test_edit_keeps_url_and_headers_when_blank(db):
    tid = targets.save_target({"name": "Fw API", "kind": "api", "category": "ip_block", "url": "https://fw.example.com/block",
                               "headers": "Authorization: Bearer abc\nX-Org: 7", "method": "PUT",
                               "body_template": '{"ip": "{{indicator}}"}'}, "a@x.com")
    targets.save_target({"id": tid, "name": "Fw API", "kind": "api", "category": "ip_block", "url": "", "headers": "",
                         "method": "PUT", "body_template": '{"ip": "{{indicator}}"}', "risk_level": "high"}, "a@x.com")
    t = targets.get_target(tid, secrets_included=True)
    assert t["url"] == "https://fw.example.com/block" and t["headers"]["X-Org"] == "7" and t["risk_level"] == "high"


@pytest.mark.parametrize("bad", ["http://x.example.com/a", "ftp://x.example.com", "https://{{indicator}}.evil.com/x", "", "x.example.com"])
def test_url_template_rejected(db, bad):
    with pytest.raises(targets.TargetError):
        targets.validate_url_template(bad)


def test_save_validation(db):
    with pytest.raises(targets.TargetError):
        targets.save_target({"name": "ab", "kind": "api", "category": "ip_block", "url": "https://a.example.com"}, "x")
    with pytest.raises(targets.TargetError):
        targets.save_target({"name": "Bad body", "kind": "api", "category": "ip_block", "url": "https://a.example.com",
                             "body_template": "{oops"}, "x")
    with pytest.raises(targets.TargetError):  # arbitrary env vars must not be readable
        targets.save_target({"name": "Leaky", "kind": "api", "category": "ip_block", "url": "https://a.example.com",
                             "headers": "X: {{env.AZURE_CLIENT_SECRET}}", "body_template": "{}"}, "x")
    with pytest.raises(targets.TargetError):
        targets.save_target({"name": "Bad header", "kind": "api", "category": "ip_block", "url": "https://a.example.com",
                             "headers": "Host: evil"}, "x")
    _logicapp("Dup")
    with pytest.raises(targets.TargetError):
        _logicapp("dup")


def test_parse_headers_formats():
    assert targets.parse_headers('{"A": "1"}') == {"A": "1"}
    assert targets.parse_headers("A: 1\n# c\nB: x:y") == {"A": "1", "B": "x:y"}


# ---- SSRF guard
def test_destination_guard(db, monkeypatch):
    monkeypatch.setattr(targets, "_resolve", lambda h, p: ["10.0.0.5"])
    with pytest.raises(targets.TargetError):
        targets.check_destination("https://internal.example.com/x")
    monkeypatch.setattr(targets, "_resolve", lambda h, p: ["169.254.169.254"])
    with pytest.raises(targets.TargetError):
        targets.check_destination("https://meta.example.com/x")
    with pytest.raises(targets.TargetError):
        targets.check_destination("https://127.0.0.1/x")
    monkeypatch.setattr(targets, "_resolve", lambda h, p: ["20.1.2.3"])
    targets.check_destination("https://ok.example.com/x")
    settings.set_value("containment.allow_private_targets", "true")
    monkeypatch.setattr(targets, "_resolve", lambda h, p: ["10.0.0.5"])
    targets.check_destination("https://internal.example.com/x")
    monkeypatch.setattr(targets, "_resolve", lambda h, p: ["169.254.169.254"])
    with pytest.raises(targets.TargetError):  # metadata address is always blocked
        targets.check_destination("https://meta.example.com/x")


# ---- running
def test_run_logicapp_success_and_audit_has_no_secrets(ctx):
    user, sent = ctx
    tid = _logicapp()
    res = targets.run_target(user, tid, "203.0.113.45", "C2 beacon seen in incident 42", prompt="block it")
    assert res["ok"] and res["http_status"] == 202
    method, url, kw = sent[0]
    assert method == "POST" and url == URL
    assert kw["json"]["indicator"] == "203.0.113.45" and kw["json"]["triggeredBy"] == "boss@corp.com"
    assert kw["json"]["category"] == "ip_block" and kw["allow_redirects"] is False
    dump = json.dumps(audit.query(limit=50))
    assert "TOPSECRETSIG" not in dump and "logic.azure.com" not in dump
    assert audit.query(action="containment.requested") and audit.query(action="containment.executed")
    assert audit.verify_chain()["ok"]
    assert targets.history("ip_block")[0]["Status"] == "Executed"


def test_run_api_renders_url_headers_body_and_env(ctx, monkeypatch):
    user, sent = ctx
    monkeypatch.setenv("CONTAINMENT_FW_KEY", "k-123")
    tid = targets.save_target({
        "name": "Proxy URL block", "kind": "api", "category": "url_block", "method": "PUT",
        "url": "https://proxy.example.com/api/v1/block/{{indicator}}?ticket={{param.ticket}}",
        "headers": "Authorization: Bearer {{env.CONTAINMENT_FW_KEY}}\nContent-Type: application/json",
        "body_template": '{"url": "{{indicator}}", "why": "{{justification}}", "by": "{{user.email}}", "t": "{{param.ticket}}"}',
    }, "boss@corp.com")
    res = targets.run_target(user, tid, "https://evil.example/a b", "phishing kit hosted here", params={"ticket": "INC 9"})
    assert res["ok"]
    method, url, kw = sent[0]
    assert method == "PUT"
    assert url == "https://proxy.example.com/api/v1/block/https%3A%2F%2Fevil.example%2Fa%20b?ticket=INC%209"
    assert kw["headers"]["Authorization"] == "Bearer k-123"
    assert kw["json"] == {"url": "https://evil.example/a b", "why": "phishing kit hosted here", "by": "boss@corp.com", "t": "INC 9"}
    assert "k-123" not in json.dumps(audit.query(limit=50))
    prev = targets.preview(targets.get_target(tid, True), targets.build_context("a@x.com", targets.get_target(tid), "x.com", "domain", "j"))
    assert prev["headers"] == ["Authorization", "Content-Type"] and "k-123" not in json.dumps(prev)


def test_run_blocked_cases(ctx):
    user, sent = ctx
    tid = _logicapp()
    l1 = rbac.load_user("l1@corp.com")
    assert targets.run_target(l1, tid, "203.0.113.45", "long enough reason")["blocked"]
    assert targets.run_target(user, tid, "203.0.113.45", "short")["blocked"]
    assert targets.run_target(user, tid, "10.0.0.0/8", "long enough reason")["blocked"]
    settings.set_value("containment.protected_entities", "203.0.113.*")
    r = targets.run_target(user, tid, "203.0.113.45", "long enough reason")
    assert r["blocked"] and "protected" in r["message"]
    settings.set_value("containment.protected_entities", "")
    settings.set_value("containment.rate_limit_per_hour", "1")
    assert targets.run_target(user, tid, "198.51.100.7", "long enough reason")["ok"]
    assert "Rate limit" in targets.run_target(user, tid, "198.51.100.8", "long enough reason")["message"]
    assert len(sent) == 1


def test_run_high_impact_needs_run_high_permission(ctx):
    user, sent = ctx
    users.create_user("l2@corp.com", roles=["L2 Analyst"])
    tid = _logicapp("Isolate", "device_isolation", risk_level="high")
    assert targets.run_target(rbac.load_user("l2@corp.com"), tid, "PC-01", "ransomware on this host")["blocked"]
    assert targets.run_target(user, tid, "PC-01", "ransomware on this host")["ok"]


def test_http_error_and_network_error_are_reported(ctx, monkeypatch):
    user, _ = ctx
    tid = _logicapp()
    monkeypatch.setattr(targets.requests, "request", lambda *a, **k: Resp(400, "bad schema"))
    r = targets.run_target(user, tid, "198.51.100.7", "long enough reason")
    assert not r["ok"] and "400" in r["message"]

    def boom(*a, **k):
        raise targets.requests.ConnectionError("down")
    monkeypatch.setattr(targets.requests, "request", boom)
    r = targets.run_target(user, tid, "198.51.100.9", "long enough reason")
    assert not r["ok"] and "down" in r["message"]
    assert targets.history("ip_block")[0]["Status"] == "Failed"


def test_ssrf_blocks_at_run_time(ctx, monkeypatch):
    user, sent = ctx
    tid = _logicapp()
    monkeypatch.setattr(targets, "_resolve", lambda h, p: ["192.168.1.10"])
    r = targets.run_target(user, tid, "198.51.100.7", "long enough reason")
    assert not r["ok"] and "non-public" in r["message"] and not sent


# ---- hunting
def test_hunting_kql_checks_and_saved(db):
    with pytest.raises(hunting.HuntError):
        hunting.check_kql(".drop table X")
    with pytest.raises(hunting.HuntError):
        hunting.check_kql("T | take 1\n  .show tables")
    assert "SigninLogs" in hunting.build_kql_prompt("SigninLogs | take 1")
    hunting.save_query("a@x.com", "My hunt", "kql", "SigninLogs | take 1", shared=True)
    hunting.save_query("a@x.com", "Private", "nl", "find logins")
    assert len(hunting.list_queries("a@x.com")) == 2
    assert [q["name"] for q in hunting.list_queries("b@x.com")] == ["My hunt"]
    q = hunting.list_queries("a@x.com")[0]
    assert not hunting.delete_query("b@x.com", q["id"])
    assert hunting.delete_query("a@x.com", q["id"])


def test_all_playbook_kql_passes_checks():
    for pb in hunting.PLAYBOOKS:
        if pb["kind"] == "kql":
            hunting.check_kql(pb["text"])


# ---- enrichment tools, registry and migration
def test_enrichment_lookup_flow(ctx, monkeypatch):
    user, sent = ctx
    monkeypatch.setenv("CONTAINMENT_VT_KEY", "vt-secret")
    monkeypatch.setattr(targets.requests, "request", lambda m, u, **k: sent.append((m, u, k)) or type("R", (), {
        "status_code": 200, "text": '{"data": {"malicious": 7}}', "json": lambda self: {"data": {"malicious": 7}}})())
    tid = targets.save_target({"name": "VT IP", "kind": "api", "category": "enrichment", "method": "GET",
                               "url": "https://vt.example.com/api/v3/ip_addresses/{{indicator}}",
                               "headers": "x-apikey: {{env.CONTAINMENT_VT_KEY}}", "body_template": ""}, "a@x.com")
    res = targets.run_enrichment(user, tid, "203.0.113.9")
    assert res["ok"] and res["data"]["data"]["malicious"] == 7
    method, url, kw = sent[0]
    assert method == "GET" and url == "https://vt.example.com/api/v3/ip_addresses/203.0.113.9"
    assert kw["headers"]["x-apikey"] == "vt-secret" and kw["json"] is None
    assert "vt-secret" not in json.dumps(audit.query(limit=50))
    assert audit.query(action="enrichment.executed")
    # enrichment tools never appear as containment targets, and containment targets cannot be used for lookups
    assert targets.list_targets("ip_block") == []
    other = _logicapp()
    assert "not found" in targets.run_enrichment(user, other, "1.1.1.1")["message"]
    users.create_user("nobody@corp.com", roles=[])
    assert "do not allow" in targets.run_enrichment(rbac.load_user("nobody@corp.com"), tid, "x.com")["message"]


def test_migration_3_keeps_existing_targets(tmp_path, monkeypatch):
    from src.core import database
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "up.db")
    full = list(database.MIGRATIONS)
    monkeypatch.setattr(database, "MIGRATIONS", full[:2])
    database.init_db()
    tid = _logicapp("Old target")
    monkeypatch.setattr(database, "MIGRATIONS", full)
    database.init_db()
    assert targets.get_target(tid, secrets_included=True)["url"] == URL
    targets.save_target({"name": "VT lookup", "kind": "api", "category": "enrichment", "url": "https://vt.example.com/x", "method": "GET"}, "a")


def test_tool_registry_status(db):
    from src.tools import registry
    tools = {t.key: t for t in registry.all_tools()}
    assert {"sentinel_mcp", "sentinel_rest", "azure_openai", "smtp", "logicapps", "custom_api", "enrichment_api", "data_lake"} <= set(tools)
    assert "defender_xdr" not in tools
    assert tools["logicapps"].status()[0] == "missing"
    _logicapp()
    assert tools["logicapps"].status()[0] == "configured"
    assert "planned" not in registry.summary()


def test_parse_action_variants():
    from src.services.indicators import parse_action
    assert parse_action("hello") is None
    assert parse_action("Which incidents contain ransomware?") is None
    a = parse_action("block IP 203.0.113.45 because of C2 beacons")
    assert a["category"] == "ip_block" and a["reason"] == "C2 beacons"
    assert parse_action("isolate LAPTOP-01 justification: ransomware")["category"] == "device_isolation"
    assert parse_action("block this ip with justification")["indicator"] == ""


def test_user_and_domain_actions_parse_and_validate():
    from src.services.indicators import parse_action, validate
    a = parse_action("disable user alice@corp.com because phishing victim")
    assert (a["category"], a["indicator"], a["reason"]) == ("user_disable", "alice@corp.com", "phishing victim")
    assert parse_action("reset password for bob@corp.com")["category"] == "password_reset"
    assert validate("domain_block", "https://Evil.example/x")[1] == "evil.example"
    assert not validate("user_disable", "not-an-email")[0]
    assert validate("password_reset", "Bob@Corp.com")[1] == "bob@corp.com"


def test_migration_4_allows_new_categories(db):
    from src.services import targets
    tid = targets.save_target({"name": "Reset hook", "kind": "api", "category": "password_reset", "method": "POST",
                               "url": "https://iam.example.com/r", "body_template": "{}"}, "a@x.com")
    assert targets.get_target(tid)["category"] == "password_reset"
