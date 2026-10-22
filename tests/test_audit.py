from src.core.database import connect
from src.services import audit


def test_chain_valid_and_filters(db):
    for i in range(5):
        audit.log("a@corp.com", "chat", "chat.prompt", f"t{i}", details={"i": i})
    audit.log("b@corp.com", "containment", "containment.executed", "inc1", "failed")
    assert audit.verify_chain() == {"ok": True, "checked": 6, "first_bad_id": None, "reason": ""}
    assert audit.count(panel="chat") == 5
    assert len(audit.query(actor="b@corp.com")) == 1
    assert audit.count(outcome="failed") == 1
    assert audit.counts_by_panel()["containment"] == 1


def test_edit_detected(db):
    for i in range(3):
        audit.log("a@corp.com", "chat", "x", details={"i": i})
    with connect(write=True) as con:
        con.execute("UPDATE audit_log SET outcome = 'success', action = 'tampered' WHERE id = 2")
    res = audit.verify_chain()
    assert not res["ok"] and res["first_bad_id"] == 2


def test_delete_detected(db):
    for i in range(4):
        audit.log("a@corp.com", "chat", "x")
    with connect(write=True) as con:
        con.execute("DELETE FROM audit_log WHERE id = 2")
    res = audit.verify_chain()
    assert not res["ok"] and res["first_bad_id"] == 3


def test_secrets_scrubbed(db):
    audit.log("a@corp.com", "containment", "x", details={
        "password": "hunter2", "msg": "call https://x.logic.azure.com/run?sig=ABC123&a=1", "token": "t"})
    row = audit.query()[0]
    assert "hunter2" not in row["details"] and "ABC123" not in row["details"]
    assert "sig=***" in row["details"]


def test_strict_mode_raises(db, monkeypatch):
    import pytest
    from src.services import audit as a
    monkeypatch.setattr(a, "connect", lambda write=False: (_ for _ in ()).throw(RuntimeError("db down")))
    assert a.log("a", "chat", "x") is False
    with pytest.raises(RuntimeError):
        a.log("a", "chat", "x", strict=True)
