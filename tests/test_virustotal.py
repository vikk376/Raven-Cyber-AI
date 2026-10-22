import pytest

from src.services import virustotal as vt


def test_classify():
    assert vt.classify("203.0.113.45") == ("ip", "203.0.113.45")
    assert vt.classify("Evil-Example[.]com")[0] == "domain"
    assert vt.classify("hxxps://a.example/x")[1].startswith("https://")
    assert vt.classify("44d88612fea8a8f36de82e1278abb02f")[0] == "hash"
    with pytest.raises(vt.VTError):
        vt.classify("not valid")


def test_internal_ip_is_not_sent(monkeypatch):
    monkeypatch.setattr(vt.config, "VIRUSTOTAL_API_KEY", "x")
    monkeypatch.setattr(vt, "_get", lambda u: pytest.fail("must not call VirusTotal for a private IP"))
    monkeypatch.setattr(vt.audit, "log", lambda *a, **k: None)
    assert "internal" in vt.make_tool("a@example.com").invoke({"indicator": "10.1.2.3"})


def test_not_found(monkeypatch):
    class R:
        status_code = 404
    monkeypatch.setattr(vt.config, "VIRUSTOTAL_API_KEY", "x")
    monkeypatch.setattr(vt, "_get", lambda u: R())
    assert "no record" in vt.format_result(vt.lookup("example.org"))
