from src.services import risk


def _inc(sev="High", alerts=12, tactics=None, title="x", classification=None):
    props = {"severity": sev, "title": title, "additionalData": {"alertsCount": alerts, "tactics": tactics or []}}
    if classification:
        props["classification"] = classification
    return {"properties": props}


def test_max_score_is_ten():
    ents = [{"kind": "Account", "properties": {"accountName": f"u{i}"}} for i in range(8)]
    r = risk.compute(_inc(tactics=["InitialAccess", "Execution", "Exfiltration", "Impact"], title="Ransomware detected"), ents)
    assert r.score == 10.0 and r.band == "Critical"


def test_low_informational():
    r = risk.compute(_inc(sev="Informational", alerts=1), [])
    assert r.score < 4 and r.band == "Low"


def test_bands():
    assert risk.band_for(3.9)[0] == "Low"
    assert risk.band_for(4.0)[0] == "Medium"
    assert risk.band_for(7.0)[0] == "High"
    assert risk.band_for(9.0)[0] == "Critical"
    assert risk.band_for(10.0)[0] == "Critical"


def test_false_positive_discount():
    base = risk.compute(_inc(), [])
    fp = risk.compute(_inc(classification="FalsePositive"), [])
    assert fp.score == round(base.score * 0.2, 1)
    assert "False Positive" in fp.modifier


def test_estimated_when_entities_missing():
    assert risk.compute(_inc(), None).estimated is True
    assert risk.compute(_inc(), []).estimated is False


def test_components_sum_matches_score():
    r = risk.compute(_inc(sev="Medium", alerts=6, tactics=["Discovery"]), [{"kind": "Host", "properties": {"hostName": "a"}}])
    assert round(sum(c["points"] for c in r.components), 1) == r.score
