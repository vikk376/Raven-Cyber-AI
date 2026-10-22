"""Deterministic, explainable incident risk score out of 10.

The score is computed from evidence in the incident, never from a language model.
Component maxima: severity 4 + alert volume 1.5 + attack stage 2 + entity exposure 1.5
+ compromise signals 1 = 10. Entity history (see correlation.py) can add up to 1 more point; the total stays capped at 10.
"""
from dataclasses import dataclass, field

BANDS = (
    (4.0, "Low", "#2e7d32"),
    (7.0, "Medium", "#f9a825"),
    (9.0, "High", "#ef6c00"),
    (10.01, "Critical", "#c62828"),
)
BAND_EMOJI = {"Low": "🟢", "Medium": "🟡", "High": "🟠", "Critical": "🔴"}

LATE_STAGE = {"credentialaccess", "lateralmovement", "collection", "exfiltration",
              "commandandcontrol", "impact", "privilegeescalation"}
STRONG_KEYWORDS = ("ransomware", "exfiltrat", "credential dump", "mimikatz", "command and control", "c2 ",
                   "malware", "compromised", "data theft", "backdoor", "webshell", "cobalt strike", "lateral movement")
MODERATE_KEYWORDS = ("suspicious", "anomalous", "brute force", "password spray", "phishing", "impossible travel",
                     "unusual", "malicious", "privilege", "persistence")


@dataclass
class RiskResult:
    score: float
    band: str
    color: str
    components: list[dict] = field(default_factory=list)
    modifier: str = ""
    estimated: bool = False

    @property
    def emoji(self) -> str:
        return BAND_EMOJI.get(self.band, "")

    @property
    def label(self) -> str:
        return f"{self.score:.1f} / 10 ({self.band})"


def band_for(score: float) -> tuple[str, str]:
    for limit, label, color in BANDS:
        if score < limit:
            return label, color
    return BANDS[-1][1], BANDS[-1][2]


def _norm(tactic: str) -> str:
    return "".join(ch for ch in str(tactic).lower() if ch.isalnum())


def _entity_key(entity: dict) -> str:
    p = entity.get("properties", {}) or {}
    ident = (p.get("friendlyName") or p.get("accountName") or p.get("hostName") or p.get("address")
             or p.get("fileName") or p.get("url") or entity.get("name") or "")
    return f"{entity.get('kind', '')}:{str(ident).lower()}"


def compute(incident: dict, entities: list[dict] | None = None, alerts: list[dict] | None = None,
            history_points: float = 0.0, history_detail: str = "") -> RiskResult:
    props = (incident or {}).get("properties", {}) or {}
    add = props.get("additionalData", {}) or {}
    comps: list[dict] = []

    # 1. Severity (0 to 4)
    sev = str(props.get("severity", "")).lower()
    sev_pts = {"high": 4.0, "medium": 2.5, "low": 1.0, "informational": 0.25}.get(sev, 1.0)
    comps.append({"name": "Severity", "points": sev_pts, "max": 4.0,
                  "detail": f"Incident severity is {props.get('severity', 'unknown')}."})

    # 2. Alert volume (0 to 1.5)
    n_alerts = add.get("alertsCount")
    if n_alerts is None and alerts is not None:
        n_alerts = len(alerts)
    n_alerts = int(n_alerts or 0)
    vol = 0.0 if n_alerts <= 1 else 0.5 if n_alerts < 5 else 1.0 if n_alerts < 10 else 1.5
    comps.append({"name": "Alert volume", "points": vol, "max": 1.5, "detail": f"{n_alerts} alert(s) in the incident."})

    # 3. Attack stage (0 to 2): breadth of tactics + presence of late-stage tactics
    tactics = list(add.get("tactics") or [])
    if not tactics and alerts:
        for a in alerts:
            tactics += (a.get("properties", {}) or {}).get("tactics") or []
    uniq = sorted({_norm(t): t for t in tactics}.items())
    breadth = 0.0 if not uniq else 0.5 if len(uniq) == 1 else 0.75 if len(uniq) < 4 else 1.0
    late = [orig for key, orig in uniq if key in LATE_STAGE]
    stage = breadth + (1.0 if late else 0.0)
    detail = f"{len(uniq)} tactic(s)"
    if late:
        detail += f"; late-stage: {', '.join(late)}"
    comps.append({"name": "Attack stage", "points": stage, "max": 2.0, "detail": detail + "."})

    # 4. Entity exposure (0 to 1.5)
    if entities is None:
        n_ent, ent_detail = 0, "Entities were not loaded, so this component is not included."
    else:
        n_ent = len({_entity_key(e) for e in entities})
        ent_detail = f"{n_ent} distinct entity(ies) involved."
    exp = 0.0 if n_ent == 0 else 0.5 if n_ent <= 2 else 1.0 if n_ent <= 5 else 1.5
    comps.append({"name": "Entity exposure", "points": exp, "max": 1.5, "detail": ent_detail})

    # 5. Compromise signals (0 to 1) from incident and alert text
    text = " ".join([str(props.get("title", "")), str(props.get("description", ""))] +
                    [str((a.get("properties", {}) or {}).get("alertDisplayName", "")) for a in (alerts or [])]).lower()
    strong = [k.strip() for k in STRONG_KEYWORDS if k in text]
    moderate = [k.strip() for k in MODERATE_KEYWORDS if k in text]
    sig = 1.0 if strong else 0.5 if moderate else 0.0
    matched = ", ".join((strong or moderate)[:5]) or "none"
    comps.append({"name": "Compromise signals", "points": sig, "max": 1.0, "detail": f"Keywords matched: {matched}."})

    if history_points > 0:  # entity history uplift, added on top of the 10 point base; the total stays capped at 10
        comps.append({"name": "History and correlation", "points": min(1.0, history_points), "max": 1.0,
                      "detail": history_detail or "Entities seen in earlier incidents."})
    total = min(10.0, sum(c["points"] for c in comps))
    modifier = ""
    cls = str(props.get("classification", "") or "")
    if cls == "FalsePositive":
        total *= 0.2
        modifier = "Classified as False Positive: score multiplied by 0.2."
    elif cls == "BenignPositive":
        total *= 0.5
        modifier = "Classified as Benign Positive: score multiplied by 0.5."
    total = round(total, 1)
    band, color = band_for(total)
    return RiskResult(score=total, band=band, color=color, components=comps, modifier=modifier,
                      estimated=entities is None)
