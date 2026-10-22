"""Dashboard metrics computed from Sentinel incident objects."""
import pandas as pd

from src.services import risk

SEVERITY_ORDER = ["Informational", "Low", "Medium", "High"]
SEVERITY_COLORS = {"Informational": "#78909c", "Low": "#2e7d32", "Medium": "#f9a825", "High": "#ef6c00"}
OPEN_STATUSES = ("New", "Active")


def build_frame(incidents: list[dict]) -> pd.DataFrame:
    rows = []
    for inc in incidents:
        p = inc.get("properties", {}) or {}
        add = p.get("additionalData", {}) or {}
        owner = (p.get("owner", {}) or {})
        r = risk.compute(inc, None, None)
        rows.append({
            "id": inc.get("id", ""),
            "number": p.get("incidentNumber"),
            "title": p.get("title", ""),
            "severity": p.get("severity", ""),
            "status": p.get("status", ""),
            "classification": p.get("classification", ""),
            "created": pd.to_datetime(p.get("createdTimeUtc"), utc=True, errors="coerce"),
            "closed": pd.to_datetime(p.get("closedTimeUtc"), utc=True, errors="coerce"),
            "owner": owner.get("assignedTo") or owner.get("userPrincipalName") or "",
            "tactics": ", ".join(add.get("tactics") or []),
            "alerts": add.get("alertsCount") or 0,
            "risk": r.score,
            "band": r.band,
        })
    cols = ["id", "number", "title", "severity", "status", "classification", "created", "closed",
            "owner", "tactics", "alerts", "risk", "band"]
    return pd.DataFrame(rows, columns=cols)


def kpis(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"total": 0, "open": 0, "open_high": 0, "unassigned_open": 0, "mttr_hours": None, "avg_open_risk": None}
    open_df = df[df["status"].isin(OPEN_STATUSES)]
    closed = df[(df["status"] == "Closed") & df["closed"].notna() & df["created"].notna()]
    mttr = None
    if not closed.empty:
        mttr = round(((closed["closed"] - closed["created"]).dt.total_seconds() / 3600).mean(), 1)
    return {
        "total": int(len(df)),
        "open": int(len(open_df)),
        "open_high": int((open_df["severity"] == "High").sum()),
        "unassigned_open": int((open_df["owner"] == "").sum()),
        "mttr_hours": mttr,
        "avg_open_risk": round(float(open_df["risk"].mean()), 1) if not open_df.empty else None,
    }


def daily_trend(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame({"date": [], "Created": [], "Closed": []})
    created = df.dropna(subset=["created"]).groupby(df["created"].dt.date).size().rename("Created")
    closed = df.dropna(subset=["closed"]).groupby(df["closed"].dt.date).size().rename("Closed")
    out = pd.concat([created, closed], axis=1).fillna(0).astype(int).sort_index()
    out.index.name = "date"
    return out.reset_index()


def severity_counts(df: pd.DataFrame) -> pd.DataFrame:
    counts = df["severity"].value_counts() if not df.empty else pd.Series(dtype=int)
    return pd.DataFrame({"severity": SEVERITY_ORDER, "count": [int(counts.get(s, 0)) for s in SEVERITY_ORDER]})


def tactic_counts(df: pd.DataFrame, top: int = 10) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame({"tactic": [], "count": []})
    series = df["tactics"].str.split(", ").explode()
    series = series[series.fillna("") != ""]
    vc = series.value_counts().head(top)
    return pd.DataFrame({"tactic": vc.index.tolist(), "count": vc.values.tolist()})
