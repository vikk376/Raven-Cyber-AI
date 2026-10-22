"""Entity history and correlation: which earlier incidents involve the same accounts, hosts, IPs and URLs.

Works only from Sentinel incident data the signed-in user can already read (REST API, no extra permissions):
list incidents in a time window, load each candidate's entities in parallel, then match them to the current
incident's entities. Matching uses strong identifiers (UPN, AAD object id, host name, IP, URL, domain, file hash).
Process names and bare file names are ignored on purpose because they match too much (cmd.exe, svchost.exe).
"""
import logging
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from src.services import arm, investigation

log = logging.getLogger(__name__)
MARK = "/providers/Microsoft.SecurityInsights"
SEV_ORDER = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}


def workspace_of(incident_arm_id: str) -> str:
    return incident_arm_id.split(MARK)[0]


def entity_keys(e: dict) -> set[str]:
    """Normalised identifiers for matching. Empty set means 'do not correlate on this entity'."""
    p = e.get("properties", {}) or {}
    kind = e.get("kind", "")
    keys: set[str] = set()
    low = lambda v: str(v).strip().lower()  # noqa: E731
    if kind == "Account":
        if p.get("accountName") and p.get("upnSuffix"):
            keys.add(f"account:{low(p['accountName'])}@{low(p['upnSuffix'])}")
        if p.get("aadUserId"):
            keys.add(f"account:aad:{low(p['aadUserId'])}")
        if p.get("objectGuid"):
            keys.add(f"account:guid:{low(p['objectGuid'])}")
        if not keys and p.get("accountName") and p.get("ntDomain"):
            keys.add(f"account:{low(p['ntDomain'])}\\{low(p['accountName'])}")
    elif kind == "Host":
        host = p.get("hostName") or p.get("netBiosName")
        if host:
            keys.add(f"host:{low(host)}")
        if p.get("azureID"):
            keys.add(f"host:azure:{low(p['azureID'])}")
    elif kind == "Ip":
        if p.get("address"):
            keys.add(f"ip:{low(p['address'])}")
    elif kind == "Url":
        url = low(p.get("url", "")).rstrip("/")
        if url:
            keys.add(f"url:{url}")
            host = urlsplit(url if "://" in url else f"//{url}").hostname
            if host:
                keys.add(f"domain:{host}")
    elif kind == "DnsResolution":
        if p.get("domainName"):
            keys.add(f"domain:{low(p['domainName'])}")
    elif kind == "FileHash":
        if p.get("hashValue"):
            keys.add(f"hash:{low(p['hashValue'])}")
    return keys


def _tactics(inc: dict) -> set[str]:
    return set(((inc.get("properties", {}) or {}).get("additionalData", {}) or {}).get("tactics") or [])


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def correlate(token: str, incident: dict, entities: list[dict], *, days: int = 30, max_incidents: int = 60,
              workers: int = 8, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    inc_id = incident.get("id", "")
    cur_tactics = _tactics(incident)

    # current entities -> keys
    cur: list[dict] = []
    for e in entities or []:
        keys = entity_keys(e)
        if keys:
            cur.append({"label": investigation.entity_label(e), "kind": e.get("kind", ""), "keys": keys})
    out = {"days": days, "scanned": 0, "failed": 0, "truncated": False, "entities": [], "related": [],
           "flags": [], "tactics": [], "errors": []}
    if not cur:
        out["errors"].append("No entities with identifiers suitable for correlation.")
        return out

    since = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        listed = arm.list_incidents(token, workspace_of(inc_id), since_iso=since, max_items=500)
    except arm.AzureError as exc:
        out["errors"].append(f"Could not list incidents: {exc}")
        return out
    candidates = [i for i in listed if i.get("id") and i["id"].lower() != inc_id.lower()]
    candidates.sort(key=lambda i: (i.get("properties", {}) or {}).get("createdTimeUtc", ""), reverse=True)
    if len(candidates) > max_incidents:
        out["truncated"] = True
        candidates = candidates[:max_incidents]

    def load(i: dict):
        try:
            return i, arm.get_incident_entities(token, i["id"])
        except Exception as exc:  # noqa: BLE001  (one bad incident must not stop the correlation)
            log.warning("entity load failed for %s: %s", i.get("name"), exc)
            return i, None

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        loaded = list(pool.map(load, candidates))
    out["scanned"] = len(candidates)
    out["failed"] = sum(1 for _, ents in loaded if ents is None)

    per_entity: dict[int, list[dict]] = defaultdict(list)
    related: list[dict] = []
    tactic_counter: Counter = Counter()
    for inc, ents in loaded:
        if not ents:
            continue
        other_keys = [(e, entity_keys(e)) for e in ents]
        shared = []
        for idx, ce in enumerate(cur):
            if any(ce["keys"] & k for _, k in other_keys if k):
                shared.append((idx, ce))
        if not shared:
            continue
        p = inc.get("properties", {}) or {}
        created = _parse(p.get("createdTimeUtc"))
        row = {
            "id": inc["id"], "number": p.get("incidentNumber"), "title": p.get("title", ""),
            "severity": p.get("severity", ""), "status": p.get("status", ""),
            "classification": p.get("classification") or "", "created": p.get("createdTimeUtc", ""),
            "tactics": sorted(_tactics(inc)), "url": p.get("incidentUrl", ""),
            "shared": [ce["label"] for _, ce in shared], "shared_kinds": [ce["kind"] for _, ce in shared],
        }
        age_days = (now - created).days if created else days
        row["score"] = round(len(shared) * 2 + len(_tactics(inc) & cur_tactics)
                             + (1.0 if age_days <= 7 else 0.0) + (1.5 if row["classification"] == "TruePositive" else 0.0), 1)
        related.append(row)
        for idx, _ in shared:
            per_entity[idx].append(row)
        tactic_counter.update(_tactics(inc) & cur_tactics)

    related.sort(key=lambda r: r["score"], reverse=True)
    out["related"] = related
    out["tactics"] = [{"tactic": t, "incidents": n} for t, n in tactic_counter.most_common(8)]

    for idx, ce in enumerate(cur):
        rows = per_entity.get(idx, [])
        cls = Counter(r["classification"] or "Undetermined" for r in rows)
        dates = sorted(r["created"] for r in rows if r["created"])
        sev = max((r["severity"] for r in rows), key=lambda s: SEV_ORDER.get(s, -1), default="")
        flag = ""
        if cls.get("TruePositive"):
            flag = "Previously confirmed malicious"
        elif len(rows) >= 2:
            flag = "Repeat entity"
        elif rows and cls.get("FalsePositive") == len(rows):
            flag = "Earlier incidents were false positives"
        out["entities"].append({
            "entity": ce["label"], "kind": ce["kind"], "incidents": len(rows),
            "first_seen": dates[0] if dates else "", "last_seen": dates[-1] if dates else "",
            "true_positive": cls.get("TruePositive", 0), "false_positive": cls.get("FalsePositive", 0),
            "benign": cls.get("BenignPositive", 0), "undetermined": cls.get("Undetermined", 0),
            "max_severity": sev, "flag": flag, "incident_numbers": [r["number"] for r in rows][:12],
        })
    out["entities"].sort(key=lambda r: (-r["incidents"], r["entity"]))

    repeat = [e for e in out["entities"] if e["incidents"] >= 2]
    tp = [e for e in out["entities"] if e["true_positive"]]
    if tp:
        out["flags"].append("Entities seen in earlier TruePositive incidents: " + ", ".join(e["entity"] for e in tp[:5]) + ".")
    if repeat:
        out["flags"].append(f"{len(repeat)} entity(ies) appear in two or more earlier incidents within {days} days: "
                            + ", ".join(e["entity"] for e in repeat[:5]) + ".")
    if related and not tp and not repeat:
        out["flags"].append(f"{len(related)} earlier incident(s) share at least one entity with this incident.")
    if not related:
        out["flags"].append(f"No other incident in the last {days} days shares an entity with this incident.")
    if out["failed"]:
        out["flags"].append(f"{out['failed']} incident(s) could not be read and were skipped.")
    if out["truncated"]:
        out["flags"].append(f"Only the newest {max_incidents} incidents in the window were checked.")
    return out


def risk_uplift(corr: dict | None) -> tuple[float, str]:
    """Extra points (0 to 1.0) for history. Added on top of the base score, total capped at 10."""
    if not corr or not corr.get("entities"):
        return 0.0, ""
    pts, why = 0.0, []
    if any(e["incidents"] >= 2 for e in corr["entities"]):
        pts += 0.5
        why.append("an entity recurs in 2 or more earlier incidents")
    if any(e["true_positive"] for e in corr["entities"]):
        pts += 0.5
        why.append("an entity was in an earlier TruePositive incident")
    return pts, ("; ".join(why) + f" (last {corr['days']} days).") if why else ""


def summary_lines(corr: dict | None, limit: int = 6) -> list[str]:
    if not corr:
        return []
    lines = list(corr.get("flags", []))
    for r in (corr.get("related") or [])[:limit]:
        lines.append(f"Related #{r['number']} ({r['severity']}, {r['status']}"
                     + (f", {r['classification']}" if r["classification"] else "") + f"): {r['title'][:80]} | shared: "
                     + ", ".join(r["shared"][:4]))
    return lines
