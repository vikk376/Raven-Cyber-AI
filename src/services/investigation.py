"""Collect incident evidence from Sentinel and build the investigation report."""
import json
from datetime import datetime, timezone

from src.services import arm, correlation, risk

SKIP_PROPS = {"additionalData", "friendlyName", "type", "kind"}


# ---- entities ----
def entity_label(e: dict) -> str:
    p = e.get("properties", {}) or {}
    kind = e.get("kind", "")
    if kind == "Account":
        if p.get("accountName") and p.get("upnSuffix"):
            return f"{p['accountName']}@{p['upnSuffix']}"
        return p.get("friendlyName") or p.get("accountName") or e.get("name", "")
    if kind == "Host":
        host = p.get("hostName", "")
        return f"{host}.{p['dnsDomain']}" if host and p.get("dnsDomain") else host or p.get("friendlyName", "")
    if kind == "Ip":
        return p.get("address", "")
    if kind == "Url":
        return p.get("url", "")
    if kind == "File":
        return p.get("fileName", "") or p.get("friendlyName", "")
    if kind == "Process":
        return p.get("commandLine", "") or p.get("friendlyName", "")
    if kind == "MailMessage":
        return p.get("subject", "") or p.get("friendlyName", "")
    return p.get("friendlyName") or e.get("name", "")


def entity_identifiers(e: dict) -> set[str]:
    """Lower-case identifiers used to match the protected-entities list."""
    p = e.get("properties", {}) or {}
    ids = {entity_label(e), p.get("friendlyName"), p.get("accountName"), p.get("hostName"), p.get("address"),
           p.get("url"), p.get("fileName"), p.get("netBiosName"), p.get("aadUserId"), p.get("objectGuid")}
    if p.get("accountName") and p.get("upnSuffix"):
        ids.add(f"{p['accountName']}@{p['upnSuffix']}")
    if p.get("hostName") and p.get("dnsDomain"):
        ids.add(f"{p['hostName']}.{p['dnsDomain']}")
    return {str(i).strip().lower() for i in ids if i}


def summarize_entity(e: dict) -> dict:
    p = e.get("properties", {}) or {}
    extras = {k: v for k, v in p.items() if k not in SKIP_PROPS and isinstance(v, (str, int, float, bool)) and v != ""}
    return {"kind": e.get("kind", ""), "name": entity_label(e), "details": dict(list(extras.items())[:8])}


# ---- collection ----
def collect(token: str, incident_arm_id: str) -> dict:
    """Fetch incident, alerts, entities and comments. Section failures are recorded, not fatal."""
    ctx: dict = {"incident": arm.get_incident(token, incident_arm_id), "errors": {}}
    for key, fn in (("alerts", arm.get_incident_alerts), ("entities", arm.get_incident_entities),
                    ("comments", arm.get_incident_comments)):
        try:
            ctx[key] = fn(token, incident_arm_id)
        except arm.AzureError as exc:
            ctx[key] = None if key == "entities" else []
            ctx["errors"][key] = str(exc)
    return ctx


def add_correlation(ctx: dict, token: str, days: int = 30) -> dict:
    """Look for earlier incidents that share entities with this one. Stores the result in ctx['correlation']."""
    corr = correlation.correlate(token, ctx["incident"], ctx.get("entities") or [], days=days)
    ctx["correlation"] = corr
    for msg in corr.get("errors", []):
        ctx["errors"]["correlation"] = msg
    return corr


def compute_risk(ctx: dict) -> risk.RiskResult:
    pts, why = correlation.risk_uplift(ctx.get("correlation"))
    return risk.compute(ctx["incident"], ctx.get("entities"), ctx.get("alerts"), history_points=pts, history_detail=why)


# ---- helpers ----
def _fmt_ts(value: str | None) -> str:
    if not value:
        return ""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return value


def timeline(ctx: dict) -> list[dict]:
    rows = []
    for a in ctx.get("alerts") or []:
        p = a.get("properties", {}) or {}
        rows.append({
            "time": p.get("timeGenerated") or p.get("startTimeUtc") or "",
            "alert": p.get("alertDisplayName", ""),
            "severity": p.get("severity", ""),
            "product": p.get("productName", ""),
            "tactics": ", ".join(p.get("tactics") or []),
            "description": (p.get("description") or "")[:300],
        })
    return sorted(rows, key=lambda r: r["time"])


def _md_table(headers: list[str], rows: list[list[str]]) -> str:
    esc = lambda s: str(s).replace("|", "\\|").replace("\n", " ")  # noqa: E731
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def build_report(ctx: dict, result: risk.RiskResult, ai_text: str | None = None,
                 enrichment: str | None = None, generated_by: str = "") -> str:
    inc = ctx["incident"]
    p = inc.get("properties", {}) or {}
    add = p.get("additionalData", {}) or {}
    lines = [
        f"# Incident #{p.get('incidentNumber', '?')}: {p.get('title', '')}",
        "",
        f"**Risk score: {result.label}**" + ("  _(estimated: entities not loaded)_" if result.estimated else ""),
        "",
        f"- **Severity:** {p.get('severity', '')}  |  **Status:** {p.get('status', '')}  |  "
        f"**Classification:** {p.get('classification') or 'Not set'}",
        f"- **Created:** {_fmt_ts(p.get('createdTimeUtc'))}  |  **Last modified:** {_fmt_ts(p.get('lastModifiedTimeUtc'))}",
        f"- **Owner:** {(p.get('owner') or {}).get('assignedTo') or 'Unassigned'}",
        f"- **Alerts:** {add.get('alertsCount', 0)}  |  **Tactics:** {', '.join(add.get('tactics') or []) or 'None'}",
        f"- **Products:** {', '.join(add.get('alertProductNames') or []) or 'None'}",
        f"- **Incident ARM id:** `{inc.get('id', '')}`",
    ]
    if p.get("incidentUrl"):
        lines.append(f"- **Portal link:** {p['incidentUrl']}")
    if p.get("description"):
        lines += ["", "## Description", p["description"][:1500]]

    lines += ["", "## Risk score breakdown", _md_table(
        ["Component", "Points", "Max", "Why"],
        [[c["name"], f"{c['points']:.2f}", f"{c['max']:.2f}", c["detail"]] for c in result.components])]
    if result.modifier:
        lines += ["", f"_{result.modifier}_"]

    ents = ctx.get("entities")
    lines += ["", "## Entities"]
    if ents:
        lines.append(_md_table(["Kind", "Entity", "Key details"], [
            [s["kind"], s["name"], "; ".join(f"{k}={v}" for k, v in list(s["details"].items())[:4])]
            for s in map(summarize_entity, ents)]))
    else:
        lines.append("No entities available." if ents is not None else "Entities could not be loaded.")

    corr = ctx.get("correlation")
    if corr:
        lines += ["", f"## Entity history and correlation (last {corr['days']} days)"]
        lines += [f"- {m}" for m in corr.get("flags", [])]
        if corr.get("entities"):
            lines.append(_md_table(["Entity", "Kind", "Earlier incidents", "First seen", "Last seen", "TP", "FP", "Flag"], [
                [e["entity"], e["kind"], e["incidents"], _fmt_ts(e["first_seen"]), _fmt_ts(e["last_seen"]),
                 e["true_positive"], e["false_positive"], e["flag"]] for e in corr["entities"]]))
        if corr.get("related"):
            lines += ["", "**Related incidents**", _md_table(["#", "Title", "Severity", "Status", "Class", "Shared entities"], [
                [r["number"], r["title"][:70], r["severity"], r["status"], r["classification"] or "-", ", ".join(r["shared"][:4])]
                for r in corr["related"][:15]])]

    tl = timeline(ctx)
    lines += ["", "## Alert timeline"]
    if tl:
        lines.append(_md_table(["Time", "Alert", "Severity", "Product", "Tactics"],
                               [[_fmt_ts(r["time"]), r["alert"], r["severity"], r["product"], r["tactics"]] for r in tl]))
    else:
        lines.append("No alerts available.")

    if ai_text:
        lines += ["", "## AI analysis", ai_text.strip()]
    if enrichment:
        lines += ["", "## Sentinel log enrichment (MCP)", enrichment.strip()]
    if ctx.get("errors"):
        lines += ["", "## Data collection notes"] + [f"- {k}: {v}" for k, v in ctx["errors"].items()]
    lines += ["", "---", f"_Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
              + (f" by {generated_by}" if generated_by else "") + "._"]
    return "\n".join(lines)


def comment_text(ctx: dict, result: risk.RiskResult, user_email: str, ai_summary: str | None = None) -> str:
    """Plain-text comment for the Sentinel incident (no markdown)."""
    p = ctx["incident"].get("properties", {}) or {}
    add = p.get("additionalData", {}) or {}
    ents = ctx.get("entities") or []
    lines = [
        "[Raven Cyber AI] Investigation summary",
        f"Risk score: {result.label}",
        f"Investigated by: {user_email} at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "Score breakdown:",
    ] + [f"- {c['name']}: {c['points']:.1f}/{c['max']:.1f} ({c['detail']})" for c in result.components]
    lines += ["", f"Alerts: {add.get('alertsCount', 0)} | Tactics: {', '.join(add.get('tactics') or []) or 'none'}"]
    if ents:
        lines.append("Key entities: " + "; ".join(f"{s['kind']}:{s['name']}" for s in map(summarize_entity, ents[:10])))
    hist = correlation.summary_lines(ctx.get("correlation"), limit=4)
    if hist:
        lines += ["", "Entity history:"] + [f"- {h}" for h in hist]
    if ai_summary:
        lines += ["", "AI summary:", ai_summary.strip()[:1800]]
    return "\n".join(lines)


# ---- AI ----
AI_INSTRUCTIONS = """You are a senior SOC analyst. Using ONLY the evidence below, write an investigation analysis in Markdown with these sections:
## Executive summary
## Attack narrative
## Impact assessment
## MITRE ATT&CK mapping
## Recommended actions (containment, eradication, recovery)
## Open questions
If entity_history is present, say whether the same entities appeared in earlier incidents and what that implies.
Rules: do not invent facts, hosts, users or IPs. If evidence is missing, say what is missing. Be concise and specific. Do not use em dashes."""


def _compact(ctx: dict, result: risk.RiskResult, limit: int = 14000) -> str:
    p = ctx["incident"].get("properties", {}) or {}
    add = p.get("additionalData", {}) or {}
    data = {
        "incident": {k: p.get(k) for k in ("title", "severity", "status", "classification", "description", "createdTimeUtc")},
        "tactics": add.get("tactics"), "techniques": add.get("techniques"), "products": add.get("alertProductNames"),
        "risk": {"score": result.score, "band": result.band, "components": result.components},
        "entities": [summarize_entity(e) for e in (ctx.get("entities") or [])[:40]],
        "alerts": timeline(ctx)[:40],
        "entity_history": correlation.summary_lines(ctx.get("correlation"), limit=8),
    }
    return json.dumps(data, default=str)[:limit]


def ai_analysis(ctx: dict, result: risk.RiskResult) -> str:
    from src.services import agent  # imported lazily: heavy LangChain dependencies

    reply = agent.build_llm().invoke([("system", AI_INSTRUCTIONS), ("human", _compact(ctx, result))])
    return reply.content if isinstance(reply.content, str) else json.dumps(reply.content)


def enrichment_prompt(ctx: dict) -> str:
    p = ctx["incident"].get("properties", {}) or {}
    ents = [summarize_entity(e) for e in (ctx.get("entities") or [])[:15]]
    return (
        "Using the Sentinel tools, enrich this incident with log evidence from the last 7 days. "
        "For the accounts, hosts and IP addresses listed, find sign-in activity, suspicious activity and "
        "related alerts, and summarise concrete findings with counts and timestamps. "
        "Show the KQL you used. Do not send any email.\n\n"
        f"Incident: {p.get('title')} (severity {p.get('severity')}).\n"
        f"Entities: {json.dumps(ents, default=str)}"
    )
