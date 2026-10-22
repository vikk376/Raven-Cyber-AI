"""Assistant tool: read one Sentinel incident by number with the signed-in user's own Azure token."""
from datetime import datetime, timedelta, timezone

from langchain_core.tools import tool

from src.core import config
from src.services import arm, auth, indicators, settings


def find_incident(token: str, workspace_arm: str, number: int) -> dict | None:
    """Look an incident up by its number. Tries a server-side filter, then scans the last 365 days."""
    def pick(items):
        return next((i for i in items if i.get("properties", {}).get("incidentNumber") == number), None)

    try:
        hit = pick(arm.list_incidents(token, workspace_arm, number=number, max_items=5))
        if hit:
            return hit
    except arm.AzureError:
        pass  # filter not supported on this API version: fall back to scanning
    since = (datetime.now(timezone.utc) - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return pick(arm.list_incidents(token, workspace_arm, since_iso=since, max_items=5000))


def _entity_lines(entities: list[dict]) -> tuple[list[str], list[str]]:
    lines, public_ips = [], []
    for e in entities:
        p, kind = e.get("properties", {}), e.get("kind", "")
        if kind == "Ip" and p.get("address"):
            internal = indicators.is_internal_ip(p["address"])
            lines.append(f"IP {p['address']} ({'internal, do not block' if internal else 'public'})")
            if not internal:
                public_ips.append(p["address"])
        elif kind == "Host":
            lines.append(f"Host {p.get('hostName') or p.get('friendlyName', '')}")
        elif kind == "Account":
            lines.append(f"Account {p.get('accountName', '')}@{p.get('upnSuffix', '')}".rstrip("@"))
        elif kind == "Url":
            lines.append(f"URL {p.get('url', '')}")
        elif kind == "DnsResolution":
            lines.append(f"Domain {p.get('domainName', '')}")
        elif kind == "FileHash":
            lines.append(f"Hash {p.get('hashValue', '')}")
    return lines[:60], public_ips


def make_tool(owner: str):
    @tool
    def get_incident_details(incident_number: int) -> str:
        """Read a Microsoft Sentinel incident by its number: title, severity, status, description, tactics, alerts and
        entities (IPs flagged public or internal, hosts, accounts, URLs, domains, hashes). Use it before proposing
        containment or a comment for an incident."""
        cfg = {k: settings.get(f"sentinel.{k}") for k in ("subscription_id", "resource_group", "workspace_name")}
        if not all(cfg.values()):
            return "The Sentinel workspace is not configured. An admin must set it in Admin > Sentinel workspace."
        token, err = auth.acquire(owner, config.ARM_SCOPE)
        if not token:
            return f"No Azure token for this user. Sign out and in again. {err or ''}"
        try:
            ws = arm.workspace_arm_id(cfg["subscription_id"], cfg["resource_group"], cfg["workspace_name"])
            inc = find_incident(token, ws, int(incident_number))
            if not inc:
                return f"Incident {incident_number} was not found in this workspace (searched the last 365 days)."
            p = inc["properties"]
            try:
                alerts = arm.get_incident_alerts(token, inc["id"])
            except arm.AzureError:
                alerts = []
            try:
                entities = arm.get_incident_entities(token, inc["id"])
            except arm.AzureError:
                entities = []
        except arm.AzureError as exc:
            return f"Azure error: {exc}"
        lines, public_ips = _entity_lines(entities)
        alert_lines = [f"- {a['properties'].get('alertDisplayName', '')} ({a['properties'].get('severity', '')})" for a in alerts[:15]]
        desc = (p.get("description") or "")[:1500]
        found = indicators.extract_iocs(desc + " " + " ".join(alert_lines))
        return ("<incident_data untrusted=\"true\">\n"
                f"Incident #{p.get('incidentNumber')}: {p.get('title', '')}\nSeverity: {p.get('severity', '')}  Status: {p.get('status', '')}  "
                f"Created: {p.get('createdTimeUtc', '')}\nTactics: {', '.join(p.get('additionalData', {}).get('tactics', []))}\n"
                f"Description: {desc}\nAlerts ({len(alerts)}):\n" + ("\n".join(alert_lines) or "none")
                + "\nEntities:\n" + ("\n".join(lines) or "none")
                + f"\nPublic IPs from entities: {', '.join(public_ips) or 'none'}"
                + (f"\nOther indicators in text: {found}" if any(found.values()) else "")
                + "\n</incident_data>")

    return get_incident_details
