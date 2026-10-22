"""Azure Resource Manager and Microsoft Sentinel REST API client (delegated user token)."""
import logging
import re
import time
import uuid

import requests

log = logging.getLogger(__name__)

ARM = "https://management.azure.com"
SENTINEL_API = "2023-02-01"
WORKSPACE_API = "2022-10-01"
SUBSCRIPTION_API = "2022-12-01"
LOGIC_API = "2016-06-01"

_GUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_WORKSPACE_RE = re.compile(
    rf"^/subscriptions/{_GUID}/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/workspaces/[^/]+$", re.I)
_INCIDENT_RE = re.compile(
    rf"^/subscriptions/{_GUID}/resourceGroups/[^/]+/providers/Microsoft\.OperationalInsights/workspaces/[^/]+"
    r"/providers/Microsoft\.SecurityInsights/incidents/[\w\-]+$", re.I)
_WORKFLOW_RE = re.compile(
    rf"^/subscriptions/{_GUID}/resourceGroups/[^/]+/providers/Microsoft\.Logic/workflows/[^/]+$", re.I)


class AzureError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _friendly(status: int, message: str) -> str:
    hints = {
        401: "Azure rejected the token (expired or wrong audience). Sign out and sign in again.",
        403: "Azure RBAC denied access. Your account needs the right role "
             "(Reader to list, Microsoft Sentinel Responder to comment, Logic App Contributor to run Logic Apps).",
        404: "Resource not found. Check the subscription, resource group and workspace settings.",
    }
    base = hints.get(status, f"Azure returned HTTP {status}.")
    return f"{base} Details: {message}" if message else base


def _request(method: str, url: str, token: str, *, params: dict | None = None,
             json_body: dict | None = None, timeout: int = 30) -> dict:
    if not url.startswith(ARM + "/"):
        raise AzureError("Refusing to call a non-ARM URL.")
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    last: AzureError | None = None
    for attempt in range(3):
        try:
            resp = requests.request(method, url, headers=headers, params=params, json=json_body, timeout=timeout)
        except requests.RequestException as exc:
            last = AzureError(f"Network error calling Azure: {exc}")
            time.sleep(1.5 * (attempt + 1))
            continue
        if resp.status_code in (429, 500, 502, 503, 504) and attempt < 2:
            try:
                wait = min(int(resp.headers.get("Retry-After", 2 * (attempt + 1))), 10)
            except ValueError:
                wait = 2
            time.sleep(wait)
            continue
        if resp.status_code >= 400:
            try:
                msg = resp.json().get("error", {}).get("message", "")
            except ValueError:
                msg = resp.text[:200]
            raise AzureError(_friendly(resp.status_code, msg), resp.status_code)
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return {}
    raise last or AzureError("Azure request failed.")


def _get_all(url: str, token: str, params: dict | None = None, max_items: int = 1000) -> list[dict]:
    items: list[dict] = []
    next_url: str | None = url
    while next_url and len(items) < max_items:
        data = _request("GET", next_url, token, params=params)
        items.extend(data.get("value", []))
        next_url, params = data.get("nextLink"), None
    return items[:max_items]


# ---- validation ----
def is_incident_id(value: str) -> bool:
    return bool(value and _INCIDENT_RE.match(value))


def _check(pattern: re.Pattern, value: str, what: str) -> str:
    if not value or not pattern.match(value):
        raise AzureError(f"Invalid {what} resource id.")
    return value


# ---- discovery ----
def list_subscriptions(token: str) -> list[dict]:
    items = _get_all(f"{ARM}/subscriptions", token, {"api-version": SUBSCRIPTION_API})
    return [{"id": s["subscriptionId"], "name": s.get("displayName", ""), "state": s.get("state", "")} for s in items]


def list_workspaces(token: str, subscription_id: str) -> list[dict]:
    items = _get_all(f"{ARM}/subscriptions/{subscription_id}/providers/Microsoft.OperationalInsights/workspaces",
                     token, {"api-version": WORKSPACE_API})
    out = []
    for w in items:
        parts = w["id"].split("/")
        out.append({
            "arm_id": w["id"], "name": w["name"], "resource_group": parts[4] if len(parts) > 4 else "",
            "location": w.get("location", ""), "customer_id": w.get("properties", {}).get("customerId", ""),
        })
    return out


def workspace_arm_id(subscription_id: str, resource_group: str, workspace_name: str) -> str:
    return (f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}")


# ---- Sentinel incidents ----
def list_incidents(token: str, workspace_arm: str, *, since_iso: str | None = None,
                   statuses: tuple[str, ...] = (), severities: tuple[str, ...] = (),
                   max_items: int = 500, number: int | None = None) -> list[dict]:
    _check(_WORKSPACE_RE, workspace_arm, "workspace")
    filters = []
    if number is not None:
        filters.append(f"properties/incidentNumber eq {int(number)}")
    if since_iso:
        filters.append(f"properties/createdTimeUtc ge {since_iso}")
    if statuses:
        filters.append("(" + " or ".join(f"properties/status eq '{s}'" for s in statuses) + ")")
    if severities:
        filters.append("(" + " or ".join(f"properties/severity eq '{s}'" for s in severities) + ")")
    params = {"api-version": SENTINEL_API, "$orderby": "properties/createdTimeUtc desc", "$top": 100}
    if filters:
        params["$filter"] = " and ".join(filters)
    return _get_all(f"{ARM}{workspace_arm}/providers/Microsoft.SecurityInsights/incidents", token, params, max_items)


def get_incident(token: str, incident_arm_id: str) -> dict:
    _check(_INCIDENT_RE, incident_arm_id, "incident")
    return _request("GET", f"{ARM}{incident_arm_id}", token, params={"api-version": SENTINEL_API})


def get_incident_alerts(token: str, incident_arm_id: str) -> list[dict]:
    _check(_INCIDENT_RE, incident_arm_id, "incident")
    return _request("POST", f"{ARM}{incident_arm_id}/alerts", token,
                    params={"api-version": SENTINEL_API}, json_body={}).get("value", [])


def get_incident_entities(token: str, incident_arm_id: str) -> list[dict]:
    _check(_INCIDENT_RE, incident_arm_id, "incident")
    return _request("POST", f"{ARM}{incident_arm_id}/entities", token,
                    params={"api-version": SENTINEL_API}, json_body={}).get("entities", [])


def get_incident_comments(token: str, incident_arm_id: str) -> list[dict]:
    _check(_INCIDENT_RE, incident_arm_id, "incident")
    return _get_all(f"{ARM}{incident_arm_id}/comments", token, {"api-version": SENTINEL_API}, 200)


def add_incident_comment(token: str, incident_arm_id: str, message: str) -> dict:
    """Needs the Microsoft Sentinel Responder role on the workspace."""
    _check(_INCIDENT_RE, incident_arm_id, "incident")
    if not message.strip():
        raise AzureError("Comment is empty.")
    cid = str(uuid.uuid4())
    return _request("PUT", f"{ARM}{incident_arm_id}/comments/{cid}", token,
                    params={"api-version": SENTINEL_API},
                    json_body={"properties": {"message": message[:30000]}})


# ---- Logic Apps ----
def list_logic_apps(token: str, subscription_id: str) -> list[dict]:
    items = _get_all(f"{ARM}/subscriptions/{subscription_id}/providers/Microsoft.Logic/workflows",
                     token, {"api-version": LOGIC_API})
    return [{"id": w["id"], "name": w["name"], "state": w.get("properties", {}).get("state", ""),
             "location": w.get("location", "")} for w in items]


def get_callback_url(token: str, workflow_id: str, trigger_name: str) -> str:
    _check(_WORKFLOW_RE, workflow_id, "Logic App")
    if not re.fullmatch(r"[\w\-]+", trigger_name or ""):
        raise AzureError("Invalid trigger name.")
    data = _request("POST", f"{ARM}{workflow_id}/triggers/{trigger_name}/listCallbackUrl", token,
                    params={"api-version": LOGIC_API}, json_body={})
    url = data.get("value", "")
    if not url:
        raise AzureError("Azure did not return a callback URL for this trigger.")
    return url


def latest_run_status(token: str, workflow_id: str) -> dict:
    _check(_WORKFLOW_RE, workflow_id, "Logic App")
    runs = _request("GET", f"{ARM}{workflow_id}/runs", token,
                    params={"api-version": LOGIC_API, "$top": 1}).get("value", [])
    if not runs:
        return {}
    p = runs[0].get("properties", {})
    return {"status": p.get("status"), "start": p.get("startTime"), "end": p.get("endTime"),
            "code": p.get("code")}
