"""Containment through Logic Apps, with safety checks and audit trail."""
import fnmatch
import json
import logging
import os
import re
import time

import requests

from src.core import constants
from src.core.database import connect, utcnow
from src.services import arm, audit, investigation, rbac, settings

log = logging.getLogger(__name__)
_PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_.]+)\s*\}\}")
SNIPPET = 500


# ---- action catalogue ----
def list_actions(enabled_only: bool = False) -> list[dict]:
    with connect() as con:
        q = "SELECT * FROM containment_actions" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY label"
        return [dict(r) for r in con.execute(q)]


def get_action(key: str) -> dict | None:
    with connect() as con:
        row = con.execute("SELECT * FROM containment_actions WHERE key = ?", (key,)).fetchone()
    return dict(row) if row else None


def save_action(data: dict) -> None:
    key = (data.get("key") or "").strip()
    if not re.fullmatch(r"[a-z0-9_]{3,40}", key):
        raise ValueError("Key must be 3 to 40 characters: lowercase letters, digits and underscores.")
    if data["source"] not in ("env", "arm"):
        raise ValueError("Source must be 'env' or 'arm'.")
    if data["source"] == "env" and not re.fullmatch(r"[A-Z][A-Z0-9_]{2,60}", data.get("url_env") or ""):
        raise ValueError("Environment variable name must be UPPER_SNAKE_CASE, for example LOGICAPP_ISOLATE_URL.")
    if data["source"] == "arm" and not data.get("workflow_id"):
        raise ValueError("Logic App resource id is required for Azure-discovered actions.")
    problems = validate_template(data["payload_template"])
    if problems["error"]:
        raise ValueError(problems["error"])
    now = utcnow()
    with connect(write=True) as con:
        con.execute(
            """INSERT INTO containment_actions
               (key, label, description, source, url_env, workflow_id, trigger_name, payload_template, risk_level, enabled, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET label=excluded.label, description=excluded.description,
                 source=excluded.source, url_env=excluded.url_env, workflow_id=excluded.workflow_id,
                 trigger_name=excluded.trigger_name, payload_template=excluded.payload_template,
                 risk_level=excluded.risk_level, enabled=excluded.enabled, updated_at=excluded.updated_at""",
            (key, data["label"], data.get("description", ""), data["source"], data.get("url_env") or None,
             data.get("workflow_id") or None, data.get("trigger_name") or "When_an_HTTP_request_is_received",
             data["payload_template"], data.get("risk_level", "standard"), 1 if data.get("enabled", True) else 0, now, now),
        )


def delete_action(key: str) -> None:
    with connect(write=True) as con:
        con.execute("DELETE FROM containment_actions WHERE key = ?", (key,))


# ---- payload templating ----
def _lookup(ctx: dict, path: str):
    cur = ctx
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return False, None
    return True, cur


def _render(value, ctx: dict):
    if isinstance(value, dict):
        return {k: _render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_render(v, ctx) for v in value]
    if isinstance(value, str):
        full = _PLACEHOLDER.fullmatch(value.strip())
        if full:  # a lone placeholder keeps its original type (list, int, ...)
            return _lookup(ctx, full.group(1))[1]
        return _PLACEHOLDER.sub(lambda m: str(_lookup(ctx, m.group(1))[1] if _lookup(ctx, m.group(1))[0] else ""), value)
    return value


def render_payload(template: str | dict, ctx: dict) -> dict:
    obj = json.loads(template) if isinstance(template, str) else template
    return _render(obj, ctx)


def validate_template(template: str) -> dict:
    """Return {'error': str|None, 'unknown': [placeholders not supported]}."""
    try:
        obj = json.loads(template)
    except json.JSONDecodeError as exc:
        return {"error": f"Payload template is not valid JSON: {exc}", "unknown": []}
    if not isinstance(obj, dict):
        return {"error": "Payload template must be a JSON object.", "unknown": []}
    found = set(_PLACEHOLDER.findall(template))
    return {"error": None, "unknown": sorted(found - set(constants.PLACEHOLDERS))}


def build_context(incident: dict, entities: list[dict], user_email: str, justification: str) -> dict:
    p = incident.get("properties", {}) or {}
    return {
        "incident": {
            "arm_id": incident.get("id", ""), "name": incident.get("name", ""),
            "number": p.get("incidentNumber"), "title": p.get("title", ""),
            "severity": p.get("severity", ""), "status": p.get("status", ""), "url": p.get("incidentUrl", ""),
        },
        "entities": entities,
        "user": {"email": user_email},
        "justification": justification,
    }


# ---- safety ----
def find_protected(entities: list[dict]) -> list[str]:
    """Return labels of entities that match the protected list (exact or wildcard, case-insensitive)."""
    patterns = [p.lower() for p in settings.get_list("containment.protected_entities")]
    if not patterns:
        return []
    hits = []
    for e in entities:
        ids = investigation.entity_identifiers(e)
        if any(fnmatch.fnmatch(i, pat) for i in ids for pat in patterns):
            hits.append(investigation.entity_label(e) or e.get("name", ""))
    return hits


# ---- execution ----
def _resolve_url(action: dict, arm_token: str | None) -> str:
    if action["source"] == "env":
        url = os.environ.get(action["url_env"] or "", "").strip().strip('"')
        if not url:
            raise RuntimeError(f"Environment variable {action['url_env']} is not set.")
        return url
    if not arm_token:
        raise RuntimeError("An Azure token is required to fetch the Logic App callback URL.")
    return arm.get_callback_url(arm_token, action["workflow_id"], action["trigger_name"])


def run_action(user: rbac.UserCtx, action: dict, incident: dict, entities: list[dict],
               justification: str, arm_token: str | None, comment: bool = False) -> dict:
    """Run a containment action. Always audited; never raises for expected failures."""
    res = {"ok": False, "blocked": False, "message": "", "http_status": None, "comment": ""}
    inc_id = incident.get("id", "")
    base = {"action": action["key"], "incident": inc_id,
            "incident_title": (incident.get("properties") or {}).get("title", ""),
            "entity_count": len(entities), "justification": justification}

    needed = "containment.run_high" if action["risk_level"] == "high" else "containment.run"
    if not user.can(needed):
        res.update(blocked=True, message=f"Your roles do not allow {action['risk_level']} impact actions.")
        audit.log(user.email, "containment", "containment.blocked", inc_id, "denied", {**base, "reason": "permission"})
        return res
    if not action["enabled"]:
        res.update(blocked=True, message="This action is disabled.")
        audit.log(user.email, "containment", "containment.blocked", inc_id, "denied", {**base, "reason": "disabled"})
        return res

    limit = settings.get_int("containment.rate_limit_per_hour", 20)
    if audit.count_recent(user.email, "containment.executed", 60) >= limit:
        res.update(blocked=True, message=f"Rate limit reached ({limit} actions per hour).")
        audit.log(user.email, "containment", "containment.blocked", inc_id, "denied", {**base, "reason": "rate_limit"})
        return res

    protected = find_protected(entities)
    if protected:
        res.update(blocked=True, message="Blocked: protected entity in scope: " + ", ".join(protected))
        audit.log(user.email, "containment", "containment.blocked", inc_id, "denied", {**base, "reason": "protected", "matches": protected})
        return res

    # Audit first: if the audit trail cannot be written, the action does not run.
    audit.log(user.email, "containment", "containment.requested", inc_id, "pending", base, strict=True)

    started = time.time()
    try:
        url = _resolve_url(action, arm_token)
        payload = render_payload(action["payload_template"], build_context(incident, entities, user.email, justification))
        resp = requests.post(url, json=payload, timeout=60, allow_redirects=False)
        res["http_status"] = resp.status_code
        snippet = (resp.text or "")[:SNIPPET]
        res["ok"] = 200 <= resp.status_code < 300
        res["message"] = (f"Logic App accepted the request (HTTP {resp.status_code})." if res["ok"]
                          else f"Logic App returned HTTP {resp.status_code}: {snippet}")
        details = {**base, "http_status": resp.status_code, "response": snippet,
                   "duration_ms": int((time.time() - started) * 1000)}
    except Exception as exc:  # noqa: BLE001
        log.exception("Containment action failed")
        res["message"] = f"Failed to call the Logic App: {exc}"
        details = {**base, "error": str(exc)[:300], "duration_ms": int((time.time() - started) * 1000)}

    audit.log(user.email, "containment", "containment.executed", inc_id, "success" if res["ok"] else "failed", details)

    if comment and arm_token:
        try:
            who = user.email
            arm.add_incident_comment(arm_token, inc_id, (
                f"[Raven Cyber AI] Containment action '{action['label']}' triggered by {who}. "
                f"Result: {'accepted' if res['ok'] else 'failed'}. Justification: {justification}"))
            res["comment"] = "Comment added to the incident."
            audit.log(user.email, "containment", "incident.comment_added", inc_id, "success", {"action": action["key"]})
        except arm.AzureError as exc:
            res["comment"] = f"Could not add the comment: {exc}"
    return res
