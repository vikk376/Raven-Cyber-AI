"""Containment targets: Logic Apps and generic HTTP APIs, defined by admins and run by analysts.

A target stores a URL, optional headers and a body template. URL and headers are encrypted at rest and are
never shown again or written to the audit log. At run time the analyst supplies the indicator and a
justification; the request is rendered from placeholders, checked and sent.

Placeholders: {{indicator}} {{indicator_type}} {{category}} {{target_name}} {{justification}} {{prompt}}
{{timestamp}} {{user.email}} {{param.<name>}} {{env.CONTAINMENT_<NAME>}}
"""
import fnmatch
import ipaddress
import json
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import requests

from src.core import constants
from src.core.database import connect, utcnow
from src.services import audit, indicators, rbac, secrets, settings
from src.services.containment import _PLACEHOLDER, _lookup, _render

log = logging.getLogger(__name__)
SNIPPET = 500
METHODS = ("POST", "PUT", "PATCH", "GET", "DELETE")
ROOTS = {"indicator", "indicator_type", "category", "target_name", "justification", "prompt", "timestamp",
         "user", "param", "env"}
DEFAULT_LOGICAPP_BODY = json.dumps({
    "indicator": "{{indicator}}", "indicatorType": "{{indicator_type}}", "category": "{{category}}",
    "justification": "{{justification}}", "triggeredBy": "{{user.email}}", "timestamp": "{{timestamp}}",
}, indent=2)
DEFAULT_API_BODY = json.dumps({"value": "{{indicator}}", "reason": "{{justification}}", "requested_by": "{{user.email}}"}, indent=2)
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")


class TargetError(ValueError):
    pass


# ------------------------------------------------------------------ parsing helpers
def parse_headers(text: str) -> dict[str, str]:
    """Accept a JSON object or one 'Name: value' per line."""
    text = (text or "").strip()
    if not text:
        return {}
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise TargetError(f"Headers are not valid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise TargetError("Headers JSON must be an object.")
        pairs = [(str(k), str(v)) for k, v in obj.items()]
    else:
        pairs = []
        for line in text.splitlines():
            if not line.strip() or line.strip().startswith("#"):
                continue
            if ":" not in line:
                raise TargetError(f"Header line needs 'Name: value': {line[:40]}")
            name, value = line.split(":", 1)
            pairs.append((name.strip(), value.strip()))
    out = {}
    for name, value in pairs:
        if not _HEADER_NAME.match(name):
            raise TargetError(f"Invalid header name: {name[:40]}")
        if name.lower() in ("host", "content-length", "transfer-encoding", "connection"):
            raise TargetError(f"Header '{name}' is set automatically and cannot be overridden.")
        if "\r" in value or "\n" in value:
            raise TargetError(f"Header '{name}' contains a line break.")
        out[name] = value
    return out


def _check_placeholders(text: str, what: str) -> None:
    for name in set(_PLACEHOLDER.findall(text or "")):
        root = name.split(".")[0]
        if root not in ROOTS:
            raise TargetError(f"Unknown placeholder {{{{{name}}}}} in {what}.")
        if root == "env" and not re.fullmatch(r"env\.CONTAINMENT_[A-Z0-9_]+", name):
            raise TargetError("Only environment variables that start with CONTAINMENT_ can be used, "
                              f"for example {{{{env.CONTAINMENT_API_KEY}}}} (found {{{{{name}}}}}).")


def allow_private() -> bool:
    return (os.getenv("ALLOW_PRIVATE_TARGETS", "").lower() in ("1", "true", "yes")
            or settings.get("containment.allow_private_targets", "false").lower() == "true")


def validate_url_template(url: str) -> None:
    url = (url or "").strip()
    if not url:
        raise TargetError("URL is required.")
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http"):
        raise TargetError("URL must start with https://")
    if parts.scheme == "http" and not allow_private():
        raise TargetError("Plain http is blocked. Use https (an admin can allow private and http targets for a lab).")
    if not parts.hostname or "{{" in (parts.netloc or ""):
        raise TargetError("The host name must be fixed. Placeholders are allowed only in the path and query.")
    _check_placeholders(url, "the URL")


def _is_bad_ip(ip: ipaddress._BaseAddress, private_ok: bool) -> bool:
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return True  # includes the cloud metadata address 169.254.169.254
    if (ip.is_private or ip.is_loopback) and not private_ok:
        return True
    return False


def _resolve(host: str, port: int) -> list[str]:
    return [i[4][0] for i in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)]


def check_destination(url: str) -> None:
    """Block requests to internal networks (SSRF guard). Raises TargetError."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    private_ok = allow_private()
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ips = [ipaddress.ip_address(a) for a in _resolve(host, port)]
        except OSError as exc:
            raise TargetError(f"Cannot resolve {host}: {exc}") from exc
    for ip in ips:
        if _is_bad_ip(ip, private_ok):
            raise TargetError(f"Blocked: {host} resolves to a non-public address ({ip}).")


# ------------------------------------------------------------------ CRUD
def _row_to_public(row) -> dict:
    d = dict(row)
    try:
        host = urlsplit(secrets.decrypt(d["url_enc"])).hostname or ""
    except ValueError:
        host = "(cannot decrypt)"
    d["host"] = host
    d["has_headers"] = bool(d.get("headers_enc"))
    d.pop("url_enc", None)
    d.pop("headers_enc", None)
    return d


def list_targets(category: str | None = None, enabled_only: bool = False) -> list[dict]:
    q, args = "SELECT * FROM containment_targets", []
    clauses = []
    if category:
        clauses.append("category = ?"); args.append(category)
    if enabled_only:
        clauses.append("enabled = 1")
    if clauses:
        q += " WHERE " + " AND ".join(clauses)
    with connect() as con:
        return [_row_to_public(r) for r in con.execute(q + " ORDER BY name", args)]


def get_target(target_id: int, secrets_included: bool = False) -> dict | None:
    with connect() as con:
        row = con.execute("SELECT * FROM containment_targets WHERE id = ?", (target_id,)).fetchone()
    if not row:
        return None
    if not secrets_included:
        return _row_to_public(row)
    d = dict(row)
    d["url"] = secrets.decrypt(d.pop("url_enc"))
    d["headers"] = json.loads(secrets.decrypt(d["headers_enc"])) if d.get("headers_enc") else {}
    d.pop("headers_enc", None)
    return d


def save_target(data: dict, actor: str) -> int:
    """Create or update. Blank url/headers on update keep the stored values."""
    name = (data.get("name") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{2,59}", name):
        raise TargetError("Name must be 3 to 60 characters (letters, digits, space, dot, dash, underscore).")
    kind, category = data.get("kind"), data.get("category")
    if kind not in ("logicapp", "api"):
        raise TargetError("Kind must be Logic App or API.")
    if category not in constants.TARGET_CATEGORIES:
        raise TargetError("Choose a category.")
    method = (data.get("method") or "POST").upper()
    if kind == "logicapp":
        method = "POST"
    if method not in METHODS:
        raise TargetError("Unsupported HTTP method.")
    body_format = data.get("body_format", "json")
    body = data.get("body_template") or ""
    if body_format == "json" and body.strip():
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise TargetError(f"Body is not valid JSON: {exc}") from exc
        if not isinstance(parsed, (dict, list)):
            raise TargetError("JSON body must be an object or a list.")
    _check_placeholders(body, "the body")

    existing = get_target(data["id"], secrets_included=True) if data.get("id") else None
    url = (data.get("url") or "").strip() or (existing["url"] if existing else "")
    validate_url_template(url)
    if (data.get("headers") or "").strip():
        headers = parse_headers(data["headers"])
    else:
        headers = existing["headers"] if existing else {}
    for k, v in headers.items():
        _check_placeholders(v, f"header {k}")
    now = utcnow()
    values = (name, kind, category, data.get("description", ""), secrets.encrypt(url), method,
              secrets.encrypt(json.dumps(headers)) if headers else None, body_format, body,
              data.get("risk_level", "standard"), 1 if data.get("enabled", True) else 0)
    try:
        with connect(write=True) as con:
            if existing:
                con.execute(
                    """UPDATE containment_targets SET name=?, kind=?, category=?, description=?, url_enc=?, method=?,
                       headers_enc=?, body_format=?, body_template=?, risk_level=?, enabled=?, updated_at=? WHERE id=?""",
                    (*values, now, existing["id"]))
                return existing["id"]
            return con.execute(
                """INSERT INTO containment_targets (name, kind, category, description, url_enc, method, headers_enc,
                   body_format, body_template, risk_level, enabled, created_by, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (*values, actor, now, now)).lastrowid
    except Exception as exc:  # noqa: BLE001
        if "UNIQUE" in str(exc):
            raise TargetError("A target with this name already exists.") from exc
        raise


def delete_target(target_id: int) -> None:
    with connect(write=True) as con:
        con.execute("DELETE FROM containment_targets WHERE id = ?", (target_id,))


# ------------------------------------------------------------------ rendering and safety
def build_context(user_email: str, target: dict, indicator: str, indicator_type: str, justification: str,
                  prompt: str = "", params: dict | None = None) -> dict:
    return {
        "indicator": indicator, "indicator_type": indicator_type, "category": target["category"],
        "target_name": target["name"], "justification": justification, "prompt": prompt,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user": {"email": user_email}, "param": params or {},
        "env": {k: v for k, v in os.environ.items() if k.startswith("CONTAINMENT_")},
    }


def _sub(text: str, ctx: dict, quote_values: bool = False) -> str:
    def repl(m):
        found, val = _lookup(ctx, m.group(1))
        s = str(val) if found and val is not None else ""
        return quote(s, safe="") if quote_values else s
    return _PLACEHOLDER.sub(repl, text)


def render_request(target: dict, ctx: dict) -> dict:
    """target must include url, headers (secrets_included=True). Returns method, url, headers, json/data."""
    url = _sub(target["url"], ctx, quote_values=True)
    headers = {k: _sub(v, ctx) for k, v in (target.get("headers") or {}).items()}
    for k, v in headers.items():
        if "\r" in v or "\n" in v:
            raise TargetError(f"Header '{k}' contains a line break after substitution.")
    req = {"method": target["method"], "url": url, "headers": headers, "json": None, "data": None}
    body = target.get("body_template") or ""
    if body.strip() and target["method"] != "GET":
        if target["body_format"] == "json":
            req["json"] = _render(json.loads(body), ctx)
        else:
            req["data"] = _sub(body, ctx).encode()
    return req


def preview(target: dict, ctx: dict) -> dict:
    """Safe preview for the UI: host only, header names only (values hidden)."""
    req = render_request(target, ctx)
    parts = urlsplit(req["url"])
    return {"method": req["method"], "host": parts.hostname, "path": parts.path or "/",
            "has_query": bool(parts.query), "headers": sorted(req["headers"]), "body": req["json"] if req["json"] is not None else (req["data"] or b"").decode(errors="replace")}


def is_protected(value: str) -> bool:
    patterns = [p.lower() for p in settings.get_list("containment.protected_entities")]
    v = (value or "").lower()
    host = (urlsplit(v).hostname or v) if "://" in v else v
    return any(fnmatch.fnmatch(x, pat) for x in {v, host} for pat in patterns)


# ------------------------------------------------------------------ execution
def _send_request(t: dict, ctx: dict):
    """Render, validate the destination and send. Raises TargetError or requests exceptions."""
    req = render_request(t, ctx)
    validate_url_template(req["url"])
    check_destination(req["url"])
    return requests.request(req["method"], req["url"], headers=req["headers"], json=req["json"], data=req["data"],
                            timeout=30, allow_redirects=False)


def run_enrichment(user: rbac.UserCtx, target_id: int, indicator: str) -> dict:
    """Look an indicator up in an enrichment tool (threat intelligence API). Audited; read-only by convention."""
    res = {"ok": False, "message": "", "http_status": None, "data": None, "text": ""}
    t = get_target(target_id, secrets_included=True)
    if not t or t["category"] != "enrichment":
        res["message"] = "Enrichment tool not found."
        return res
    if not user.can("investigation.view"):
        res["message"] = "Your roles do not allow lookups."
        return res
    if not t["enabled"]:
        res["message"] = "This tool is disabled."
        return res
    ok, value, err = indicators.validate("enrichment", indicator)
    if not ok:
        res["message"] = err
        return res
    if audit.count_recent(user.email, "enrichment.executed", 60) >= 120:
        res["message"] = "Lookup limit reached (120 per hour)."
        return res
    base = {"tool": t["name"], "indicator": value}
    started = time.time()
    try:
        ctx = build_context(user.email, t, value, "value", "", "", None)
        resp = _send_request(t, ctx)
        res["http_status"] = resp.status_code
        res["ok"] = 200 <= resp.status_code < 300
        text = (resp.text or "")[:6000]
        res["text"] = text
        try:
            res["data"] = resp.json()
        except ValueError:
            res["data"] = None
        res["message"] = f"{t['name']} answered (HTTP {resp.status_code})." if res["ok"] else f"{t['name']} returned HTTP {resp.status_code}."
        details = {**base, "http_status": resp.status_code, "duration_ms": int((time.time() - started) * 1000)}
    except (TargetError, requests.RequestException, ValueError) as exc:
        res["message"] = f"Lookup failed: {exc}"
        details = {**base, "error": str(exc)[:300]}
    audit.log(user.email, "investigation", "enrichment.executed", t["name"], "success" if res["ok"] else "failed", details)
    return res


def run_target(user: rbac.UserCtx, target_id: int, indicator: str, justification: str, prompt: str = "",
               params: dict | None = None) -> dict:
    """Run a target. Always audited. Never raises for expected failures."""
    res = {"ok": False, "blocked": False, "message": "", "http_status": None}
    t = get_target(target_id, secrets_included=True) if target_id else None
    if not t:
        res.update(blocked=True, message="Target not found.")
        return res
    category = t["category"]
    base = {"target": t["name"], "kind": t["kind"], "category": category, "justification": justification}

    needed = "containment.run_high" if t["risk_level"] == "high" else "containment.run"
    if not user.can(needed):
        res.update(blocked=True, message=f"Your roles do not allow {t['risk_level']} impact actions.")
        audit.log(user.email, "containment", "containment.blocked", t["name"], "denied", {**base, "reason": "permission"})
        return res
    if not t["enabled"]:
        res.update(blocked=True, message="This target is disabled.")
        audit.log(user.email, "containment", "containment.blocked", t["name"], "denied", {**base, "reason": "disabled"})
        return res
    if len((justification or "").strip()) < 10:
        res.update(blocked=True, message="A justification of at least 10 characters is required.")
        return res
    ok, value, err = indicators.validate(category, indicator)
    if not ok:
        res.update(blocked=True, message=err)
        return res
    base.update(indicator=value)
    limit = settings.get_int("containment.rate_limit_per_hour", 20)
    if audit.count_recent(user.email, "containment.executed", 60) >= limit:
        res.update(blocked=True, message=f"Rate limit reached ({limit} actions per hour).")
        audit.log(user.email, "containment", "containment.blocked", t["name"], "denied", {**base, "reason": "rate_limit"})
        return res
    if is_protected(value):
        res.update(blocked=True, message=f"Blocked: {value} matches a protected entity.")
        audit.log(user.email, "containment", "containment.blocked", t["name"], "denied", {**base, "reason": "protected"})
        return res

    itype = {"ip_block": "ip", "url_block": "url" if "://" in value else "domain", "domain_block": "domain", "device_isolation": "device",
             "user_disable": "user", "password_reset": "user"}.get(category, "value")
    audit.log(user.email, "containment", "containment.requested", f"{category}:{value}", "pending", base, strict=True)

    started = time.time()
    try:
        ctx = build_context(user.email, t, value, itype, justification.strip(), prompt, params)
        resp = _send_request(t, ctx)
        res["http_status"] = resp.status_code
        snippet = (resp.text or "")[:SNIPPET]
        res["ok"] = 200 <= resp.status_code < 300
        res["message"] = (f"{t['name']} accepted the request (HTTP {resp.status_code})." if res["ok"]
                          else f"{t['name']} returned HTTP {resp.status_code}: {snippet}")
        details = {**base, "http_status": resp.status_code, "response": snippet,
                   "duration_ms": int((time.time() - started) * 1000)}
    except (TargetError, requests.RequestException, ValueError) as exc:
        res["message"] = f"Request not sent or failed: {exc}"
        details = {**base, "error": str(exc)[:300], "duration_ms": int((time.time() - started) * 1000)}
    except Exception as exc:  # noqa: BLE001
        log.exception("Containment target failed")
        res["message"] = f"Unexpected error: {exc}"
        details = {**base, "error": str(exc)[:300]}
    audit.log(user.email, "containment", "containment.executed", f"{category}:{value}",
              "success" if res["ok"] else "failed", details)
    return res


def history(category: str | None = None, limit: int = 15) -> list[dict]:
    """Recent executed/blocked actions from the audit log, newest first."""
    rows = audit.query(panel="containment", action="containment.", limit=300)
    out = []
    for r in rows:
        if r["action"] not in ("containment.executed", "containment.blocked"):
            continue
        try:
            d = json.loads(r["details"] or "{}")
        except json.JSONDecodeError:
            d = {}
        if "category" not in d:
            continue
        if category and d.get("category") != category:
            continue
        out.append({"Time": r["ts"], "Indicator": d.get("indicator", ""), "Target": d.get("target", ""),
                    "Status": "Executed" if r["action"] == "containment.executed" and r["outcome"] == "success"
                              else ("Failed" if r["action"] == "containment.executed" else "Blocked"),
                    "By": r["actor"], "Reason": d.get("justification", "")[:80]})
        if len(out) >= limit:
            break
    return out
