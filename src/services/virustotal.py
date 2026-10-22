"""VirusTotal v3 lookups (IP, domain, URL, file hash) for the Chat Assistant. Read-only: nothing is submitted for scanning."""
import base64
import ipaddress
import re
import threading
import time
from datetime import datetime, timezone

import requests
from langchain_core.tools import tool

from src.core import config
from src.services import audit, indicators

API = "https://www.virustotal.com/api/v3"
GUI = "https://www.virustotal.com/gui"
_HASH = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")
_DOMAIN = re.compile(r"(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")

_CACHE: dict[str, tuple[float, str]] = {}
_CACHE_TTL = 3600
_lock = threading.Lock()
_last_call = -1e9
_MIN_GAP = 15.5  # the free public key allows 4 requests per minute


class VTError(Exception):
    pass


def configured() -> bool:
    return bool(config.VIRUSTOTAL_API_KEY)


def classify(value: str) -> tuple[str, str]:
    """Return (type, normalised value): ip, domain, url or hash. Raises VTError when it is none of them."""
    v = indicators.refang((value or "").strip().strip("<>\"'"))
    if not v:
        raise VTError("Nothing to look up.")
    if re.match(r"(?i)^https?://", v):
        return "url", v
    try:
        return "ip", str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if _HASH.match(v):
        return "hash", v.lower()
    host = v.lower().rstrip(".")
    if _DOMAIN.match(host):
        return "domain", host
    raise VTError(f"'{value[:80]}' is not an IP, URL, domain or file hash.")


def _endpoint(kind: str, v: str) -> tuple[str, str]:
    if kind == "ip":
        return f"{API}/ip_addresses/{v}", f"{GUI}/ip-address/{v}"
    if kind == "domain":
        return f"{API}/domains/{v}", f"{GUI}/domain/{v}"
    if kind == "hash":
        return f"{API}/files/{v}", f"{GUI}/file/{v}"
    uid = base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")
    return f"{API}/urls/{uid}", f"{GUI}/url/{uid}"


def _throttle() -> None:
    global _last_call
    with _lock:
        wait = _MIN_GAP - (time.monotonic() - _last_call)
        if wait > 0:
            time.sleep(min(wait, _MIN_GAP))
        _last_call = time.monotonic()


def _get(url: str) -> requests.Response:
    _throttle()
    try:
        r = requests.get(url, headers={"x-apikey": config.VIRUSTOTAL_API_KEY, "accept": "application/json"}, timeout=25)
    except requests.RequestException as exc:
        raise VTError(f"Could not reach VirusTotal: {exc.__class__.__name__}") from None
    if r.status_code == 429:
        time.sleep(20)
        _throttle()
        r = requests.get(url, headers={"x-apikey": config.VIRUSTOTAL_API_KEY, "accept": "application/json"}, timeout=25)
    return r


def _ts(v) -> str:
    try:
        return datetime.fromtimestamp(int(v), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OSError):
        return "unknown"


def _verdict(stats: dict) -> str:
    mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
    if mal >= 5:
        return "MALICIOUS"
    if mal >= 1 or sus >= 3:
        return "SUSPICIOUS"
    if mal == 0 and sus == 0 and sum(stats.values()) > 0:
        return "CLEAN (no detections)"
    return "UNKNOWN"


def lookup(value: str) -> dict:
    """Query VirusTotal. Returns a dict with kind, value, found, score fields and a link. Raises VTError."""
    if not configured():
        raise VTError("VIRUSTOTAL_API_KEY is not set in .env, so VirusTotal lookups are disabled.")
    kind, v = classify(value)
    url, link = _endpoint(kind, v)
    r = _get(url)
    if r.status_code == 404:
        return {"kind": kind, "value": v, "found": False, "link": link}
    if r.status_code in (401, 403):
        raise VTError("VirusTotal rejected the API key (401/403). Check VIRUSTOTAL_API_KEY.")
    if r.status_code != 200:
        raise VTError(f"VirusTotal returned HTTP {r.status_code}.")
    a = r.json().get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {}) or {}
    results = a.get("last_analysis_results", {}) or {}
    flagged = sorted(f"{eng}: {res.get('result') or res.get('category')}" for eng, res in results.items()
                     if res.get("category") in ("malicious", "suspicious"))
    out = {"kind": kind, "value": v, "found": True, "link": link, "stats": stats, "verdict": _verdict(stats),
           "engines_total": sum(stats.values()), "flagged": flagged[:12], "reputation": a.get("reputation"),
           "last_analysis": _ts(a.get("last_analysis_date")), "tags": (a.get("tags") or [])[:8],
           "categories": sorted(set((a.get("categories") or {}).values()))[:6]}
    if kind == "ip":
        out.update(owner=a.get("as_owner"), asn=a.get("asn"), country=a.get("country"), network=a.get("network"))
    elif kind == "domain":
        out.update(registrar=a.get("registrar"), created=_ts(a.get("creation_date")) if a.get("creation_date") else None)
    elif kind == "url":
        out.update(title=(a.get("title") or "")[:120], final_url=a.get("last_final_url"), times_submitted=a.get("times_submitted"))
    else:
        out.update(name=(a.get("meaningful_name") or "")[:120], file_type=a.get("type_description"), size=a.get("size"),
                   threat=(a.get("popular_threat_classification") or {}).get("suggested_threat_label"))
    return out


def format_result(d: dict) -> str:
    if not d["found"]:
        return (f"VirusTotal has no record of this {d['kind']} ({d['value']}). That is not proof it is safe, only that nobody "
                f"has submitted it. Link: {d['link']}")
    s = d["stats"]
    lines = [f"VirusTotal result for {d['kind']} {d['value']}",
             f"Verdict: {d['verdict']}",
             f"Detections: {s.get('malicious', 0)} malicious, {s.get('suspicious', 0)} suspicious, {s.get('harmless', 0)} harmless, "
             f"{s.get('undetected', 0)} undetected (of {d['engines_total']} engines)",
             f"Community reputation: {d.get('reputation')}", f"Last analysed: {d['last_analysis']}"]
    for key, label in (("owner", "AS owner"), ("asn", "ASN"), ("country", "Country"), ("network", "Network"), ("registrar", "Registrar"),
                       ("created", "Created"), ("title", "Page title"), ("final_url", "Final URL"), ("name", "File name"),
                       ("file_type", "File type"), ("threat", "Threat label")):
        if d.get(key):
            lines.append(f"{label}: {d[key]}")
    if d.get("categories"):
        lines.append("Categories: " + ", ".join(d["categories"]))
    if d.get("tags"):
        lines.append("Tags: " + ", ".join(d["tags"]))
    if d["flagged"]:
        lines.append("Engines that flagged it: " + "; ".join(d["flagged"]))
    lines.append(f"Full report: {d['link']}")
    return "\n".join(lines)


def make_tool(owner: str):
    @tool
    def virustotal_lookup(indicator: str) -> str:
        """Look up the reputation of ONE public IP address, domain, URL or file hash (MD5, SHA1, SHA256) on VirusTotal.
        Returns the verdict, detection counts, owner or registrar details and a link. Read-only. Call it once per
        indicator, and only for public indicators (never private or internal IPs)."""
        try:
            kind, v = classify(indicator)
            if kind == "ip" and indicators.is_internal_ip(v):
                return f"{v} is an internal or private address. VirusTotal only knows public indicators, so it was not sent."
            key = f"{kind}:{v}"
            hit = _CACHE.get(key)
            if hit and time.time() - hit[0] < _CACHE_TTL:
                return hit[1] + "\n(cached for up to 1 hour)"
            text = format_result(lookup(v))
            _CACHE[key] = (time.time(), text)
            audit.log(owner, "chat", "virustotal.lookup", f"{kind}:{v}"[:200])
            return text
        except VTError as exc:
            audit.log(owner, "chat", "virustotal.lookup", str(indicator)[:200], "failed", {"error": str(exc)[:200]})
            return f"VirusTotal lookup failed: {exc}"
    return virustotal_lookup
