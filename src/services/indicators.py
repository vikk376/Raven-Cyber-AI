"""Detect and validate indicators (IP, URL, domain, device) typed in a containment prompt."""
import ipaddress
import re

_URL = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\"']+")
_IPV4 = re.compile(r"\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b")
_DOMAIN = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[\.\]|\.))+[a-z]{2,24}\b")
_HOST_HINT = re.compile(r"(?i)\b(?:isolate|quarantine|contain|device|host|machine|laptop|server|endpoint)\s+([A-Za-z0-9][A-Za-z0-9._-]{1,62})\b")
_REASON = re.compile(r"(?i)\b(?:because(?:\s+of)?|reason[:\s]|justification[:\s]|due to|since)\s*(.+)$")
_ACTION_VERB = re.compile(r"(?i)\b(block|blacklist|ban|deny|sinkhole|isolate|quarantine|disable|suspend|lock|revoke|reset|deactivate)\b")
_ACTION_NOUN = re.compile(r"(?i)\b(ip|ips|address|url|urls|domain|domains|device|devices|host|hosts|machine|laptop|endpoint|user|users|account|password|passwords)\b")
_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+\-]+@(?:[a-z0-9\-]+\.)+[a-z]{2,24}\b")
_RESET = re.compile(r"(?i)\b(reset|password|passwd|credential)")
_INCIDENT = re.compile(r"(?i)\b(?:run|start|open|launch|trigger)\b.{0,30}\bincident (?:playbook|containment)\b|\bcontain (?:the |this )?incident\b")
_STOP = {"the", "this", "that", "it", "is", "to", "and", "a", "an", "of", "for", "on", "in", "as"}


def refang(text: str) -> str:
    return (text or "").replace("[.]", ".").replace("hxxp", "http").replace("hXXp", "http").strip()


def parse_prompt(text: str) -> dict:
    """Return {indicator, type, category, reason}. Empty strings when nothing was found."""
    raw = refang(text or "")
    out = {"indicator": "", "type": "", "category": "", "reason": ""}
    m = _REASON.search(raw)
    if m:
        out["reason"] = m.group(1).strip()
    body = raw[: m.start()] if m else raw
    url = _URL.search(body)
    if url:
        out.update(indicator=url.group(0).rstrip(".,);"), type="url", category="url_block")
        return out
    ip = _IPV4.search(body)
    if ip:
        cand = ip.group(0)
        try:
            ipaddress.ip_address(cand)
            out.update(indicator=cand, type="ip", category="ip_block")
            return out
        except ValueError:
            pass
    for token in re.findall(r"[0-9a-fA-F:]{3,}", body):
        if token.count(":") >= 2:
            try:
                ipaddress.ip_address(token)
                out.update(indicator=token, type="ip", category="ip_block")
                return out
            except ValueError:
                continue
    mail = _EMAIL.search(body)
    if mail:
        out.update(indicator=mail.group(0), type="user", category="password_reset" if _RESET.search(raw) else "user_disable")
        return out
    host = _HOST_HINT.search(body)
    if host and host.group(1).lower() not in _STOP:
        cand = host.group(1)
        if "." not in cand or not _DOMAIN.fullmatch(cand):
            out.update(indicator=cand, type="device", category="device_isolation")
            return out
    dom = _DOMAIN.search(body)
    if dom:
        out.update(indicator=dom.group(0), type="domain", category="domain_block")
    return out


def validate(category: str, value: str) -> tuple[bool, str, str]:
    """Return (ok, normalized_value, error)."""
    v = refang(value)
    if not v:
        return False, "", "Enter the value to act on."
    if len(v) > 500 or any(c in v for c in "\r\n\x00"):
        return False, "", "The value is too long or contains control characters."
    if category == "ip_block":
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                return False, "", "Not a valid IP address or CIDR range."
            if net.prefixlen < (16 if net.version == 4 else 48):
                return False, "", "That range is too large to block from here."
            return True, str(net), ""
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            return False, "", "That address cannot be blocked (loopback, unspecified, multicast or link-local)."
        return True, str(ip), ""
    if category == "url_block":
        if "://" in v:
            if not re.match(r"(?i)^https?://[^\s/]+", v):
                return False, "", "Only http and https URLs are supported."
            return True, v, ""
        if _DOMAIN.fullmatch(v):
            return True, v.lower(), ""
        return False, "", "Enter a URL (https://example.com/path) or a domain (example.com)."
    if category == "domain_block":
        host = re.sub(r"(?i)^https?://", "", v).split("/")[0].split(":")[0].lower()
        if _DOMAIN.fullmatch(host):
            return True, host, ""
        return False, "", "Enter a domain such as example.com."
    if category in ("user_disable", "password_reset"):
        if _EMAIL.fullmatch(v):
            return True, v.lower(), ""
        return False, "", "Enter the user principal name or email, for example alice@corp.com."
    if category == "device_isolation":
        if not _HOSTNAME.match(v):
            return False, "", "Enter a hostname or device id (letters, digits, dot, dash, underscore)."
        return True, v, ""
    return True, v, ""


def parse_action(text: str) -> dict | None:
    """Detect a containment request in a chat sentence such as "block IP 203.0.113.5 because of C2".

    Returns None when it is not a request. Otherwise the parse_prompt result; indicator is empty when the sentence
    names a kind of target ("block this ip") but no value, so the caller can ask for it.
    """
    raw = text or ""
    if _INCIDENT.search(raw):
        m = _REASON.search(raw)
        return {"indicator": "incident", "type": "incident", "category": "incident", "reason": m.group(1).strip() if m else ""}
    if not _ACTION_VERB.search(raw):
        return None
    found = parse_prompt(raw)
    if found["indicator"]:
        verb = _ACTION_VERB.search(raw).group(1).lower()
        if found["category"] == "ip_block" and verb in ("isolate", "quarantine"):
            return None
        return found
    return found if _ACTION_NOUN.search(raw) and len(raw) < 240 else None


# ---------------------------------------------------------------- aliases and extraction
CATEGORY_ALIASES = {
    "ip": "ip_block", "ip_block": "ip_block", "block_ip": "ip_block",
    "url": "url_block", "url_block": "url_block", "block_url": "url_block",
    "domain": "domain_block", "domain_block": "domain_block", "block_domain": "domain_block",
    "device": "device_isolation", "device_isolation": "device_isolation", "isolate": "device_isolation", "host": "device_isolation",
    "user": "user_disable", "user_disable": "user_disable", "disable_user": "user_disable", "disable": "user_disable",
    "password": "password_reset", "password_reset": "password_reset", "reset_password": "password_reset", "reset": "password_reset",
    "custom": "advanced", "custom_action": "advanced", "advanced": "advanced",
}


def normalize_category(name: str) -> str | None:
    """Map free text such as 'Block IP' or 'reset password' to a containment category key."""
    return CATEGORY_ALIASES.get(re.sub(r"[^a-z]+", "_", (name or "").lower()).strip("_"))


_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
_FILE_EXT = {"txt", "csv", "tsv", "json", "md", "log", "pdf", "docx", "doc", "xlsx", "xls", "png", "jpg", "jpeg", "gif", "webp",
             "py", "js", "ts", "html", "css", "xml", "yaml", "yml", "ini", "cfg", "exe", "dll", "bat", "ps1", "sh", "zip",
             "php", "asp", "aspx", "jsp", "tmp", "bak", "sys", "msi", "lnk", "evtx", "pcap", "kql", "sql", "db", "so", "dat", "conf", "local", "internal", "lan"}


def extract_iocs(text: str, limit: int = 50) -> dict[str, list[str]]:
    """Find indicators of compromise in text (defanged forms accepted). Internal (RFC1918) IPs are skipped; file names are not domains."""
    raw = refang(text or "")
    out: dict[str, list[str]] = {"ips": [], "urls": [], "domains": [], "emails": [], "hashes": []}

    def add(key: str, value: str) -> None:
        if value and value not in out[key] and len(out[key]) < limit:
            out[key].append(value)

    for m in _URL.finditer(raw):
        add("urls", m.group(0).rstrip(".,);]"))
    for m in _IPV4.finditer(raw):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or any(ip in n for n in _INTERNAL)):
            add("ips", str(ip))
    for m in _EMAIL.finditer(raw):
        add("emails", m.group(0).lower())
    mail_domains = {e.split("@", 1)[1] for e in out["emails"]}
    url_hosts = {re.sub(r"(?i)^https?://", "", u).split("/")[0].split(":")[0].lower() for u in out["urls"]}
    for m in _DOMAIN.finditer(raw):
        d = m.group(0).lower()
        if d.rsplit(".", 1)[-1] in _FILE_EXT or d in mail_domains or d in url_hosts:
            continue
        try:
            ipaddress.ip_address(d)
            continue
        except ValueError:
            add("domains", d)
    for m in _HASH.finditer(raw):
        add("hashes", m.group(0).lower())
    return out


_COMMENT_WORD = re.compile(r"(?i)\bcomment\b")
_INCIDENT_NO = re.compile(r"(?i)\bincident\s*(?:number|no\.?|id)?\s*#?\s*(\d{1,9})\b|#(\d{1,9})\b")
_QUOTED = re.compile(r"[\"“'](.{3,}?)[\"”']\s*(?:(?:on|to|for)\b|$)")
_TEXT_AFTER = re.compile(r"(?i)^\s*(?:[:\-,]|saying|that says|says|with|text|note|as)?\s*[:\-]?\s*(.*)$")


def parse_comment(text: str) -> dict | None:
    """Detect "comment on incident 123: ..." style requests. Returns {incident, text} or None."""
    raw = (text or "").strip()
    if not _COMMENT_WORD.search(raw) or len(raw) > 4000:
        return None
    m = _INCIDENT_NO.search(raw)
    if not m:
        return None
    number = int(m.group(1) or m.group(2))
    q = _QUOTED.search(raw)
    if q:
        body = q.group(1).strip()
    else:
        tail = _TEXT_AFTER.match(raw[m.end():])
        body = (tail.group(1) if tail else "").strip()
        if not body:  # "comment <text> on incident 12": take what sits between the word comment and the incident
            head = raw[: m.start()]
            c = _COMMENT_WORD.search(head)
            body = re.sub(r"(?i)\s*\b(?:on|to|for|in)\s*$", "", head[c.end():]).strip(" :-,") if c else ""
    return {"incident": number, "text": body}


_WORKFLOW = re.compile(r"(?i)\b(analy[sz]\w*|investigat\w*|enrich\w*|summari[sz]\w*|review|check|look ?up|find|found|if you|then|after that|also|triage|assess)\b")


def is_workflow(text: str) -> bool:
    """True when a sentence asks for several steps (analyse, then block, then comment). Those go to the assistant."""
    raw = text or ""
    m = _REASON.search(raw)
    head = raw[: m.start()] if m else raw  # the reason itself may contain words such as "found"
    return bool(_WORKFLOW.search(head)) or len(head) > 220


def parse_single_action(text: str) -> dict | None:
    """parse_action for one direct command only. Multi-step sentences and sentences without a value go to the assistant."""
    act = parse_action(text)
    if not act or is_workflow(text):
        return None
    if act["category"] != "incident" and not act["indicator"]:
        return None
    if sum(len(v) for v in extract_iocs(text).values()) > 1:
        return None
    return act


def parse_single_comment(text: str) -> dict | None:
    """parse_comment for one direct command ("comment on incident 123: ..."). "Analyse incident 123 and comment" goes to the assistant."""
    cm = parse_comment(text)
    if not cm:
        return None
    m = _INCIDENT_NO.search(text)
    return None if is_workflow(text[: m.end()]) else cm


def is_internal_ip(value: str) -> bool:
    """RFC1918, loopback or link-local. Documentation ranges (203.0.113.0/24 and so on) count as external."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_link_local or any(ip in n for n in _INTERNAL)
