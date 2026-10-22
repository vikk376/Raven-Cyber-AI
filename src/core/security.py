"""Helpers that keep secrets out of logs and audit records."""
import hashlib
import re
from typing import Any

_SECRET_KEYS = {
    "password", "passwd", "secret", "client_secret", "token", "access_token", "refresh_token",
    "sig", "signature", "authorization", "api_key", "apikey", "sas", "url", "callback_url",
}
_SIG_RE = re.compile(r"(sig=)[^&\s\"']+", re.IGNORECASE)
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def scrub_text(text: str) -> str:
    text = _SIG_RE.sub(r"\1***", text)
    return _BEARER_RE.sub(r"\1***", text)


def scrub(obj: Any) -> Any:
    """Recursively mask secret-looking keys and signatures inside strings."""
    if isinstance(obj, dict):
        return {k: ("***" if str(k).lower() in _SECRET_KEYS else scrub(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub(v) for v in obj]
    if isinstance(obj, str):
        return scrub_text(obj)
    return obj
