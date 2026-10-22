"""Microsoft Entra delegated sign-in (authorization code flow) using MSAL.

Each user has their own token cache file, so several people can use the platform at once.
The Sentinel MCP server and Azure Resource Manager both require delegated tokens.
"""
import json
import os
import secrets
import time
from dataclasses import dataclass

import msal

from src.core import config, security

STATE_TTL_SECONDS = 600


@dataclass
class LoginOutcome:
    ok: bool
    email: str = ""
    name: str = ""
    error: str = ""


def _authority() -> str:
    return f"https://login.microsoftonline.com/{config.AZURE_TENANT_ID}"


def _cache_path(email: str):
    return config.TOKEN_DIR / f"{security.sha256_hex(email.lower())[:40]}.json"


def _load_cache(email: str | None) -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    if email:
        path = _cache_path(email)
        if path.exists():
            cache.deserialize(path.read_text())
    return cache


def _save_cache(email: str, cache: msal.SerializableTokenCache) -> None:
    if cache.has_state_changed:
        config.TOKEN_DIR.mkdir(parents=True, exist_ok=True)
        path = _cache_path(email)
        path.write_text(cache.serialize())
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _app(cache: msal.SerializableTokenCache) -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        client_id=config.AZURE_CLIENT_ID,
        client_credential=config.AZURE_CLIENT_SECRET,
        authority=_authority(),
        token_cache=cache,
    )


# ---- one-time OAuth state (must survive the redirect, which starts a new Streamlit session) ----
def _read_states() -> dict:
    try:
        data = json.loads(config.STATE_PATH.read_text())
    except Exception:  # noqa: BLE001
        data = {}
    now = time.time()
    return {k: v for k, v in data.items() if now - v < STATE_TTL_SECONDS}


def _write_states(states: dict) -> None:
    config.STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    newest = dict(sorted(states.items(), key=lambda kv: kv[1])[-50:])
    config.STATE_PATH.write_text(json.dumps(newest))


def new_state() -> str:
    states = _read_states()
    state = secrets.token_urlsafe(16)
    states[state] = time.time()
    _write_states(states)
    return state


def consume_state(state: str | None) -> bool:
    if not state:
        return False
    states = _read_states()
    if state not in states:
        return False
    del states[state]
    _write_states(states)
    return True


# ---- sign in ----
def get_login_url(state: str) -> str:
    return _app(_load_cache(None)).get_authorization_request_url(
        scopes=[config.MCP_SCOPE], redirect_uri=config.REDIRECT_URI, state=state, prompt="select_account",
    )


def complete_login(code: str) -> LoginOutcome:
    cache = msal.SerializableTokenCache()
    result = _app(cache).acquire_token_by_authorization_code(
        code=code, scopes=[config.MCP_SCOPE], redirect_uri=config.REDIRECT_URI
    )
    if "access_token" not in result:
        return LoginOutcome(False, error=result.get("error_description") or result.get("error") or "Sign-in failed.")
    claims = result.get("id_token_claims", {}) or {}
    email = (claims.get("preferred_username") or claims.get("email") or claims.get("upn") or "").strip().lower()
    if not email:
        return LoginOutcome(False, error="Microsoft did not return an email address for this account.")
    _save_cache(email, cache)
    return LoginOutcome(True, email=email, name=claims.get("name", ""))


# ---- tokens ----
def acquire(email: str, scope: str) -> tuple[str | None, str | None]:
    """Return (access_token, error). Refreshes silently from the user's cache."""
    try:
        cache = _load_cache(email)
        app = _app(cache)
        accounts = app.get_accounts()
        account = next((a for a in accounts if a.get("username", "").lower() == email.lower()),
                       accounts[0] if accounts else None)
        if account is None:
            return None, "No cached Microsoft session. Please sign in again."
        result = app.acquire_token_silent([scope], account=account)
        _save_cache(email, cache)
    except Exception as exc:  # noqa: BLE001  (bad tenant, network down, corrupt cache)
        return None, f"Could not reach Microsoft sign-in service: {exc}"[:400]
    if result and "access_token" in result:
        return result["access_token"], None
    detail = (result or {}).get("error_description") or (result or {}).get("error") or "Token refresh failed."
    return None, detail[:400]


def get_mcp_token(email: str) -> str | None:
    return acquire(email, config.MCP_SCOPE)[0]


def get_arm_token(email: str) -> str | None:
    return acquire(email, config.ARM_SCOPE)[0]


def drop_cache(email: str) -> None:
    path = _cache_path(email)
    if path.exists():
        path.unlink()
