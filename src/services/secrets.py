"""Encrypt secrets (Logic App URLs, API headers) before they are stored in the database.

Key order: APP_SECRET_KEY from .env (any string), else a random key file at data/secret.key (mode 600).
Losing the key means stored URLs and headers cannot be decrypted and must be entered again.
"""
import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken

from src.core import config

_cached: Fernet | None = None


def _key() -> bytes:
    env = os.getenv("APP_SECRET_KEY", "").strip()
    if env:
        return base64.urlsafe_b64encode(hashlib.sha256(env.encode()).digest())
    path = config.DATA_DIR / "secret.key"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(Fernet.generate_key())
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return path.read_bytes().strip()


def _fernet() -> Fernet:
    global _cached
    key = _key()
    if _cached is None or getattr(_cached, "_k", None) != key:
        _cached = Fernet(key)
        _cached._k = key  # type: ignore[attr-defined]
    return _cached


def encrypt(text: str) -> str:
    return _fernet().encrypt((text or "").encode()).decode()


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Stored secret cannot be decrypted (the encryption key changed). Enter it again.") from exc
