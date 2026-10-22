import pytest

pytest.importorskip("msal")
from src.core import config  # noqa: E402
from src.services import auth  # noqa: E402


def test_state_is_one_time_and_survives_new_session(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "STATE_PATH", tmp_path / "states.json")
    state = auth.new_state()
    assert auth.consume_state(state) is True   # a fresh Streamlit session can still validate it
    assert auth.consume_state(state) is False  # but only once
    assert auth.consume_state("junk") is False
    assert auth.consume_state(None) is False


def test_cache_path_is_per_user(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "TOKEN_DIR", tmp_path)
    assert auth._cache_path("a@x.com") != auth._cache_path("b@x.com")
    assert auth._cache_path("A@X.com") == auth._cache_path("a@x.com")


def test_acquire_without_cache_returns_error(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "TOKEN_DIR", tmp_path)
    monkeypatch.setattr(config, "AZURE_TENANT_ID", "")  # invalid authority must not crash the UI
    token, err = auth.acquire("nobody@x.com", "scope")
    assert token is None and err
