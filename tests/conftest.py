import pytest

from src.core import config, database


@pytest.fixture()
def db(tmp_path, monkeypatch):
    """Fresh isolated database for each test."""
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(config, "BOOTSTRAP_ADMIN_EMAIL", "")
    database.init_db()
    return tmp_path
