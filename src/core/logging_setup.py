"""Application logging with a rotating file handler."""
import logging
from logging.handlers import RotatingFileHandler

from src.core import config

_CONFIGURED = False


def setup_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    config.LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(getattr(logging, config.LOG_LEVEL, logging.INFO))
    file_handler = RotatingFileHandler(config.LOG_DIR / "app.log", maxBytes=5_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)
    # Keep third-party chatter down and never log request URLs that carry secrets
    for noisy in ("urllib3", "httpx", "httpcore", "msal"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _CONFIGURED = True
