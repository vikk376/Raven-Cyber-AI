"""Integration status (configuration checks) and optional live connection tests."""
import smtplib
import ssl

import certifi

from src.core import config
from src.services import settings, targets


def status() -> list[dict]:
    """Configuration state only. 'Configured' does not prove the service is reachable; use Test."""
    ws = bool(settings.get("sentinel.subscription_id") and settings.get("sentinel.resource_group")
              and settings.get("sentinel.workspace_name"))
    tl = targets.list_targets()
    la = [t for t in tl if t["kind"] == "logicapp"]
    api = [t for t in tl if t["kind"] == "api"]
    return [
        {"key": "mcp", "name": "Sentinel MCP", "ok": bool(config.MCP_SERVER_URL), "detail": config.MCP_SERVER_URL},
        {"key": "arm", "name": "Sentinel REST (ARM)", "ok": ws,
         "detail": settings.get("sentinel.workspace_name") or "Workspace not set"},
        {"key": "openai", "name": "Azure OpenAI", "ok": bool(config.AZURE_OPENAI_API_KEY and config.AZURE_OPENAI_ENDPOINT),
         "detail": config.AZURE_OPENAI_DEPLOYMENT_NAME},
        {"key": "smtp", "name": "Email (SMTP)", "ok": bool(config.SMTP_USER and config.SMTP_PASSWORD),
         "detail": f"{config.SMTP_HOST}:{config.SMTP_PORT}"},
        {"key": "logicapps", "name": "Logic App targets", "ok": any(t["enabled"] for t in la),
         "detail": f"{len(la)} defined"},
        {"key": "api", "name": "API targets", "ok": any(t["enabled"] for t in api), "detail": f"{len(api)} defined"},
    ]


def test_smtp() -> str:
    """Connect and log in without sending any mail."""
    ctx = ssl.create_default_context(cafile=certifi.where())
    if config.SMTP_SECURITY == "ssl":
        with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, context=ctx, timeout=20) as s:
            s.login(config.SMTP_USER, config.SMTP_PASSWORD)
    else:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=20) as s:
            if config.SMTP_SECURITY == "starttls":
                s.starttls(context=ctx)
            s.login(config.SMTP_USER, config.SMTP_PASSWORD)
    return "SMTP login succeeded (no email was sent)."


def test_openai() -> str:
    from src.services import agent
    reply = agent.build_llm().invoke("Reply with the single word: ok")
    return f"Azure OpenAI answered: {str(reply.content)[:40]}"
