"""Built-in tools. Statuses describe configuration only; use Test to check a live connection."""
from src.core import config
from src.services import settings, targets
from src.tools.registry import Tool, register


def _mcp() -> tuple[str, str]:
    ok = bool(config.MCP_SERVER_URL and config.AZURE_CLIENT_ID and config.AZURE_CLIENT_SECRET
              and config.AZURE_TENANT_ID and not config.AZURE_TENANT_ID.startswith("PUT-"))
    return ("configured" if ok else "missing"), config.MCP_SERVER_URL


def _arm() -> tuple[str, str]:
    ok = bool(settings.get("sentinel.subscription_id") and settings.get("sentinel.resource_group")
              and settings.get("sentinel.workspace_name"))
    return ("configured" if ok else "missing"), (settings.get("sentinel.workspace_name") or "Workspace not set (Admin)")


def _openai() -> tuple[str, str]:
    ok = bool(config.AZURE_OPENAI_API_KEY and config.AZURE_OPENAI_ENDPOINT)
    return ("configured" if ok else "missing"), config.AZURE_OPENAI_DEPLOYMENT_NAME


def _smtp() -> tuple[str, str]:
    ok = bool(config.SMTP_USER and config.SMTP_PASSWORD)
    return ("configured" if ok else "missing"), f"{config.SMTP_HOST}:{config.SMTP_PORT}"


def _count(kind: str | None = None, category: str | None = None) -> tuple[str, str]:
    try:
        items = [t for t in targets.list_targets() if t["enabled"] and (kind is None or t["kind"] == kind)
                 and (category is None or t["category"] == category)]
    except Exception:  # noqa: BLE001  (registry must never break a page)
        items = []
    return ("configured" if items else "missing"), f"{len(items)} enabled"


def _test_smtp() -> str:
    from src.services import integrations
    return integrations.test_smtp()


def _test_openai() -> str:
    from src.services import integrations
    return integrations.test_openai()


register(Tool("sentinel_mcp", "Microsoft Sentinel (MCP)", "Microsoft", "SIEM", "🛰️",
              "Natural language and KQL access to your Sentinel data lake through the MCP server.",
              ("hunt", "investigate", "enrich"), _mcp, nav="hunting"))
register(Tool("sentinel_rest", "Microsoft Sentinel (REST)", "Microsoft", "SIEM", "🛡️",
              "Incidents, alerts, entities and comments through the Azure Resource Manager API.",
              ("detect", "investigate"), _arm, nav="investigation"))
register(Tool("azure_openai", "Azure OpenAI", "Microsoft", "AI", "🧠",
              "Language model for analysis, narratives and the assistant.", ("ai",), _openai, _test_openai, nav="chat"))
register(Tool("smtp", "Email (SMTP)", "Your mail server", "Notification", "✉️",
              "Sends investigation and chat reports.", ("notify",), _smtp, _test_smtp))
register(Tool("logicapps", "Azure Logic Apps", "Microsoft", "SOAR", "⚙️",
              "HTTP-triggered playbooks for blocking, isolation and custom actions.", ("contain",),
              lambda: _count("logicapp"), nav="ip_block"))
register(Tool("custom_api", "Custom API tools", "Any vendor", "SOAR", "🔌",
              "Firewalls, proxies, EDR and ticketing APIs added from the UI with URL, headers and body.",
              ("contain",), lambda: _count("api"), nav="ip_block"))
register(Tool("enrichment_api", "Enrichment APIs", "Any vendor", "Threat Intel", "🔎",
              "Threat intelligence and lookup APIs (for example VirusTotal or AbuseIPDB) used in entity correlation.",
              ("enrich",), lambda: _count(category="enrichment"), nav="tools"))


def _lake() -> tuple[str, str]:
    try:
        from src.services import lake
        n = len(lake.list_datasets())
    except Exception:  # noqa: BLE001
        n = 0
    return "configured", f"{n} dataset(s)"


register(Tool("data_lake", "Data Lake", "Raven Cyber AI", "Data", "🌊",
              "Upload tables, JSON, PDF and Word files. Query with SQL, search documents (RAG) and ask the AI, in the Data Lake or in chat.",
              ("store", "ai"), _lake, nav="lake"))
