"""Central configuration loaded from the .env file."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")


def _get(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _int(name: str, default: int) -> int:
    try:
        return int(_get(name, str(default)))
    except ValueError:
        return default


# Paths
DATA_DIR = BASE_DIR / "data"
DB_PATH = BASE_DIR / _get("DB_PATH", "data/sentinel_platform.db")
TOKEN_DIR = DATA_DIR / "tokens"
STATE_PATH = DATA_DIR / "oauth_states.json"
LOG_DIR = DATA_DIR / "logs"
LOG_LEVEL = _get("LOG_LEVEL", "INFO").upper()

# Microsoft Entra
AZURE_CLIENT_ID = _get("AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = _get("AZURE_CLIENT_SECRET")
AZURE_TENANT_ID = _get("AZURE_TENANT_ID")
REDIRECT_URI = _get("REDIRECT_URI", "http://localhost:8501")

# Sentinel MCP and Azure Resource Manager
MCP_SERVER_URL = _get("MCP_SERVER_URL", "https://sentinel.microsoft.com/mcp/data-exploration")
MCP_SCOPE = _get("MCP_SCOPE", "4500ebfb-89b6-4b14-a480-7f749797bfcd/.default")
ARM_SCOPE = _get("ARM_SCOPE", "https://management.azure.com/user_impersonation")

# Azure OpenAI
AZURE_OPENAI_ENDPOINT = _get("AZURE_OPENAI_ENDPOINT")
AZURE_OPENAI_API_KEY = _get("AZURE_OPENAI_API_KEY")
AZURE_OPENAI_DEPLOYMENT_NAME = _get("AZURE_OPENAI_DEPLOYMENT_NAME", "gpt-4.1")
# Optional: an embeddings deployment (for example text-embedding-3-small). Without it the Data Lake uses keyword (BM25) search.
AZURE_OPENAI_EMBEDDING_DEPLOYMENT = _get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT", "")

# VirusTotal (optional): enables IP, domain, URL and hash reputation lookups in the Chat Assistant
VIRUSTOTAL_API_KEY = _get("VIRUSTOTAL_API_KEY")

# Email
EMAIL_TO = _get("EMAIL_TO")
EMAIL_FROM = _get("EMAIL_FROM")
SMTP_HOST = _get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = _int("SMTP_PORT", 587)
SMTP_SECURITY = _get("SMTP_SECURITY", "starttls").lower()
SMTP_USER = _get("SMTP_USER")
# Gmail app passwords are displayed with spaces; they work without them
SMTP_PASSWORD = _get("SMTP_PASSWORD").replace(" ", "")

# Access control bootstrap
BOOTSTRAP_ADMIN_EMAIL = _get("BOOTSTRAP_ADMIN_EMAIL").lower()

# Optional defaults for the Sentinel workspace (can also be set in the Admin panel)
SENTINEL_SUBSCRIPTION_ID = _get("SENTINEL_SUBSCRIPTION_ID")
SENTINEL_RESOURCE_GROUP = _get("SENTINEL_RESOURCE_GROUP")
SENTINEL_WORKSPACE_NAME = _get("SENTINEL_WORKSPACE_NAME")
SENTINEL_WORKSPACE_ID = _get("SENTINEL_WORKSPACE_ID")


def missing_settings() -> list[str]:
    """Blocking problems: the app cannot start without these."""
    required = {
        "AZURE_CLIENT_ID": AZURE_CLIENT_ID,
        "AZURE_CLIENT_SECRET": AZURE_CLIENT_SECRET,
        "AZURE_TENANT_ID": AZURE_TENANT_ID,
        "AZURE_OPENAI_ENDPOINT": AZURE_OPENAI_ENDPOINT,
        "AZURE_OPENAI_API_KEY": AZURE_OPENAI_API_KEY,
    }
    missing = [k for k, v in required.items() if not v]
    if AZURE_TENANT_ID.startswith("PUT-YOUR"):
        missing = [m for m in missing if m != "AZURE_TENANT_ID"] + ["AZURE_TENANT_ID (still the placeholder)"]
    return missing


def warnings() -> list[str]:
    """Non-blocking problems shown to administrators."""
    out = []
    if not (SMTP_USER and SMTP_PASSWORD and EMAIL_TO):
        out.append("Email is not fully configured (SMTP_USER, SMTP_PASSWORD, EMAIL_TO).")
    if not VIRUSTOTAL_API_KEY:
        out.append("VIRUSTOTAL_API_KEY is not set, so VirusTotal lookups in the Chat Assistant are disabled.")
    if not os.getenv("LOGICAPP_INCIDENT_URL"):
        out.append("LOGICAPP_INCIDENT_URL is not set, so the default containment action cannot run.")
    return out
