"""Static definitions: permissions, default roles, default settings."""
import json

APP_NAME = "Raven Cyber AI"
APP_TAGLINE = "One AI-powered cyber defense platform for a safer tomorrow"
APP_VERSION = "3.9.0"

# Audit log panels
PANELS = ("auth", "chat", "hunting", "investigation", "dashboard", "containment", "lake", "admin", "audit")

PERMISSIONS = {
    "chat.use": "Use the Sentinel chat assistant",
    "investigation.view": "Open the Investigation portal and run investigations",
    "investigation.comment": "Post comments on Sentinel incidents",
    "investigation.email": "Email reports (investigation and chat)",
    "dashboard.view": "View the incident dashboard",
    "containment.view": "View the Containment panel",
    "containment.run": "Run standard containment actions",
    "containment.run_high": "Run high impact containment actions",
    "containment.manage_targets": "Add, edit and delete Logic App and API containment targets",
    "hunting.use": "Use the Threat Hunting panel",
    "hunting.save": "Save hunting queries",
    "lake.view": "View and download Data Lake datasets",
    "lake.upload": "Upload files to the Data Lake",
    "lake.delete": "Delete Data Lake datasets",
    "lake.ai": "Ask the AI questions about Data Lake datasets",
    "audit.view": "View the audit log",
    "audit.export": "Export the audit log to CSV",
    "audit.verify": "Verify audit log integrity",
    "admin.users": "Manage users and role assignments",
    "admin.roles": "Manage roles and permissions",
    "admin.settings": "Manage sign-in and platform settings",
    "admin.workspace": "Configure the Sentinel workspace",
    "admin.containment": "Manage containment actions and safety rules",
}

SUPER_ADMIN = "Super Admin"
_ALL = tuple(PERMISSIONS)

# name -> (description, permissions)
DEFAULT_ROLES = {
    "Super Admin": ("Full platform access", _ALL),
    "SOC Manager": (
        "Runs the SOC: investigation, all containment, audit read",
        ("chat.use", "investigation.view", "investigation.comment", "investigation.email",
         "dashboard.view", "containment.view", "containment.run", "containment.run_high",
         "containment.manage_targets", "hunting.use", "hunting.save", "audit.view", "audit.export",
         "lake.view", "lake.upload", "lake.delete", "lake.ai"),
    ),
    "L2 Analyst": (
        "Investigates and runs standard containment",
        ("chat.use", "investigation.view", "investigation.comment", "investigation.email",
         "dashboard.view", "containment.view", "containment.run", "hunting.use", "hunting.save",
         "lake.view", "lake.upload", "lake.ai"),
    ),
    "L1 Analyst": (
        "Triage: investigate and comment, no containment",
        ("chat.use", "investigation.view", "investigation.comment", "dashboard.view", "hunting.use", "lake.view", "lake.ai"),
    ),
    "Viewer": ("Read-only dashboard and investigations", ("dashboard.view", "investigation.view", "lake.view")),
    "Auditor": ("Reads and verifies the audit log", ("dashboard.view", "audit.view", "audit.export", "audit.verify")),
}

DEFAULT_SETTINGS = {
    "login.title": "Welcome Back",
    "login.message": "Sign in with your organization Microsoft account to access Raven Cyber AI. Access is granted by an administrator.",
    "login.allowed_domains": "",
    "access.self_registration": "request",  # request | deny
    "session.timeout_minutes": "60",
    "sentinel.subscription_id": "",
    "sentinel.resource_group": "",
    "sentinel.workspace_name": "",
    "sentinel.workspace_id": "",
    "containment.protected_entities": "",
    "containment.rate_limit_per_hour": "20",
    "email.default_recipient": "",
    "containment.allow_private_targets": "false",
}

# Containment target categories (tabs in the Containment panel)
CONTAINMENT_CATEGORIES = {
    "ip_block": ("IP Blocking", "IP address"),
    "url_block": ("URL Blocking", "URL"),
    "domain_block": ("Domain Blocking", "Domain"),
    "device_isolation": ("Device Isolation", "Hostname or device id"),
    "user_disable": ("User Disable", "User (UPN or email)"),
    "password_reset": ("Password Reset", "User (UPN or email)"),
    "advanced": ("Custom Action", "Target value"),
}
# Categories a target can have: the containment panels plus enrichment (threat intelligence and lookup APIs)
TARGET_CATEGORIES = {**CONTAINMENT_CATEGORIES, "enrichment": ("Enrichment", "Indicator to look up")}

# Placeholders available to payload templates are documented in docs/ADMIN_GUIDE.md
DEFAULT_PAYLOAD_TEMPLATE = json.dumps(
    {
        "incidentArmId": "{{incident.arm_id}}",
        "incidentName": "{{incident.name}}",
        "incidentId": "{{incident.number}}",
        "incidentTitle": "{{incident.title}}",
        "entities": "{{entities}}",
        "triggeredBy": "{{user.email}}",
        "justification": "{{justification}}",
    },
    indent=2,
)

PLACEHOLDERS = (
    "incident.arm_id", "incident.name", "incident.number", "incident.title",
    "incident.severity", "incident.status", "incident.url",
    "entities", "user.email", "justification",
)
