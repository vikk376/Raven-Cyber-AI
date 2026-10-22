"""Threat hunting: saved queries, starter playbooks and safe prompt construction for the Sentinel MCP agent."""
import re

from src.core.database import connect, utcnow

MAX_QUERY = 6000

PLAYBOOKS = [
    {"name": "Password spray from a single IP", "kind": "kql",
     "why": "Many users failing from one address in 24 hours.",
     "text": """SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType !in ("0", "50125", "50140")
| summarize FailedAttempts = count(), DistinctUsers = dcount(UserPrincipalName), Apps = make_set(AppDisplayName, 5) by IPAddress
| where DistinctUsers >= 5
| order by FailedAttempts desc"""},
    {"name": "Download cradles via living-off-the-land binaries", "kind": "kql",
     "why": "certutil, bitsadmin, mshta, regsvr32 or rundll32 with URL or script arguments.",
     "text": """DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("http://", "https://", "-urlcache", "/i:http", "scrobj.dll")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc"""},
    {"name": "Encoded PowerShell commands", "kind": "kql",
     "why": "PowerShell started with an encoded command.",
     "text": """DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", "-ec ")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc"""},
    {"name": "Directory role assignments in the last 7 days", "kind": "kql",
     "why": "Who was added to an Entra role and by whom.",
     "text": """AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add member to role", "Add eligible member to role")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, OperationName, Actor, Target, Result
| order by TimeGenerated desc"""},
    {"name": "Failed logins from unusual countries", "kind": "nl",
     "why": "Natural language hunt.",
     "text": "Show failed sign-ins in the last 24 hours grouped by country, and highlight countries that are new compared with the previous 30 days."},
    {"name": "Possible lateral movement", "kind": "nl",
     "why": "Natural language hunt.",
     "text": "Find accounts that signed in to many different devices within one hour in the last 24 hours and list the devices and source IPs."},
    {"name": "Data exfiltration indicators", "kind": "nl",
     "why": "Natural language hunt.",
     "text": "Look for unusually large outbound transfers or mass file downloads in the last 7 days and show the users and destinations involved."},
]


class HuntError(ValueError):
    pass


def check_kql(text: str) -> str:
    q = (text or "").strip()
    if not q:
        raise HuntError("Enter a KQL query.")
    if len(q) > MAX_QUERY:
        raise HuntError(f"Query is too long (max {MAX_QUERY} characters).")
    if re.search(r"(?m)^\s*\.", q):
        raise HuntError("Control commands (lines starting with a dot) are not allowed. Only read queries can run.")
    return q


def build_kql_prompt(query: str) -> str:
    q = check_kql(query)
    q = q.replace("```", "")
    return ("Run exactly this KQL query with the Sentinel query tool. Do not change it. "
            "If the table or a column does not exist, say so and suggest the closest valid table. "
            "Show the results as a Markdown table (first 50 rows), then a two sentence summary of what stands out.\n"
            f"```kql\n{q}\n```")


def build_nl_prompt(question: str) -> str:
    q = (question or "").strip()
    if not q:
        raise HuntError("Describe what you want to hunt for.")
    if len(q) > 2000:
        raise HuntError("The question is too long (max 2000 characters).")
    return ("Threat hunting request. Find the right Sentinel tables, write a KQL query, run it, and answer. "
            "Show the KQL you used in a fenced block, the results as a Markdown table (first 50 rows), "
            f"then key findings and suggested next steps.\nRequest: {q}")


def save_query(owner: str, name: str, kind: str, text: str, shared: bool = False) -> None:
    name = (name or "").strip()
    if not (3 <= len(name) <= 80):
        raise HuntError("Name must be 3 to 80 characters.")
    if kind not in ("nl", "kql"):
        raise HuntError("Invalid query type.")
    if kind == "kql":
        text = check_kql(text)
    elif not (text or "").strip():
        raise HuntError("Nothing to save.")
    with connect(write=True) as con:
        con.execute("INSERT INTO hunting_queries (owner, name, kind, text, shared, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (owner, name, kind, text.strip(), 1 if shared else 0, utcnow()))


def list_queries(owner: str) -> list[dict]:
    with connect() as con:
        rows = con.execute(
            "SELECT * FROM hunting_queries WHERE owner = ? OR shared = 1 ORDER BY created_at DESC", (owner,)).fetchall()
    return [dict(r) for r in rows]


def delete_query(owner: str, query_id: int, is_admin: bool = False) -> bool:
    with connect(write=True) as con:
        if is_admin:
            cur = con.execute("DELETE FROM hunting_queries WHERE id = ?", (query_id,))
        else:
            cur = con.execute("DELETE FROM hunting_queries WHERE id = ? AND owner = ? COLLATE NOCASE", (query_id, owner))
        return cur.rowcount > 0
