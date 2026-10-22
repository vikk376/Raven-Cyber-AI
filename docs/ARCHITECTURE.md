# Architecture

```
Browser
  |
Streamlit app.py ---- sign-in gate ---- sessions (server-side, idle timeout)
  |                        |
  |                   MSAL auth code flow (per-user token cache)
  |
  +-- RBAC navigation (permissions resolved from the database on every run)
        |
        +-- Home / Investigation / Containment / Audit / Admin / Chat   (src/ui)
              |
              +-- services (src/services)
                    arm.py            Azure Resource Manager + Sentinel REST (user token)
                    agent.py          LangGraph ReAct agent -> Sentinel MCP server (user token)
                    risk.py           deterministic risk score out of 10
                    investigation.py  evidence collection, report, AI narrative
                    containment.py    incident playbook (Logic App) with safety checks
                    targets.py        Logic App and API containment targets (encrypted, SSRF guarded)
                    hunting.py        saved queries, starter hunts, safe prompts for the MCP agent
                    audit.py          hash-chained audit log
                    rbac / users / access / sessions / settings
              |
              +-- SQLite (WAL): users, roles, permissions, settings, sessions, audit_log, chats, actions
```

## Identity and tokens

* One Entra app registration. Users sign in with the authorization code flow.
* The Sentinel MCP server and Azure Resource Manager both require **delegated** tokens, so every call
  runs as the signed-in person. Azure RBAC therefore applies in addition to the platform's own RBAC.
* Each user has their own token cache file (`data/tokens/`, mode 600). The ARM token is obtained silently
  from the same refresh token (needs admin consent for `user_impersonation`).

## Authorization

Permissions are plain strings (`containment.run_high`, `audit.view`, ...). A user's effective permissions
are the union of all assigned roles. Super Admin always holds every permission. The last active Super Admin
cannot be disabled, deleted or demoted. Changes in the Admin panel take effect on the user's next click.

## Risk score (out of 10)

Computed from incident evidence only. The AI writes explanations, never the number.

| Component | Max | Signal |
|---|---|---|
| Severity | 4.0 | High 4, Medium 2.5, Low 1, Informational 0.25 |
| Alert volume | 1.5 | 2-4 alerts 0.5, 5-9 alerts 1.0, 10+ alerts 1.5 |
| Attack stage | 2.0 | tactic breadth (up to 1.0) plus 1.0 if a late-stage tactic is present |
| Entity exposure | 1.5 | distinct entities: 1-2 0.5, 3-5 1.0, 6+ 1.5 |
| Compromise signals | 1.0 | strong keywords 1.0 (ransomware, exfiltration, ...), moderate 0.5 |

Classification modifiers: False Positive x0.2, Benign Positive x0.5.
Bands: 0-3.9 Low (green), 4-6.9 Medium (amber), 7-8.9 High (orange), 9-10 Critical (red).
Weights live in `src/services/risk.py` and are covered by tests.

## Containment flow

1. Role check (`containment.run` or `containment.run_high`).
2. Rate limit per user per hour.
3. Protected-entity check (exact or wildcard).
4. Audit record `containment.requested` written first. If the audit write fails, nothing runs.
5. Payload rendered from the action template, POSTed to the Logic App HTTP trigger.
6. Audit record `containment.executed` with HTTP status and a response snippet. The URL and signature are never stored.
7. Optional incident comment through the Sentinel API.

## Data and audit

SQLite with WAL and versioned migrations (`src/core/database.py`). Every audit row stores the SHA-256 of the
previous row; `Verify log integrity` recomputes the chain and reports the first edited or removed record.
For stronger guarantees, ship audit rows to an immutable store (see Roadmap).

## Roadmap ideas

* Second-approver workflow for high impact actions
* Forward audit records to a Sentinel custom table (Logs Ingestion API, DCR/DCE)
* Postgres backend and Azure Container Apps deployment with Easy Auth in front
* Per-action Logic App run status tracking for URLs stored in `.env`

## 3.1 additions
* `src/tools/`: tool registry. The Tools page and Home read it; custom targets are added dynamically from the database.
* `src/services/correlation.py`: lists incidents in a window, loads entities in parallel, matches strong keys (account, host, IP, URL, domain, hash) and returns flags plus a risk uplift of at most 1.0.
* `src/ui/theme.py`: one CSS block using `color-mix(currentColor)` so it works in light and dark. Palette from `.streamlit/config.toml`.
* Navigation is sectioned in `app.py`; every Respond panel is a function in `containment_view.py`.
