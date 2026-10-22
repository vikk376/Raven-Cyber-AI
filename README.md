# Raven Cyber AI

*AI-Powered Microsoft Sentinel for a Safer Tomorrow.* An enterprise SOC portal for Microsoft Sentinel built with Streamlit, LangChain and LangGraph.

| Panel | What it does |
|---|---|
| **Home** | AI assistant prompt, shortcuts to every panel you may use, 30 day security overview |
| **Home overview** | Incident KPIs, severity donut and created-vs-closed trend on the Home page |
| **Incidents** | Full incident evidence, **colour-coded risk score out of 10** with a breakdown, AI analysis, MCP log enrichment, **post a comment to the Sentinel incident**, email or download the report |
| **Hunting** | Natural language or KQL hunts through the Sentinel MCP server, saved queries, starter hunting playbooks |
| **Containment** | Separate panels for IP Blocking, URL Blocking, Device Isolation, Advanced Actions and Incident Playbook. Admins register **Logic Apps** (name + URL) and **APIs** (URL, headers, body); analysts run them with a justification, or type a prompt such as "block IP 203.0.113.45 because of C2". Plus the incident playbook (ARM id, entities, name, id) |
| **Chat Assistant** | Ask anything about Sentinel through the Sentinel MCP server, optionally email the answer |
| **Audit Logs** | Panel-wise and user-wise history, tamper-evident, CSV export, integrity check |
| **Admin** | Overview dashboard, users, multiple roles per user, role permission matrix, sign-in rules, workspace, containment safety rules, integrations status and tests, system |

Everything is role based. Each person signs in with Microsoft and only sees the panels their roles allow.

> Full feature and support guide: `docs/FEATURES.md`.

## Quick start

1. **Edit `.env`**: replace `AZURE_TENANT_ID=PUT-YOUR-TENANT-ID-HERE` with your real Directory (tenant) ID.
   All other values (app, OpenAI, Gmail, Logic App URL, workspace, `APP_SECRET_KEY`) are already filled in.
2. **Azure app registration** (details in `docs/RUNBOOK.md`):
   - Authentication > Web redirect URI `http://localhost:8501`
   - API permissions: Sentinel Platform Services `SentinelPlatform.DelegatedAccess` and Azure Service Management `user_impersonation`, both admin consented
3. **Run** (Python 3.10 or newer):

   ```bash
   cd sentinel-soc-platform
   python3 -m venv .venv
   source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   python -m streamlit run app.py --server.port 8501
   ```
   or `./run.sh` (macOS/Linux), `run.bat` (Windows), `make install && make run`, `docker compose up --build`.
4. Open http://localhost:8501 and sign in with Microsoft. **The first person to sign in becomes Super Admin**
   (set `BOOTSTRAP_ADMIN_EMAIL` to restrict who can claim this).
5. Go to **Admin > Sentinel workspace**, click *Load my subscriptions*, pick your workspace and save.
6. Go to **Admin > Users** to add people and assign roles.

## Tools, panels and correlation (new in 3.1)
The **Tools** page shows every connected product. Add more without code from any Respond panel or the Tools page (see `docs/ADDING_A_TOOL.md`). The incident view has an **Entity history** tab that correlates entities with earlier incidents and adds up to +1.0 to the risk score.

## Containment targets (3.0)

1. Open the **Containment** page and press **Add connector** (needs `containment.manage_targets`, held by Super Admin and SOC Manager).
2. **Logic App**: give it a name, choose the tab (IP, URL, device, advanced), paste the HTTP trigger URL. The default body sends
   `indicator`, `indicatorType`, `category`, `justification`, `triggeredBy`, `timestamp`. Edit the body so the names match your Logic App's request schema.
3. **API**: name, method, URL, headers (JSON or `Name: value` lines) and a body template. Use `{{indicator}}`, `{{justification}}`,
   `{{user.email}}`, `{{param.name}}` and `{{env.CONTAINMENT_NAME}}` (keep API keys in `.env` as `CONTAINMENT_NAME=...`).
4. Analysts open the tab, pick the target, type the value (or a prompt and press **Detect**), add a justification and run.

URLs and headers are encrypted in the database and never shown again or written to the audit log.
Requests to private networks and the cloud metadata address are refused.

## Azure roles each person needs

| To do this | The user needs |
|---|---|
| See incidents, dashboard, investigate | Microsoft Sentinel **Reader** on the workspace |
| Post incident comments | Microsoft Sentinel **Responder** |
| Discover Logic Apps / fetch callback URLs (optional) | **Logic App Contributor** (not needed for URLs stored in `.env`) |
| Use the chat (MCP) | Sentinel data lake access as in the Microsoft docs |

App roles (Admin panel) control what the platform allows. Azure roles control what Azure allows. Both must permit an action.

## Project layout

```
assets/                Raven logo and favicon
app.py                 entry point: sign-in gate, session, RBAC navigation
src/core/              config, constants, database + migrations, logging, secret scrubbing
src/services/          auth (MSAL), rbac, access, sessions, audit, arm (Azure REST), risk, metrics,
                       investigation, containment (incident playbook), targets (Logic App and API containment), indicators, secrets,
                       hunting, integrations, agent (LangGraph + MCP), emailer, settings, users
src/ui/                one module per panel + theme (Raven look and feel)
tests/                 93 tests (services and every panel through Streamlit AppTest)
docs/                  architecture, admin guide, security, runbook
```

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

## Security notes

`.env` contains live secrets. Do not commit or share it. Rotate any secret that has been pasted into chat or email.
Read `docs/SECURITY.md` before putting this on a shared server.

## Containment from chat (3.2)
On Home or in Chat type for example `block IP 203.0.113.45 because of C2 beacons`, `block URL https://bad.example because of phishing` or `isolate LAPTOP-01 because of ransomware`. Raven shows a review card (connector, value, justification). Nothing runs until you press Run, and the same permission, protected-entity, rate-limit and audit rules apply as in the Containment page.

## Containment actions (3.3)
IP Blocking, URL Blocking, Domain Blocking, Device Isolation, User Disable, Password Reset, Custom Action and Incident Playbook all live on the **Containment** page. Each action type has its own connectors (Logic App or API). Mark user and password connectors as High impact so they require typing CONFIRM, and list break-glass accounts under protected entities in Admin.

## Data Lake (3.4)
Open **Data Lake** in the sidebar. Upload CSV, TSV, Excel, JSON or JSONL files from your computer (Upload tab). Tables are queryable with SQL in the Explore tab (one read-only SELECT, tables are named after the dataset, for example `signins`). JSON that is not a table is stored as a document. The **Ask AI** tab lets the model analyse the datasets you select. Files are stored under `data/lake/` (originals in `raw/`, tables in `lake.db`), which is separate from the platform database. Back up the `data` folder.

## RAG Data Lake (3.5)
Upload PDF, Word, TXT and Markdown in Data Lake. Files are extracted, chunked and indexed (keyword BM25 always). For semantic search add an embeddings deployment to `.env`:

    AZURE_OPENAI_EMBEDDING_DEPLOYMENT=text-embedding-3-small

Documents uploaded before it was set stay keyword-only (re-upload to embed). Scanned PDFs need OCR first.

## VirusTotal in the Chat Assistant (3.9)
Set `VIRUSTOTAL_API_KEY` in `.env` and restart. Then ask, for example, "VirusTotal score for 203.0.113.45", "check evil-example.com" or "is this URL malicious: hxxps://...". The assistant calls the read-only `virustotal_lookup` tool and answers with the verdict, detections (for example 7/94), owner or registrar and a link to the full report. Private IPs are never sent. Results are cached for one hour and calls are spaced for the free tier (4 per minute, 500 per day). Every lookup is written to the audit log. Nothing is submitted for scanning, so an unknown indicator returns "no record", which is not proof of safety.
