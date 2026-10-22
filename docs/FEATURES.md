# Raven Cyber AI: feature and support guide

Version 3.8. This is the one place that explains every feature, who can use it, how it works and what to check when it
does not. Related guides: `RUNBOOK.md` (install and troubleshooting), `ADMIN_GUIDE.md` (users, roles, connectors),
`SECURITY.md` (controls), `ARCHITECTURE.md` (design), `ADDING_A_TOOL.md` (new tools).

## 1. At a glance

| Area | Page | What it does | Permission |
|---|---|---|---|
| Overview | Home | Assistant bar, quick actions, connected tools, live numbers, recent activity | everyone signed in |
| Investigate | Incidents | Sentinel incidents, risk score out of 10, alerts, entities, entity history, comments | `investigation.view` |
| Investigate | Hunting | Natural language or KQL threat hunting, saved queries | `hunting.use` |
| Investigate | Chat Assistant | Ask Sentinel, the Data Lake and attached files; contain threats in one click | `chat.use` |
| Respond | Containment | IP, URL, Domain, Device, User Disable, Password Reset, Custom Action, Incident Playbook | `containment.view` |
| Data | Data Lake | Tables, JSON, PDF and Word; SQL, document search (RAG) and AI with sources | `lake.view` |
| Platform | Tools | Every connected product and its status | everyone signed in |
| Platform | Audit Logs | Tamper-evident log of every action | `audit.view` |
| Platform | Admin | Users, roles, sign-in, workspace, safety rules, connectors | `admin.*` |
| Help | Support | This guide and the other guides, searchable, inside the app | everyone signed in |

## 2. Signing in and access
* Sign in with your organization Microsoft account. Access is granted by an administrator (Admin > Users).
* The first person to sign in becomes Super Admin (restrict with `BOOTSTRAP_ADMIN_EMAIL`).
* New people either request access (an admin approves) or are denied, depending on Admin > Sign-in settings.
* Sessions idle out after 60 minutes by default (absolute maximum 12 hours).
* Sentinel and Azure calls use the signed-in person's own Microsoft permissions. See the role table in `README.md`.

### Roles
| Role | Intended use | Key permissions |
|---|---|---|
| Super Admin | Platform owner | everything |
| SOC Manager | Runs the SOC | investigation, all containment and connector management, audit read and export, full Data Lake |
| L2 Analyst | Investigates and responds | investigation, standard containment, hunting, Data Lake view, upload and AI |
| L1 Analyst | Triage | investigation, comments, hunting, chat, Data Lake view and AI; no containment |
| Viewer | Read only | dashboard, investigations, Data Lake view |
| Auditor | Compliance | audit view, export and verify |
Roles can be combined per person and edited in Admin > Roles and permissions.

## 3. Chat Assistant
The assistant is a LangGraph agent. It can query Sentinel through the MCP server, search your earlier chats, read your Data
Lake, analyse attached files and prepare containment. It never runs a containment action by itself.

### 3.1 Ask questions
Examples: "show high severity incidents from the last 7 days", "list sign-in failures for alice@corp.com", "write KQL for
rare parent processes", "email me the report". Ask from Home (it opens the chat) or from the Chat Assistant page.

### 3.2 Contain with one click
Say what you want and give the reason in the same sentence:

| Say | Card prepared |
|---|---|
| `block IP 203.0.113.45 because of C2 beacons` | IP Blocking |
| `block URL https://bad.example/x because phishing` | URL Blocking |
| `block domain evil.example because malware hosting` | Domain Blocking |
| `isolate LAPTOP-01 because ransomware` | Device Isolation |
| `disable user alice@corp.com because impossible travel` | User Disable |
| `reset password for alice@corp.com because credentials leaked` | Password Reset |
| `contain this incident because ransomware` | opens the Incident Playbook |
Custom Action cards come from the assistant (for example "run the custom action on host X") or from "Change details".

The card shows the indicator, the justification and the connector. If everything is present you press **Continue** once.
* No justification in your sentence: a Justification box appears on the card. Minimum 10 characters.
* **Change details** lets you switch the action type, connector, value or justification first.
* Connector choice defaults to one you are allowed to run. High impact connectors also ask you to type `CONFIRM`.
* The same safety rules apply as on the Containment page: role check, protected entities, rate limit, audit-before-action.
* More than one indicator in a sentence, indicators found in an attached file, or indicators found in the Data Lake go through
  the assistant, which prepares up to 10 cards. Each card still needs its own Continue.

### 3.2a Multi-step requests (analyse, then act)
Write the whole job in one sentence, for example:
`433962 analyse this incident, and if you find an IP, block it in the IP firewall with proper justification and post it into the incident comment`
Direct one-line commands (above) are handled instantly. Anything with several steps, or with no value to act on, goes to the
assistant, which:
1. reads the incident with `get_incident_details` (title, severity, alerts, entities; IPs are marked public or internal) using your own Azure token,
2. explains what it found,
3. prepares one IP-block card per **public** IP with a justification taken from the evidence (internal addresses are never proposed),
4. prepares a comment card with the analysis, the indicators and the justification, worded as "containment requested" because nothing has run yet.
If you name a connector ("in the IP firewall"), the card preselects the connector whose name matches. You then press **Continue** on each
card. The assistant asks you instead of guessing when a value cannot be determined.

### 3.2b Comment on a Sentinel incident
Say `comment on incident 123: analyst confirmed phishing, user reset` (also "add a comment to incident #123 saying ..."). A card
shows the incident (number, title, severity, status) and your text; press **Continue** to post it. A line "Posted via Raven Cyber AI by
<you>" is appended so the Sentinel timeline shows where it came from. If you give no text the card asks for it.
Needs `investigation.comment` and the Microsoft Sentinel **Responder** role. The assistant can also prepare comments while answering
("add a comment to the incident we just discussed"). Incidents are looked up by number (server-side filter first, then a scan of the last 365 days).

### 3.3 Attach files for analysis
Use the paperclip in the chat box (or **Attach** on Home). Up to 5 files per message, 10 MB each.

| Type | What happens |
|---|---|
| CSV, TSV, Excel | Row and column summary, data types, empty cells, first rows (small files are sent whole) |
| JSON, TXT, MD, LOG, CSS | Read as text (JSON is pretty printed) |
| PDF, Word | Text extracted (PDF per page, Word paragraphs and tables). Scanned PDFs need OCR or a screenshot |
| PNG, JPG, WEBP | Re-encoded and downsized (metadata removed) and sent to the vision model, which can read text in screenshots |
* Indicators (public IPs, URLs, domains, emails, hashes, defanged forms included) are extracted and shown.
* Files stay available for follow-up questions in the same chat (see "Files in this chat"). Remove any with the X.
* **Prepare containment cards** turns the extracted indicators into cards with one shared justification.
* File content is untrusted data: the assistant is told never to follow instructions inside files.
* Files are not stored on disk. Their name, size and SHA-256 are in the audit log (`chat.attachment`). To keep a file, upload it to the Data Lake.
* Image analysis needs a vision-capable Azure OpenAI deployment (for example gpt-4o or newer).

### 3.4 Use the Data Lake from chat
When you hold `lake.ai`, the assistant can list datasets, run read-only SQL, read JSON and search PDF/Word documents, and says
which source it used. Ask "which IPs in the sign-ins dataset are not in our asset list?" and follow with "block the top two".

### 3.5 Reports and history
* Each chat is saved per person. Start a new chat, switch or delete chats on the left.
* "Email the last answer as a report" sends a formatted HTML email (permission `investigation.email`).
* "Sentinel MCP tools" lists the tools available from the MCP server.

## 4. Containment
One page, one selector for every response action. Each type has a connector grid, a run card, an automation flow and recent actions.

* **Connectors**: a Logic App (HTTP trigger URL) or any HTTP API with headers and a body template. Managers add them with the
  **Add custom connector** tile. Details, placeholders and examples are in `ADMIN_GUIDE.md`.
* **Run**: choose the connector tile, type the value (or a prompt and press Detect), add a justification, press Run.
* **Incident Playbook**: pick an incident; the Logic App receives the incident ARM id, name, id, title and entities, and can add a Sentinel comment.
* **Safety rules** (Admin > Containment): protected entities that can never be actioned, hourly rate limit, private network blocking.
* Everything is audited, including blocked attempts.

## 5. Data Lake
* **Upload** from your device: CSV, TSV, Excel (one dataset per sheet), JSON, JSONL, PDF, Word (.docx), TXT and Markdown. Per-file cap `LAKE_MAX_MB` (default 100 MB); the uploader accepts up to 200 MB.
* **Tables** become SQL tables. Column names are made SQL-safe. **Non-tabular JSON** is stored as a document.
* **PDF, Word and text** are extracted, split into overlapping passages (about 1000 characters) and indexed for search (RAG).
* **Search**: keyword ranking (BM25) always; semantic search too when `AZURE_OPENAI_EMBEDDING_DEPLOYMENT` is set. Results show document and page.
* **Explore**: schema, preview, read-only SQL editor, passage search, download of the original file.
* **Ask AI**: pick datasets, ask in plain language. Answers cite sources as (Document, p.N). It can prepare containment cards for indicators it finds.
* **Delete** removes the dataset, its passages and the stored original (with confirmation).
* Permissions: `lake.view`, `lake.upload`, `lake.delete`, `lake.ai`.
* Limits: scanned PDFs have no text and are rejected; documents uploaded before embeddings were configured stay keyword-only (re-upload to embed).

## 6. Incidents and Hunting
* **Incidents**: filters, severity, status, owner, time range. The detail view has tabs: Risk breakdown (score out of 10 and its factors), Entity history (correlates entities with earlier incidents, adds up to +1.0 to the risk), Entities, Alerts and timeline, AI analysis, Log enrichment (MCP), Comments and Report.
* **Post comment** needs Microsoft Sentinel Responder.
* **Hunting** tabs: Natural Language, KQL Editor, Saved Queries and Hunting Playbooks. The generated KQL is shown, can be edited and saved.

## 7. Tools
Lists every integrated product with its status (Configured or Missing) and capabilities: Microsoft Sentinel, Azure OpenAI, email, Logic App, the Data Lake and any connector you add. Only integrated tools are listed.

## 8. Audit log
* Every sign-in, chat prompt, attachment, proposal, containment, lake upload/query/ask/delete and admin change is recorded.
* Entries are hash-chained: **Verify** detects edits and deletions. Export to CSV needs `audit.export`.
* Secrets (URLs, headers, keys) are never written.
* Useful actions: `chat.prompt`, `chat.attachment`, `chat.action_proposed`, `containment.executed`, `lake.ask`, `lake.uploaded`.

## 9. Administration
Admin tabs: Overview, Users, Roles and permissions, Sign-in settings, Sentinel workspace, Containment (safety rules), Integrations and System. See `ADMIN_GUIDE.md`.

## 10. Configuration reference (`.env`)
| Key | Purpose |
|---|---|
| `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, `REDIRECT_URI` | Microsoft sign-in |
| `MCP_SERVER_URL`, `MCP_SCOPE`, `ARM_SCOPE` | Sentinel MCP and Azure Resource Manager |
| `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT_NAME` | Language model (use a vision-capable deployment for images) |
| `AZURE_OPENAI_EMBEDDING_DEPLOYMENT` | Optional embeddings for semantic document search |
| `EMAIL_*`, `SMTP_*` | Report email |
| `LOGICAPP_INCIDENT_URL` | Default incident playbook Logic App |
| `SENTINEL_*` | Default workspace (can be set in Admin) |
| `BOOTSTRAP_ADMIN_EMAIL`, `APP_SECRET_KEY`, `DB_PATH`, `LOG_LEVEL`, `LAKE_MAX_MB` | Platform |

## 11. Troubleshooting (feature level)
| Symptom | Check |
|---|---|
| Chat says the Microsoft session expired | Sign out and in again |
| Several chat messages in a row failed with "Event loop is closed" | Fixed in 3.7: all assistant calls share one background event loop. Update to 3.7 |
| Comment card says incident not found | Check the number and the workspace in Admin; incidents older than 365 days are not searched |
| Chat shows only a hint card or ignores a long request | Fixed in 3.8: multi-step sentences go to the assistant |
| "I need the value to act on" | The sentence had no IP, URL, domain, host or user. Add it |
| Continue is greyed out | Justification under 10 characters, invalid value, protected entity, role lacks the connector, or CONFIRM not typed |
| "No ... connector is set up yet" | Add a connector on the Containment page (needs `containment.manage_targets`) |
| File rejected: type or content mismatch | Use a supported type; the file must really be that format |
| PDF has no text | It is a scan. Attach a screenshot as an image or run OCR first |
| Image analysis returns an error | The Azure OpenAI deployment is not vision-capable |
| Lake answer has no citations | The question was about a table (SQL) or the document was not selected in Ask AI |
| Semantic search says keyword only | Set `AZURE_OPENAI_EMBEDDING_DEPLOYMENT`, restart, re-upload documents |
| Audit verify fails | The database was edited outside the app. Restore from backup (`RUNBOOK.md`) |

## 12. Support page
The last item in the sidebar. It shows this guide and the runbook to everyone, and the admin guide, security notes, architecture and
tool guide to administrators. Search inside a guide, open the chat command cheat sheet, or download a guide as Markdown.

## 13. Glossary
**IOC** indicator of compromise. **RAG** retrieval-augmented generation: search the documents, then answer from the passages found. **BM25** keyword ranking. **MCP** Model Context Protocol, how the assistant reaches Sentinel. **Protected entity** an asset that containment may never touch.
