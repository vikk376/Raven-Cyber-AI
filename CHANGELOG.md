# Changelog

## 3.9.0
- Incident filters: the Refresh button now sits on the same line as the filter boxes.
- Data Lake, Ask AI: no dataset selection. The AI reads the catalogue and chooses the datasets and documents itself.
- Chat Assistant: new `virustotal_lookup` tool (IP, domain, URL, file hash) returning verdict, detection counts, owner and link.
  Set `VIRUSTOTAL_API_KEY` in `.env`. Lookups are read-only, cached for one hour, throttled for the free tier and audited.

## 3.8.0
* **Multi-step chat requests now work**: "433962 analyse this incident, if you find an IP block it in the IP firewall with justification and post into the incident comment" is sent to the assistant instead of being mistaken for a one-line block command. It reads the incident, prepares one card per public IP and a comment card, and you press Continue on each
* New assistant tool `get_incident_details` (Sentinel incident by number with alerts and entities, using the user's own Azure token); `propose_containment` rejects internal addresses and accepts a `connector_hint` so "in the IP firewall" preselects that connector
* Sentences with no value to act on ("block this ip") go to the assistant instead of showing a dead-end hint
* Incident lookup by number uses a server-side filter, then a 365 day scan (comment card and assistant)

## 3.7.0
* **Fix**: "Error: Event loop is closed" on the second and later chat messages. Assistant calls now share one long-lived background event loop instead of creating and closing a loop per message (also fixes Hunting, Investigation AI and MCP tool listing)
* **Comment on Sentinel incidents from chat**: `comment on incident 123: text` shows a card and one Continue posts it (audit `incident.comment_added`, source chat). The assistant can prepare comments too (`propose_incident_comment`)
* **Support page** (last item in the sidebar): feature guide, runbook, and for admins the admin, security, architecture and tool guides, with search, a chat command cheat sheet and download. Docs are now included in the Docker image

## 3.6.0
* **One-click containment from chat**: the card shows the indicator, justification and connector and asks for a single **Continue**. A missing justification is asked for on the card; "Change details" edits type, connector, value or reason. Works from Home, Chat Assistant and Data Lake Ask AI for IP, URL, Domain, Device, User Disable, Password Reset, Custom Action and the Incident Playbook
* **Chat assistant uses the Data Lake** (tables, JSON, PDF and Word with citations) and can prepare up to 10 containment cards per answer through a `propose_containment` tool that never executes anything
* **Attach files in chat** (also from Home): CSV, TSV, Excel, JSON, TXT, MD, LOG, PDF, Word and images (PNG, JPG, WEBP). Magic-byte checks, 5 files and 10 MB limits, images re-encoded without metadata, IOC extraction, files kept per chat for follow-ups, prepared containment cards from found indicators, SHA-256 in the audit log
* Attached and lake content is marked untrusted so instructions inside it are not followed
* New `docs/FEATURES.md` support guide covering every feature, role, setting and fix

## 3.5.0
* **RAG Data Lake**: upload PDF, Word (.docx), text and Markdown. Text is extracted (PDF per page, Word paragraphs and tables), split into overlapping passages and indexed. Scanned image-only PDFs are rejected because they have no text layer
* Hybrid retrieval: SQLite FTS5 BM25 keyword search always; semantic embeddings merged with reciprocal rank fusion when `AZURE_OPENAI_EMBEDDING_DEPLOYMENT` is set. Falls back to keyword search if embeddings fail
* Ask AI gains a `search_documents` tool and cites sources as (Document, p.N); per-document passage search in Explore
* Whole app is now a white and light blue theme; Quick actions, tool and dataset cards have equal heights and aligned grids
* Migration 6 rebuilds `lake_datasets` (open kind list, `info_json`)

## 3.4.0
* **Data Lake** (sidebar section Data): upload CSV, TSV, Excel (one dataset per sheet), JSON and JSONL from your device. Tables become SQL-queryable; other JSON is stored as a document. Explore with schema, preview and a read-only SQL editor, download the original file, delete with confirmation
* **Ask AI** over the lake: the model uses read-only tools (list, describe, SQL, read JSON document) limited to the datasets you pick; dataset contents are treated as untrusted data
* New permissions lake.view, lake.upload, lake.delete, lake.ai (migration 5 grants them to existing roles); every upload, query, delete and AI question is audited
* Tools page lists only integrated tools: the eight planned (not integrated) products were removed; Data Lake added
* Upload limit raised to 200 MB in `.streamlit/config.toml` (LAKE_MAX_MB in `.env` sets the per-file cap, default 100)

## 3.3.0
* Containment page now holds every response action: IP, URL, Domain, Device, User Disable, Password Reset, Custom Action and the Incident Playbook (sidebar Respond has one entry)
* Prompts understand users and domains: "disable user alice@corp.com because ...", "reset password for alice@corp.com because ...", "block domain evil.example because ..."
* Database migration 4 (open category list); Home quick action "Contain a threat"

## 3.2.1
* IP Blocking, URL Blocking and Device Isolation are now one **Containment** page with an action selector (IP, URL, Device, Custom Action); Advanced Actions page removed, custom actions are added with Add connector
* Detect and chat requests switch the action type automatically

## 3.2.0
* Respond panels show connectors as an aligned card grid (same layout as Home). Press Use to pick one, Edit to change it, or the Add custom connector tile to add a Logic App or API without leaving the panel
* Containment from chat: type "block IP 203.0.113.45 because of C2 beacons" on Home or in Chat; a review card appears with connector, value and justification, then Run
* Dashboard page and Targets and Tools page removed (live numbers stay on Home; connectors are managed in each Respond panel and on Tools)
* Lighter sky-blue theme with dark blue accents, equal-height cards
* 110 automated tests

## 3.1.0 (consolidated Cyber AI platform)
* Sky blue and dark blue theme from the logo, light and dark mode, logo watermark on the hero and login, animated cards
* Containment is now one panel per action: IP Blocking, URL Blocking, Device Isolation, Advanced Actions, Incident Playbook (sidebar sections Overview, Investigate, Respond, Platform)
* Tools hub and tool registry (`src/tools`): Sentinel, Azure OpenAI, SMTP, Logic Apps, custom APIs and enrichment, plus planned tools (Defender, Entra ID, Intune, Palo Alto, Zscaler, CrowdStrike, ServiceNow, Slack/Teams)
* Targets and Tools page; new `enrichment` target category (VirusTotal style lookups) from the investigation view
* Entity history and correlation: related incidents, repeat entities, previously confirmed malicious and false positive history, matrix and timeline, up to +1.0 added to the risk score
* Home page with assistant prompt, quick actions, connected tools and live activity
* Database migration 3 (enrichment category), `docs/ADDING_A_TOOL.md`

## 3.0.0 (Raven Cyber AI)
* New Raven Cyber AI branding with your logo, dark theme, login page, Home page with assistant prompt and overview
* Containment redesigned into IP Blocking, URL Blocking, Device Isolation, Advanced Actions, Incident Playbook, Manage Targets
* Admins register Logic App targets (name + URL) and API targets (method, URL, headers, body); URLs and headers encrypted at rest
* Prompt-wise containment: type "block IP ... because ..." and press Detect, plus `{{indicator}}`, `{{justification}}`, `{{param.x}}`, `{{env.CONTAINMENT_X}}` placeholders
* SSRF protection, indicator validation, protected-entity and rate-limit checks, audit-before-action for every target run
* Hunting panel (natural language, KQL editor, saved queries, starter playbooks) through the Sentinel MCP server
* Admin overview dashboard, Integrations status with SMTP and Azure OpenAI tests
* Database migration 2 (containment_targets, hunting_queries, new permissions), 93 automated tests

## 2.0.0
* Multi-user platform with Microsoft sign-in, server-side sessions and per-user token caches
* RBAC with multiple roles per user, permission matrix, access requests, domain allowlist
* Investigation portal with colour-coded risk score out of 10, AI analysis, MCP enrichment, Sentinel incident comments
* Dashboard from the Sentinel REST API
* Containment through Logic Apps with protected entities, rate limit, confirmation and audit-before-action
* Hash-chained audit log with panel and user filters, CSV export and integrity check
* Admin panel for users, roles, sign-in, workspace and containment actions
* Docker, Makefile, CI workflow, 57 automated tests

## 1.x
* Single-user chat agent with SQLite history and HTML email reports
