# Security

## Secrets
* `.env` holds live credentials and is excluded from git and from the Docker image. Do not email or paste it.
* **Rotate** any secret that has been shared in chat or email: the Entra client secret, the Azure OpenAI key,
  the Gmail app password, and the Logic App callback URL (regenerate its access keys in the Azure portal).
* The Logic App URL contains a signature (`sig=`). The platform never displays it and scrubs `sig=`, tokens,
  passwords and bearer values from audit records and logs.
* For servers, store secrets in Azure Key Vault or your platform's secret store and inject them as environment variables.

## Authentication and sessions
* Microsoft Entra sign-in; the redirect uses a one-time `state` value stored on disk (it must survive the new
  Streamlit session that the redirect creates).
* After sign-in the app keeps a server-side session (random 256-bit id, stored hashed). The id is carried in the
  URL as `?sid=` so a browser refresh keeps you signed in. Anyone who obtains the full URL could reuse it until it
  expires (idle timeout, default 60 minutes; absolute maximum 12 hours), so do not share or screenshot URLs.
  For stricter setups, put the app behind Azure Container Apps Easy Auth or an authenticating reverse proxy.
* Denied or pending users have their token cache removed immediately.

## Authorization
* Platform RBAC is checked on every run and again inside services (containment re-checks permission).
* Azure RBAC still applies because calls use the user's own token.
* First-run bootstrap: set `BOOTSTRAP_ADMIN_EMAIL` so only your named account can become Super Admin.

## Containment safety
Role check, rate limit, protected entities, justification, typed confirmation for high impact, audit-before-action.

## Containment targets
* Logic App URLs and API headers are encrypted with Fernet (AES) using `APP_SECRET_KEY` (or `data/secret.key`). Back the key up with the database.
* The UI shows only the host and header names. Audit records never contain URLs, headers or tokens.
* Only environment variables that start with `CONTAINMENT_` can be referenced from templates, so `AZURE_CLIENT_SECRET` and similar cannot be exfiltrated.
* Destination guard: https only, loopback, private, link-local (including 169.254.169.254) and reserved addresses refused, redirects not followed.
  DNS is resolved before sending; a hostile DNS server that changes its answer between check and send is a residual risk. Use allow-listed egress on servers.
* Indicators are validated per category (IP or CIDR no wider than /16, URL or domain, hostname). Protected entities, rate limits and audit-before-action apply.

## Audit integrity
The SHA-256 hash chain detects tampering with the database file after the fact, but a person with full write access
to the server could rebuild the whole chain. For regulated environments, forward audit records to an external
immutable store.

## Known limits
* SQLite suits a small team on one host. Use Postgres or a managed database for many concurrent users.
* Risk scoring uses incident data and keywords; it supports, but does not replace, analyst judgement.
* The chat agent runs Sentinel MCP tools with the user's permissions and can read anything that user can read.

## 3.1 notes
* Enrichment lookups send only the indicator to the configured target, are limited to 120 per hour per user and are audited as `enrichment.executed`.
* Correlation reads incidents with the signed-in user's own Azure token; it does not store entities beyond the session.
* Rotate any secret that was pasted into chat or shared: Azure client secret, OpenAI key, SMTP app password, Logic App signature.

## Data Lake
* SQL runs on `data/lake/lake.db` only, opened read-only with an authorizer that allows SELECT and nothing else, a 15 second limit and a table allow-list for the AI. It cannot reach users, sessions, secrets or the audit log.
* Uploads are limited by type (csv, tsv, xlsx, json, jsonl, ndjson), size and row count, are never executed, and are stored under generated names.
* Do not upload secrets. Dataset text is sent to the Azure OpenAI deployment when a user asks the AI about it; the AI is told to treat it as data, not instructions.
* Permissions: lake.view, lake.upload, lake.delete, lake.ai. Every upload, query, delete and AI question is in the audit log (panel "lake").
* Documents (PDF, Word, text) are parsed with pypdf and python-docx, never executed. Extracted passages are stored in `rag_*` tables that SQL cannot read directly. Passages sent to the model are treated as untrusted data, and answers cite their sources.

## Chat attachments and proposals
* Attachments are limited by type, size (10 MB), count (5) and magic bytes, parsed in memory, never executed and not written to disk. Images are re-encoded (metadata dropped) and downsized.
* Extracted text is wrapped as untrusted data; the assistant is told never to follow instructions in files, datasets or documents.
* The `propose_containment` tool validates every value, deduplicates, caps at 10 per answer and cannot execute. A person must press Continue, and role checks, protected entities, rate limits and audit apply unchanged.
* Audit actions: `chat.attachment` (name, SHA-256, size), `chat.action_proposed` (source: prompt, home, assistant, attachment, lake).
