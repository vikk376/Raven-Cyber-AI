# Runbook

## 1. Azure setup (once)

**App registration** (the one whose client id is in `.env`)
1. Authentication > Add a platform > **Web** > redirect URI `http://localhost:8501` (no trailing slash).
2. API permissions, all **Delegated**:
   * Sentinel Platform Services: `SentinelPlatform.DelegatedAccess`
   * Azure Service Management: `user_impersonation`
   * Microsoft Graph: `User.Read`
3. Click **Grant admin consent** and confirm every row shows a green tick (including `user_impersonation`).
4. Certificates and secrets: use the secret **Value** in `AZURE_CLIENT_SECRET`.
5. Overview: copy **Directory (tenant) ID** into `AZURE_TENANT_ID`.

**Azure RBAC for people** (Access control (IAM) on the workspace or resource group)
* Microsoft Sentinel Reader for everyone who views incidents
* Microsoft Sentinel Responder for those who comment
* Logic App Contributor only if you use the `arm` source for containment actions

**Logic App**: trigger must be *When an HTTP request is received*. Copy its URL into `.env`.

## 2. Start

```bash
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py --server.port 8501
```
Always use `python -m streamlit` from the activated venv so the right interpreter is used.
Python 3.10+ is required (`langchain-mcp-adapters`).

## 3. First sign-in
Open http://localhost:8501, sign in. The first account (or `BOOTSTRAP_ADMIN_EMAIL`) becomes Super Admin.
Then Admin > Sentinel workspace, then Admin > Users.

## 4. Backup and restore
Everything lives in `data/`: `sentinel_platform.db` (users, roles, settings, audit, chats), `tokens/`, `logs/`.
Stop the app and copy the folder. To restore, copy it back. Keep backups protected: they contain tokens.

## 5. Upgrading
Unzip the new version, keep your `.env` and `data/`. Database migrations run automatically at start.

## 6. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `No module named langchain_mcp_adapters` | Wrong Python. Activate the venv and use `python -m streamlit`. Python must be 3.10+ |
| AADSTS50011 redirect URI mismatch | Add `http://localhost:8501` under **Web**; wait a few minutes; the URI in `.env` must match exactly |
| AADSTS7000215 invalid client secret | Use the secret Value (not its id); check expiry |
| Bounced back to the login page | Sign-in message appears in red; read it. Usually wrong secret or tenant id |
| "Could not get an Azure Resource Manager token" | Admin consent for `user_impersonation` missing, or sign out and in again |
| 403 from Azure | Missing Azure role (Reader to read, Responder to comment, Logic App Contributor for arm source) |
| Dashboard says workspace not configured | Admin > Sentinel workspace |
| Comment fails with 403 | The user needs Microsoft Sentinel Responder |
| Logic App returns 400 | Payload field names do not match the trigger's request schema. Edit the template in Admin > Containment |
| Logic App returns 401/403 | The callback URL signature was regenerated. Update `LOGICAPP_INCIDENT_URL` |
| Email `CERTIFICATE_VERIFY_FAILED` | Fixed by certifi; run `python -m pip install certifi` |
| Email 535 | Use a Gmail app password (2-Step Verification on) |
| "Sign-in expired or already used" | Do not reload the page with `?code=` in the URL; click Sign in again |
| Pending after first sign-in | Microsoft returned a different address than `BOOTSTRAP_ADMIN_EMAIL`. Leave it empty on a fresh database, or run `python scripts/make_admin.py <address shown on the pending screen>` |
| "Stored secret cannot be decrypted" | `APP_SECRET_KEY` (or `data/secret.key`) changed. Edit the target and enter the URL again |
| "Blocked: host resolves to a non-public address" | The target is on a private network. Use a public https endpoint, or allow lab targets in Admin > Containment |
| Logic App target returns 400/401 | Body field names do not match the trigger schema, or the URL signature was regenerated |
| Access request stuck on pending | An admin must approve it in Admin > Users |

## 7. Logs
`data/logs/app.log` (rotating). Audit events are in the database and the Audit panel.
