# Admin guide

Open **Admin**. Tabs are shown only if your roles include the matching `admin.*` permission.

## Users
* **Pending access requests**: people who signed in but were not on the list. Choose roles and *Approve*, or *Reject*.
* **Edit user**: change display name, status (active or disabled) and roles. A user can hold several roles; permissions combine.
* **Add user**: pre-create an account with the person's Microsoft sign-in email, so their first sign-in works immediately.
* Safety: you cannot remove the last active Super Admin, and you cannot delete yourself.

## Roles and permissions
A matrix of permissions (rows) by roles (columns). Tick, then *Save permission changes*. Create custom roles below the matrix.
Built-in roles: Super Admin, SOC Manager, L2 Analyst, L1 Analyst, Viewer, Auditor.

| Permission | Allows |
|---|---|
| chat.use | Chat panel |
| investigation.view | Investigation panel |
| investigation.comment | Post comments on Sentinel incidents |
| investigation.email | Email reports |
| dashboard.view | Dashboard |
| containment.view / .run / .run_high | See the panel / run standard actions / run high impact actions |
| audit.view / .export / .verify | Read, export, verify the audit log |
| admin.users / .roles / .settings / .workspace / .containment | The matching Admin tabs |

## Sign-in settings
Controls the login page and who may enter:
* Login page title and message
* Allowed email domains (empty allows any domain in your tenant)
* Unknown users: *create an access request* (default) or *deny*
* Idle session timeout
* *Sign out all other users*

## Sentinel workspace
*Load my subscriptions*, choose one, *Find Sentinel workspaces*, choose the workspace, *Use this workspace*.
You can also type the values manually. Dashboard, Investigation and Containment use this workspace.

## Containment targets (Logic Apps and APIs)
Managed from the **Containment** page (connector grid and the **Add custom connector** tile) (permission `containment.manage_targets`).

| Field | Meaning |
|---|---|
| Name | Shown in the tab, for example "Block IP on Azure Firewall" |
| Type | Logic App (POST to an HTTP request trigger) or API (any method) |
| Category | Which tab it appears in: IP, URL, Domain, Device, User Disable, Password Reset or Custom Action |
| Impact | `high` needs `containment.run_high` and a typed CONFIRM |
| URL | Encrypted. Leave blank when editing to keep the stored URL. Placeholders are allowed in the path and query only |
| Headers | JSON or `Name: value` lines. Encrypted. Use `{{env.CONTAINMENT_NAME}}` to keep keys in `.env` |
| Body | JSON or text template |

Placeholders: `{{indicator}}` `{{indicator_type}}` `{{category}}` `{{target_name}}` `{{justification}}` `{{prompt}}`
`{{timestamp}}` `{{user.email}}` `{{param.name}}` `{{env.CONTAINMENT_NAME}}`. In the URL, values are URL-encoded automatically.

Analysts can add `key=value` extra fields at run time and use them as `{{param.key}}`.
Allowed destinations: public https hosts. Private networks, loopback and the cloud metadata address are refused;
an admin can allow private and http targets for a lab in Admin > Containment.

## Incident playbook action (ARM id, entities, name, id)
Each action is one Logic App with an HTTP request trigger.

| Field | Meaning |
|---|---|
| Key | Short id, lowercase with underscores |
| Source `env` | URL is read from a variable in `.env`, for example `LOGICAPP_INCIDENT_URL` (recommended) |
| Source `arm` | URL is fetched from Azure when the action runs (needs Logic App Contributor) |
| Impact | `high` needs `containment.run_high` plus a typed CONFIRM |
| Payload template | JSON sent to the Logic App |

Placeholders (a lone placeholder keeps its type, so `entities` stays a list and `incident.number` stays a number):

`{{incident.arm_id}}` `{{incident.name}}` `{{incident.number}}` `{{incident.title}}` `{{incident.severity}}`
`{{incident.status}}` `{{incident.url}}` `{{entities}}` `{{user.email}}` `{{justification}}`

Default template (matches the Logic App you supplied):

```json
{
  "incidentArmId": "{{incident.arm_id}}",
  "incidentName": "{{incident.name}}",
  "incidentId": "{{incident.number}}",
  "incidentTitle": "{{incident.title}}",
  "entities": "{{entities}}",
  "triggeredBy": "{{user.email}}",
  "justification": "{{justification}}"
}
```

**Match the field names to your Logic App's "Request Body JSON Schema".** If your trigger defines a schema with required
properties, rename the keys here to exactly what it expects. Use the *Preview payload* box in the Containment panel to check.

To add another Logic App: put its URL in `.env` as `LOGICAPP_<NAME>_URL`, restart, then add an action with that variable name.

Safety rules: protected entities (one per line, wildcards allowed, `#` for comments) and a per-user hourly rate limit.

## Audit log
Filter by panel, user, outcome, date and text. Export to CSV. *Verify log integrity* detects edited or deleted rows.
Recorded events include sign-ins, denied logins, chat prompts, investigations, comments, emails, every containment
request and result, and every Admin change.

## System
Configuration checklist (no secret values shown), table sizes and session cleanup.

## Tools and panels (3.1)
* **Tools** lists everything connected and what is planned.
* Connectors (Logic Apps, APIs, enrichment lookups) are added from the Add connector tile in the Containment page or on Tools.
* Each Respond panel has its own targets, flow, protected-entity checks and recent actions.
* Theme follows the browser or OS; users can switch from the top-right menu, Settings, Theme.
