# Adding a tool to Raven Cyber AI

## Without code
1. Sign in as a user with `containment.manage_targets`.
2. Open Containment and press **Add connector**, or use the tile on the Tools page.
3. Pick a category:
   * `ip_block`, `url_block`, `device_isolation`, `advanced`: appears in the matching Respond panel.
   * `enrichment`: appears as a lookup in the Entity history tab of an incident.
4. Fill the URL, method, headers and body. Placeholders: `{{indicator}}`, `{{indicator_type}}`, `{{category}}`, `{{target_name}}`, `{{justification}}`, `{{prompt}}`, `{{timestamp}}`, `{{user.email}}`, `{{param.x}}`, `{{env.CONTAINMENT_X}}`.
5. URLs and headers are encrypted at rest. Only https public destinations are allowed.

Keep API keys in `.env` as `CONTAINMENT_<NAME>` and reference them as `{{env.CONTAINMENT_<NAME>}}` in a header.

## With code
Register a tool in `src/tools/builtin.py`:

```python
register(Tool(
    key="crowdstrike", name="CrowdStrike Falcon", vendor="CrowdStrike", category="EDR", icon="🦅",
    description="Endpoint detections and host containment.",
    capabilities=("detect", "contain"),
    status=lambda: ("configured", "") if os.getenv("CROWDSTRIKE_CLIENT_ID") else ("missing", "set CROWDSTRIKE_CLIENT_ID"),
    nav="device_isolation",
))
```

* `status` returns `("configured" | "missing" | "planned", detail)`.
* `test` (optional) returns a success message or raises.
* `nav` is a page key from the catalog in `app.py`.

Then add a test in `tests/test_targets.py` and an entry in `CHANGELOG.md`.
