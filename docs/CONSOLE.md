# Management console

`secure-mcp-admin` is a Check Point-branded web console for operating the
broker. It is a **separate process** from the MCP stdio servers, so it manages
**persistent configuration** (applied on the next MCP server start) and gives
**live inspection** of the audit trail and upstream reachability. It never
displays or edits secret key *values* — those stay in Vault/env.

## What it does

| Tab | Capability | Effect |
|---|---|---|
| **Overview** | Status cards + contextual guidance | Read-only |
| **Identities & Scopes** | Create / update / delete caller identity files; per-scope checkboxes validated against the known scope set | Persistent — applied on MCP server (re)start |
| **Configuration** | DLP mode, daily quota, rate limit | Persistent — written to the op-config file, read by the MCP server at startup |
| **Audit Trail** | Chain-verification status, event/denial/DLP counts, recent entries | Read-only |
| **Upstream Health** | Live TLS reachability probe to TE / ThreatCloud / Lakera (no credentials sent) | Read-only |
| **Instances** | View managed systemd units and restart them to apply config/identity changes | Opt-in; allowlisted |

Every mutation is recorded to a **separate** tamper-evident admin-audit log
(`SECURE_MCP_ADMIN_AUDIT_LOG`) — separate because two processes appending to
one hash-chained file would break verification.

## Security model

- **Authentication on every data/mutation endpoint.** Sign-in exchanges the
  admin token (`SECURE_MCP_ADMIN_TOKEN`, constant-time compared) for a short-
  lived HMAC-signed session token; all `/api/*` calls require it. Failed
  logins are throttled with per-source lockout.
- **Loopback by default.** Binds `127.0.0.1`. Binding to any other interface
  **without TLS is refused** (fails closed). Set `SECURE_MCP_ADMIN_TLS_CERT/KEY`
  for remote access — TLS 1.2+ is enforced.
- **No secrets exposed.** API keys and the audit HMAC key are never returned
  by any endpoint or rendered in the UI. Audit `details` are already redacted
  at write time.
- **Hardened responses.** CSP (`default-src 'none'`), `X-Frame-Options: DENY`,
  `nosniff`, `no-referrer`, `no-store` on every response. Input validated:
  caller IDs are slug-checked (no path traversal), scopes must be known, config
  values range-checked.
- **Single-file UI.** One self-contained HTML document (embedded CSS + minimal
  inline JS, no external resources).

## Run it

```bash
export SECURE_MCP_ADMIN_TOKEN=...          # from Vault/KMS
export SECURE_MCP_IDENTITY_DIR=/etc/secure-mcp/identities
export SECURE_MCP_CONFIG_FILE=/etc/secure-mcp/config.json
export SECURE_MCP_AUDIT_LOG_PATH=/var/log/secure-mcp/audit.jsonl
export SECURE_MCP_AUDIT_HMAC_KEY=...       # so the console can verify the chain
secure-mcp-admin
# → admin console listening http://127.0.0.1:8765
```

Open the URL, sign in with the admin token, and manage the deployment.
For remote access, set the TLS cert/key and a non-loopback host — see
[deploy/secure-mcp-admin.service](../deploy/secure-mcp-admin.service).

## The restart-to-apply model (important)

The console writes config and identity files; the MCP stdio servers read them
at startup. Changes therefore take effect when the relevant MCP server next
(re)starts — the console does not mutate a running process's in-memory state
(there is no IPC channel for that, by design). The UI states this on the
Configuration tab. After a change, restart the affected MCP server instance(s)
(`systemctl restart secure-mcp@<instance>`).

## Precedence

For the operational knobs (`dlp_mode`, `daily_quota`, `rate_limit_per_minute`):
**op-config file (console) > environment variable > built-in default.** Secrets
ignore this entirely — they always come from env/Vault.

## Restarting instances (Instances tab)

Config/identity changes apply when an MCP server (re)starts. The **Instances**
tab can restart the affected systemd units from the console — opt-in and off by
default.

**How it's kept safe (no dynamic execution with user input):**
- The console restarts only units in an operator-set **allowlist**
  (`SECURE_MCP_MANAGED_UNITS`, comma-separated). An empty list disables the
  whole feature.
- Execution is a **fixed `subprocess` argv list** — `["systemctl","restart",
  <unit>]` — never a shell string and never built by interpolating user input.
  The unit must be a member of the allowlist (and pass a strict format check).
  User input only *selects* a pre-authorized target.
- Every restart (and every denied attempt) is written to the tamper-evident
  admin-audit log; the UI requires explicit confirmation.

**One-click apply & restart.** The Configuration tab has a **Save & Restart
Affected** button that saves the op-config and then restarts all managed units
(config changes affect every instance, since they share the op-config file).
Each restart still goes through the per-unit allowlist + audit path. The
Instances tab also offers per-unit Restart and Restart All.

**Granting privilege (least-privilege).** The console process needs permission
to restart exactly those units — do NOT run it as root. Prefer the ready-made
polkit rule at [deploy/polkit/49-secure-mcp-restart.rules](../deploy/polkit/49-secure-mcp-restart.rules),
which authorizes only the `restart` verb on `secure-mcp@*.service` for the
`secure-mcp` user (works with the admin unit's `NoNewPrivileges=true`).
Alternatively, a scoped sudoers line plus `SECURE_MCP_RESTART_USE_SUDO=true`
(note: sudo needs setuid, so drop `NoNewPrivileges=true` if you use it):

```
secure-mcp ALL=(root) NOPASSWD: /usr/bin/systemctl restart secure-mcp@*.service
```

If no allowlist is configured, the tab explains how to restart from the host
directly: `systemctl restart secure-mcp@<instance>`.
