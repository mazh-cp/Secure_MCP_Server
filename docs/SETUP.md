# Setup guide

First-time deployment of `secure-mcp`. Aim is a least-privilege service that
fails closed if any secret is missing.

## 1. Prerequisites

- Python 3.11 or newer
- Network egress to `te.checkpoint.com:443` and `api.lakera.ai:443` only.
  All other outbound traffic should be blocked at the host firewall —
  defense in depth against accidental data egress.
- An API key for Check Point Threat Emulation (cloud) and for Lakera Guard,
  both stored in your secrets manager (Vault / cloud KMS-backed store).
  Never paste keys into the codebase or commit them.

## 2. Install

```bash
git clone <repo> secure-mcp && cd secure-mcp
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest    # confirm 42 tests pass
```

## 3. Create the identity file

The identity file declares which tool scopes this instance is allowed to
expose. Different MCP clients get different identity files — that is how
scopes are partitioned under the stdio transport.

```bash
sudo install -d -m 0700 -o secure-mcp /etc/secure-mcp
sudo install -m 0600 -o secure-mcp identity.example.json /etc/secure-mcp/identity.json
sudo $EDITOR /etc/secure-mcp/identity.json
```

```json
{
  "caller_id": "soc-analyst-desktop",
  "allowed_tools": ["threat_emulation", "ai_guard"]
}
```

Set `allowed_tools` to the smallest set the caller actually needs.

## 4. Provision secrets

The recommended pattern is a wrapper script that pulls secrets from Vault and
execs the server with them in env — secrets never touch disk. See
[deploy/vault-env-load.sh.example](../deploy/vault-env-load.sh.example).

For development only, you can copy `.env.example` to `.env`, fill in real
values, and use a tool such as `direnv` to load it. **Never commit `.env`** —
it is already in `.gitignore`.

Required / optional environment variables:

| Variable                        | Required? | Purpose                                       |
| ------------------------------- | --------- | --------------------------------------------- |
| `SECURE_MCP_IDENTITY_FILE`      | yes       | Path to the JSON identity file (step 3)       |
| `CHECKPOINT_TE_API_KEY`         | yes       | Threat Emulation cloud API key                |
| `LAKERA_GUARD_API_KEY`          | yes       | Lakera Guard API key                          |
| `CHECKPOINT_TC_API_KEY`         | if intel scope | ThreatCloud key — needed only when a `threat_intel`/`url_category`/`anti_phishing` scope is granted |
| `CHECKPOINT_TC_BASE_URL`        | no        | ThreatCloud base (default `https://rep.checkpoint.com`; VERIFY) |
| `SECURE_MCP_AUDIT_LOG_PATH`     | yes       | JSONL audit log; storage must be encrypted    |
| `SECURE_MCP_AUDIT_HMAC_KEY`     | recommended | HMAC key (hex/raw) for tamper-evident chaining |
| `SECURE_MCP_DLP_MODE`           | no        | `block` / `redact` (default) / `flag`         |
| `SECURE_MCP_DAILY_QUOTA`        | no        | Daily call cap (default 0 = unlimited)        |
| `SECURE_MCP_UPLOAD_DIR`         | yes       | Transient upload staging dir                  |
| `SECURE_MCP_MAX_UPLOAD_BYTES`   | no        | Per-file cap (default 32 MiB)                 |
| `SECURE_MCP_RATE_LIMIT_PER_MIN` | no        | Per-scope call cap (default 60)               |

## 5. Smoke test

With env populated and identity file in place:

```bash
.venv/bin/python -c "from secure_mcp.server import build_server; build_server()"
```

A clean exit means: config loaded, TLS bases validated, SSRF guard passed,
audit log opened, DLP/quota/rate controls initialized, and the tools for the
granted scopes registered (up to 15 with all six scopes). Any failure here is
a deploy config problem — fix before exposing the server to a client.

The server fails closed on misconfiguration: an invalid `SECURE_MCP_DLP_MODE`,
or a granted intel scope without `CHECKPOINT_TC_API_KEY`, raises at build time
rather than starting in a degraded state.

## 6. Wire to an MCP client

For Claude Desktop or similar stdio MCP clients, register the server with a
launcher that injects secrets at exec time. Example for Claude Desktop config:

```json
{
  "mcpServers": {
    "secure-broker": {
      "command": "/opt/secure-mcp/deploy/vault-env-load.sh",
      "args": ["/opt/secure-mcp/.venv/bin/secure-mcp"]
    }
  }
}
```

The launcher is responsible for pulling secrets from Vault and exec-ing the
real entrypoint with them in env. The client never sees the keys.

## 7. Production deployment

For server-style deployments, use the systemd unit at
[deploy/secure-mcp.service](../deploy/secure-mcp.service) as a starting
point. It runs the server as a dedicated unprivileged user with hardening
flags (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, etc.).

Create the service user once:

```bash
sudo useradd --system --shell /usr/sbin/nologin --home /var/lib/secure-mcp secure-mcp
sudo install -d -m 0750 -o secure-mcp -g secure-mcp /var/lib/secure-mcp/staging
sudo install -d -m 0700 -o secure-mcp -g secure-mcp /var/log/secure-mcp
```

Place secrets via your secret-provisioning agent (Vault Agent, AWS SSM, etc.)
or via the wrapper script — not via static env files in `/etc`.

## 8. Next steps

- Operational runbook: [docs/ADMIN.md](ADMIN.md)
- When upstream API specs change: update the path constants in
  [adapters/checkpoint_te.py](../src/secure_mcp/adapters/checkpoint_te.py) and
  [adapters/lakera_guard.py](../src/secure_mcp/adapters/lakera_guard.py),
  re-run `pytest`, redeploy.
