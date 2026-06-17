# Deploying the backend on a VM / server

## What gets hosted

Only the **network services** are server-hosted:

| Service | Role | Exposure |
|---|---|---|
| **edge PDP** (`secure-mcp-edge`) | URL verdicts + signed policy for browser plugins | **Internet-facing** (TLS) |
| **admin console** (`secure-mcp-admin`) | management UI (identities, policy, keys, audit) | **Internal only** — admin subnet / VPN / SSH tunnel |

The **broker** (`secure-mcp`) and **MCP guard** (`secure-mcp-guard`) are **stdio**
MCP servers spawned by each MCP client (Claude Desktop, Cursor, agents) — they
run wherever the client runs, not on this server.

Two supported paths: **Docker Compose** (portable, recommended) or **systemd**
(bare VM). Both inject secrets at runtime — nothing secret is baked into images
or committed.

---

## Option A — Docker Compose (recommended)

On a VM with Docker + Compose:

```bash
cd deploy/docker
./gen-dev-certs.sh                 # self-signed TLS for dev (use real certs in prod)
cp .env.example .env               # fill secrets, OR export them from Vault instead
#   openssl rand -hex 16  → SECURE_MCP_ADMIN_TOKEN, SECURE_MCP_EDGE_ENROLLMENT_SECRET
#   openssl rand -hex 32  → SECURE_MCP_AUDIT_HMAC_KEY, SECURE_MCP_KEYSTORE_MASTER_KEY
docker compose up -d --build
```

- **edge** publishes `:8770` (front it with TLS / a reverse proxy for the public).
- **admin** binds `127.0.0.1:8765` on the host — reach it via SSH tunnel
  (`ssh -L 8765:127.0.0.1:8765 vm`) or an internal reverse proxy. Do **not**
  set `ADMIN_PUBLISH_ADDR=0.0.0.0` on an untrusted network.
- Persistent state lives in named volumes: `state` (`/etc/secure-mcp` —
  identities, policies, signing keys, `secrets.enc`, `config.json`) and `logs`
  (`/var/log/secure-mcp` — tamper-evident audit). **Back these up; encrypt the
  underlying volume at rest.**
- Containers run **non-root, read-only rootfs, `cap_drop: ALL`,
  `no-new-privileges`** (see `docker-compose.yml`).

Secrets from Vault instead of a file:
```bash
export SECURE_MCP_ADMIN_TOKEN=$(vault kv get -field=token secret/secure-mcp/admin)
export CHECKPOINT_TC_API_KEY=$(vault kv get -field=api_key secret/secure-mcp/threatcloud)
# … then: docker compose up -d
```
`compose` fails closed (`${VAR:?}`) if a required secret is missing.

---

## Option B — systemd on the VM

```bash
sudo useradd --system --shell /usr/sbin/nologin --home /var/lib/secure-mcp secure-mcp
sudo install -d -m 0700 -o secure-mcp -g secure-mcp \
     /etc/secure-mcp /etc/secure-mcp/identities /etc/secure-mcp/policies \
     /etc/secure-mcp/keys /etc/secure-mcp/tls /var/log/secure-mcp
# Install the app into /opt/secure-mcp/.venv (python -m venv + pip install .)

# Copy + edit the Vault wrappers (chmod 0750), then the units:
sudo cp deploy/edge-env-load.sh.example  /opt/secure-mcp/deploy/edge-env-load.sh
sudo cp deploy/admin-env-load.sh.example /opt/secure-mcp/deploy/admin-env-load.sh
sudo cp deploy/secure-mcp-edge.service deploy/secure-mcp-admin.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now secure-mcp-edge secure-mcp-admin
```

The units run hardened (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`,
empty `CapabilityBoundingSet`, …). The broker template unit
(`secure-mcp@.service`) is for client hosts, not this server. See
[SETUP.md](SETUP.md) and [CONSOLE.md](CONSOLE.md) for per-service config.

---

## TLS

- **edge** is internet-facing → use real certs. Easiest: front it with Caddy or
  nginx doing Let's Encrypt, proxying to the edge (bind it loopback behind the
  proxy), or set `SECURE_MCP_EDGE_TLS_CERT/KEY` to real certs directly.
- **admin** → internal CA cert, or keep it loopback + reach via SSH tunnel.
- `gen-dev-certs.sh` produces self-signed certs for **dev only**.
- The services **refuse to bind a non-loopback interface without TLS** (fail
  closed) — so remote exposure always has transport encryption.

## Networking / firewall

- **Inbound:** edge `:443` (or `:8770`) open to where browsers live; admin port
  restricted to the admin subnet / VPN (ideally never published).
- **Outbound (egress allowlist):** `rep.checkpoint.com:443` (ThreatCloud),
  `te.checkpoint.com:443`, `api.lakera.ai:443`, and your Vault/KMS endpoint —
  block the rest at the host/cloud firewall.

## Secrets & data handling (policy)

- Secrets are injected at runtime from env/Vault — **never** baked into images,
  written to plaintext config, or committed. `.env`, `*.enc`, `*.key`, `*.crt`
  are gitignored.
- The `secrets.enc` keystore is AES-256-GCM encrypted under a KMS-injected master
  key; the audit logs are HMAC-chained (verify with
  `python -m secure_mcp.audit_verify`). Keep the state/log volumes on
  encrypted-at-rest storage and back them up.

## Validate the deployment

```bash
# automated, in-process, no real keys (great for CI / a fresh VM smoke):
.venv/bin/python scripts/validate_local.py

# against the running services:
curl -sk https://EDGE_HOST:8770/edge/v1/healthz      # {"ok": true}
curl -sk https://ADMIN_HOST:8765/ | grep -o 'Management Console'
```
See [LOCAL-VALIDATION.md](LOCAL-VALIDATION.md).
