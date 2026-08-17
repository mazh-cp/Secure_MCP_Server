# secure-mcp documentation

Hardened MCP broker + control plane for Check Point Threat Emulation,
ThreatCloud, and Lakera Guard — with an admin console, an internet-facing edge
PDP for browser policy, and an MCP guard for agent tool-calls.

Start here, then jump to the doc for your task.

## Start here
- **[../README.md](../README.md)** — what it is, the services, quickstart.
- **[SETUP.md](SETUP.md)** — first-time install, identities, secrets, systemd.
- **[LOCAL-VALIDATION.md](LOCAL-VALIDATION.md)** — `validate_local.py` (22-check
  report) and `run_local.py` (interactive instance) — no real keys needed.

## Operate
- **[CONSOLE.md](CONSOLE.md)** — the admin console: tabs, auth, restart model,
  Browser Policy, and Keys & Secrets (write-only key provisioning).
- **[ADMIN.md](ADMIN.md)** — day-2 ops: identities/scopes, secret rotation, the
  two log streams, audit review + verification, quotas, circuit breaker, IR.

## Deploy
- **[DEPLOY.md](DEPLOY.md)** — host the backend on a VM/server: Docker Compose
  or systemd, TLS, firewall/egress, secrets injection, persistence.

## Architecture & integration
- **[ARCHITECTURE.md](ARCHITECTURE.md)** — **v0.8 guard-first topology**: Cursor →
  `secure-mcp-guard` → complementary official `@chkp/*` MCP servers; broker owns
  TE/ThreatCloud/Lakera (no double exposure).
- **[EDGE-INTEGRATION.md](EDGE-INTEGRATION.md)** — browser plugin ⇄ secure-mcp as
  a centralized PDP: enrollment, indicator-only URL verdicts, Ed25519-signed
  policy, telemetry → audit (Phases 1–2 built).
- **[MCP-GUARD.md](MCP-GUARD.md)** — the policy plane for agent tool-calls:
  tool-poisoning / prompt-injection screening + the guarded proxy gate.

## Security
- **[SECURITY.md](SECURITY.md)** — trust boundaries, system-wide controls, the
  admin-portal security model, and the latest review findings.

## Strategy
- **[COMPETITIVE-STRATEGY.md](COMPETITIVE-STRATEGY.md)** — competitive review vs.
  industry browser-security products and the MCP-native differentiator.

## Components at a glance

| Service | Entry point | Transport | Role |
|---|---|---|---|
| Broker | `secure-mcp` | stdio | TE/ThreatCloud/Lakera tools + control plane |
| Admin console | `secure-mcp-admin` | HTTPS (internal) | management plane (PAP) |
| Edge PDP | `secure-mcp-edge` | HTTPS (internet) | browser verdicts + signed policy |
| MCP guard | `secure-mcp-guard` | stdio | screen + gate agent tool-calls |

The console's **Read Me** and **Release Notes** tabs mirror this overview and the
changelog (`src/secure_mcp/release.py`) so operators have in-product docs too.
