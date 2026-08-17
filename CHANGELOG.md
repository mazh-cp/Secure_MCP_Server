# Changelog

## [0.8.0] - 2026-08-17

### Guard-first topology + official Check Point MCP integration

- Reference architecture: Cursor → `secure-mcp-guard` → complementary `@chkp/*` servers from [CheckPointSW/mcp-servers](https://github.com/CheckPointSW/mcp-servers); TE/reputation stay on the broker (no double exposure).
- Guard registry `${VAR}` expansion and parent-env merge for `npx` upstreams.
- Guard-only identities (`mcp_proxy`) no longer require TE/Lakera API keys.
- Templates: `deploy/topology/*`, `scripts/materialize_topology.py`, `docs/ARCHITECTURE.md`.

## [0.7.0] - 2026-06-15

### Live MCP forwarder + cross-browser packaging

- MCP guard proxies real upstream MCP servers (stdio client bridged into the sync gate; allowlisted via `SECURE_MCP_GUARD_REGISTRY`) — `guard_call` is now live.
- Cross-browser plugin generator: Chrome/Edge/Firefox packages + Safari converter, one bundled background, branded icons, cross-browser native-host installer + native-messaging host bridge (`scan_file` / `scan_url` / `query_report` / `cache_stats`).

## [0.6.0] - 2026-06-02

### VM / server deployment

- Docker Compose deployment for the edge PDP + admin console (TLS, persistent volumes, non-root, read-only rootfs, fail-closed secret injection).
- systemd unit for the edge PDP + Vault env wrapper; completed deploy assets.
- Security review: HSTS on TLS for admin + edge; `SECURITY.md` threat model.
- Console: Read Me + Release Notes sections.

## [0.5.0] - 2026-06-01

### Keys & Secrets management

- AES-256-GCM encrypted keystore with KMS-injected master key; values write-only, fingerprint-only display.
- `load_settings` resolves upstream keys: env > keystore.
- Console Keys & Secrets tab with masked set/rotate, connectivity test, delete.

## [0.4.0] - 2026-05-30

### MCP Guard

- Policy-enforcing MCP gateway: authz → quota → rate → outbound-arg DLP → forward → response injection+DLP screen → audit.
- Tool-poisoning / prompt-injection screening of tool descriptors and responses.
- `secure-mcp-guard` server exposing `screen_tool` / `screen_response` standalone.

## [0.3.0] - 2026-05-28

### Edge PDP + central policy

- Internet-facing edge PDP: device enrollment, indicator-only URL verdicts.
- Central policy authority: Ed25519-signed per-group policy, ETag polling, telemetry → audit. Browser plugin wired to consume it (verify-before-apply).

## [0.2.0] - 2026-05-25

### Admin console

- Check Point-branded management console: identities, config, audit, health, instance restart, browser-policy authoring.
- `secure-mcp-admin` and `secure-mcp-edge` entrypoints; policy store and scope registry.
- Systemd templates: `secure-mcp@.service`, `secure-mcp-admin.service`, polkit restart rules.

## [0.1.0] - 2026-05-20

### Broker + control plane

- MCP broker for TE / ThreatCloud / Lakera (6 scopes, 15 tools).
- DLP egress filter, tamper-evident audit, per-scope rate limit, daily quota, per-upstream circuit breaker, SSRF/TLS guards.
