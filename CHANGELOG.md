# Changelog

## [0.2.0] - 2026-06-02

### Added

- `secure-mcp-admin` — operator console MCP server (policy, scopes, service control).
- `secure-mcp-edge` — lightweight edge verdict MCP for integration gateways.
- Shared policy store and scope registry (`policy_store.py`, `scopes.py`).
- Systemd templates: `secure-mcp@.service`, `secure-mcp-admin.service`, polkit restart rules.
- Docs: `CONSOLE.md`, `EDGE-INTEGRATION.md`; expanded `SETUP.md` and `ADMIN.md`.

### Changed

- Replaced single `deploy/secure-mcp.service` with instance template + admin unit.
- Extended `.env.example` and config validation for admin/edge entrypoints.

### Tests

- 177 pytest cases covering broker, admin, edge, and policy store.

## [0.1.0] - 2026-06-01

- Initial hardened MCP broker (Threat Emulation, Lakera Guard, ThreatCloud tools).
- DLP egress filter, tamper-evident audit, quota, rate limit, circuit breaker.
