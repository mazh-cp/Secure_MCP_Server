# Security overview & review

*Covers the admin portal in depth, plus the system-wide posture. Findings from
the latest review are in §4.*

## 1. Components & trust boundaries

| Component | Transport | Exposure | Holds secrets? |
|---|---|---|---|
| `secure-mcp` broker | stdio (MCP) | client host | API keys in memory (from env/keystore) |
| `secure-mcp-guard` | stdio (MCP) | client host | — |
| `secure-mcp-admin` | HTTPS | **internal only** (loopback/VPN) | admin token, keystore master key |
| `secure-mcp-edge` | HTTPS | **internet-facing** | enrollment secret, ThreatCloud key |

Upstreams (Check Point TE/ThreatCloud, Lakera) are reached only by the broker/
edge over TLS. The data-egress boundary is explicit: indicators (URL/hash/domain)
and DLP-screened text only; never raw customer files to non-approved sinks.

## 2. Controls (system-wide)

- **Secrets**: never in code/config/VCS. Injected from env/Vault, or stored in
  an **AES-256-GCM** keystore under a KMS-injected master key. Write-only via the
  API; fingerprint-only display.
- **Transport**: TLS 1.2+ enforced; services refuse a non-loopback bind without
  TLS (fail closed). **HSTS** set when TLS is enabled.
- **Tamper-evident audit**: HMAC-SHA256 hash-chained; `python -m
  secure_mcp.audit_verify` detects edits/truncation. Secret-shaped fields
  redacted at write.
- **Input validation**: allowlists for scopes, policy keys, config ranges;
  sha256/hash/IP/domain/URL validators; path-traversal guards on file refs and
  identity/policy names.
- **SSRF**: literal-IP + DNS-resolution checks on outbound hosts (broker), URL
  validator rejects private/loopback ranges (edge).
- **Abuse limits**: per-scope rate limit, per-caller daily quota, per-upstream
  circuit breaker.
- **DLP egress filter**: redacts/blocks secrets before text crosses to Lakera or
  out through the MCP guard; injection/tool-poisoning screening on MCP traffic.
- **No dynamic execution** of user input; restart is a fixed allowlisted argv.

## 3. Admin portal — security model

- **Authentication**: admin token compared in constant time → short-lived
  HMAC-signed session token (signing key derived from the admin token, so
  rotating the token invalidates sessions). Every `/api/*` route except
  `/api/login` requires a valid session.
- **Brute force**: per-source login throttle with lockout.
- **CSRF**: none — the SPA holds the session in `sessionStorage` and sends it as
  a `Bearer` header; there are no cookies / ambient credentials, so cross-site
  requests cannot authenticate.
- **Response hardening**: CSP `default-src 'none'` + `frame-ancestors 'none'`,
  `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `no-store`, and HSTS on TLS.
- **Secrets**: no endpoint ever returns a key value; only status + fingerprint.
- **Auditing**: every identity/policy/config/secret/restart action is written to
  the tamper-evident admin-audit log (separate chain from the broker's).
- **Error handling**: generic 500s (no stack to client); the ops logger never
  logs request bodies or secret values.

## 4. Review findings (latest)

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | No HSTS header under TLS | Low | **Fixed** — `Strict-Transport-Security` added (admin + edge) when TLS enabled |
| 2 | CSP allows `'unsafe-inline'` (script/style) | Low | **Accepted** — inherent to the single-file console; mitigated by `default-src 'none'`, no external origins, no cookies. Move to nonce-CSP if hardening further |
| 3 | Login throttle is per-source-IP, in-memory | Medium (proxied) | **Documented** — behind a reverse proxy all clients share the proxy IP, making lockout global. Keep admin loopback/VPN-only (default) or rate-limit at the proxy; do not blindly trust `X-Forwarded-For` |
| 4 | Throttle/session state resets on restart | Low | **Accepted** — fine for a single instance; use a shared store if scaled horizontally |
| 5 | Session security depends on admin-token strength | — | **By design** — the admin token must be high-entropy and Vault-injected (the session signing key is derived from it) |
| 6 | MCP guard forwarder live; v0.8 guard-first topology | Info | **Shipped** — registry + `@chkp/*` complementary upstreams; see ARCHITECTURE.md |

No high/critical findings. Strengths: no-CSRF design, write-only secrets,
tamper-evident audit, fail-closed config, broad input validation + SSRF guards.

## 5. Operational guidance

- Keep the **admin console internal** (loopback + SSH tunnel, or an internal
  reverse proxy / VPN). Never publish it. Only the **edge PDP** is internet-facing.
- Use a strong, Vault-injected `SECURE_MCP_ADMIN_TOKEN` and rotate it (rotation
  invalidates live sessions).
- Put state/audit volumes on encrypted-at-rest storage; back them up; verify the
  audit chain periodically (`audit_verify`).
- Firewall outbound egress to TE/ThreatCloud/Lakera/Vault only.
- See [DEPLOY.md](DEPLOY.md) for hardened systemd/Docker deployment and
  [CONSOLE.md](CONSOLE.md) for the admin model.
