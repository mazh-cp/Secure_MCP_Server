# secure-mcp

A hardened MCP broker that fronts Check Point security services — and acts as
a **data-egress control plane** in its own right. Beyond proxying to the
upstreams, the broker enforces DLP, tamper-evident audit, quota, and
resilience controls that none of the individual services provide.

```
MCP client ─stdio─▶ secure-mcp ─┬─▶ te.checkpoint.com   (Threat Emulation cloud)
                    │            ├─▶ rep.checkpoint.com  (ThreatCloud reputation)
                    │            └─▶ api.lakera.ai       (Guard, TEXT-ONLY)
                    │
                    └─ control plane: DLP egress filter · tamper-evident audit
                       · per-scope rate limit · daily quota · circuit breaker
```

## Tools exposed

| Scope               | Tool             | Purpose                                    |
| ------------------- | ---------------- | ------------------------------------------ |
| `threat_emulation`  | `emulate_file`   | Detonate a staged file in TE cloud sandbox |
|                     | `query_verdict`  | Look up cached verdict by sha256           |
|                     | `emulate_url`    | Detonate a URL                             |
| `file_sandboxing`   | `submit_file`    | Deep sandbox submission across OS images   |
|                     | `extract_threats`| CDR / Threat Extraction                    |
|                     | `get_report`     | Full forensic report by job id             |
| `ai_guard`          | `screen_prompt`  | Lakera injection / jailbreak check (text)  |
|                     | `screen_output`  | Lakera PII / moderation check (text)       |
|                     | `screen_payload` | Policy-bound screening (text + project_id) |
| `threat_intel`      | `lookup_ip`      | ThreatCloud IP reputation                  |
|                     | `lookup_domain`  | ThreatCloud domain reputation              |
|                     | `lookup_url`     | ThreatCloud URL reputation                 |
|                     | `lookup_hash`    | ThreatCloud file-hash reputation           |
| `url_category`      | `categorize_url` | URL Filtering category + risk class        |
| `anti_phishing`     | `score_url`      | Zero-Phishing ML score for a URL           |

Each scope is granted independently per deployment via the identity file.
Coverage tools (`threat_intel` / `url_category` / `anti_phishing`) only wire
up when their scope is granted, and then require `CHECKPOINT_TC_API_KEY`.

## Security posture

- **Secrets** never in code. Loaded from env at process start; placeholder
  values rejected by `config.load_settings()` (fails closed).
- **TLS** enforced on all upstreams; `verify=True` explicit, redirects off.
- **SSRF guard** at config time (literal-IP check) and connect time (DNS
  resolution check) — see [http_client.py](src/secure_mcp/http_client.py).
- **Per-tool scopes** enforced on every call via the identity file.
- **Input validation** for sha256/hashes, IP, domain, URL, file paths
  (traversal-safe), and text size.
- **Lakera egress** is TEXT-ONLY by design; ThreatCloud receives indicators
  only — neither path exposes customer files or threat-intel artifacts.
- **No dynamic execution** of user input anywhere on the broker host;
  detonation happens *only* inside the Check Point sandbox upstream.

### Egress control plane (broker-enforced, independent of upstreams)

- **DLP egress filter** ([dlp.py](src/secure_mcp/dlp.py)) — local detection of
  AWS/GitHub/Slack/OpenAI/Google keys, JWTs, private keys, US SSNs, and
  Luhn-valid card numbers. Runs *before* any text reaches Lakera. Modes:
  `block` / `redact` (default) / `flag`. Findings carry type + count only,
  never the matched value.
- **Tamper-evident audit** ([audit.py](src/secure_mcp/audit.py)) — HMAC-SHA256
  hash-chained entries; `python -m secure_mcp.audit_verify <log>` detects any
  edit, truncation, or reordering. Owner-only file; encrypted-at-rest volume.
- **Per-scope rate limit** ([rate_limit.py](src/secure_mcp/rate_limit.py)) —
  token bucket, default 60/min, isolates one scope's burst from another.
- **Daily quota** ([quota.py](src/secure_mcp/quota.py)) — fail-closed daily
  call cap on top of the rate limit; bounds upstream cost / abuse blast radius.
- **Per-upstream circuit breaker**
  ([circuit_breaker.py](src/secure_mcp/circuit_breaker.py)) — opens after N
  consecutive failures so the broker doesn't amplify an upstream outage.

Every tool call runs `ctx.preflight(scope)` → **authorize → quota → rate** →
validate → (DLP on egress paths) → upstream → audit, with both success and
denial recorded to the tamper-evident log.

## Management console

`secure-mcp-admin` is a Check Point-branded web console for operating the
broker: manage caller identities/scopes, set DLP mode / quota / rate limit,
review the tamper-evident audit trail, and probe upstream health — with
contextual guidance. Auth-gated (admin token → short-lived session),
loopback-by-default, TLS-required for remote access, and it never exposes
secret values. It manages persistent config (applied on MCP server restart)
and gives live inspection. See [docs/CONSOLE.md](docs/CONSOLE.md).

```bash
SECURE_MCP_ADMIN_TOKEN=... SECURE_MCP_IDENTITY_DIR=... secure-mcp-admin
# → http://127.0.0.1:8765
```

## Edge PDP (browser policy enforcement over the internet)

`secure-mcp-edge` is an internet-facing **Policy Decision Point** for browser
extensions: devices enroll for a short-lived token, then ask for URL verdicts
(`allow`/`warn`/`block`) instead of carrying Check Point keys and scanning
locally. Phase 1 is **indicator-only** (URL/domain/hash) — see
[docs/EDGE-INTEGRATION.md](docs/EDGE-INTEGRATION.md). Reuses the ThreatCloud
adapter, rate limit, quota, and tamper-evident audit; refuses non-loopback
binds without TLS.

```bash
SECURE_MCP_EDGE_ENROLLMENT_SECRET=... CHECKPOINT_TC_API_KEY=... secure-mcp-edge
# → POST /edge/v1/enroll  then  POST /edge/v1/url/verdict
```

Phase 2 adds a **central policy authority**: author per-group browser policy in
the admin console (Browser Policy tab), and the edge serves it as an
Ed25519-signed envelope (`GET /edge/v1/policy`, ETag-polled) with telemetry
(`POST /edge/v1/events`) flowing into the tamper-evident audit log. The plugin
verifies the signature with WebCrypto before applying. Devices poll — no MCP
restart needed for policy changes.

## Quickstart

See [docs/SETUP.md](docs/SETUP.md) for the full first-time walkthrough.
See [docs/ADMIN.md](docs/ADMIN.md) for ongoing operations, and
[docs/CONSOLE.md](docs/CONSOLE.md) for the management console.

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest                  # 177 tests
```

## Upstream API caveats

All adapters use publicly documented API shapes (Check Point Threat Prevention
API; ThreatCloud reputation; Lakera Guard v2). Endpoint paths are class
constants in each adapter file — verify them against your subscription's
current docs before flipping the service on:

- [adapters/checkpoint_te.py](src/secure_mcp/adapters/checkpoint_te.py) —
  `QUERY_PATH`, `UPLOAD_PATH`, `URL_QUERY_PATH`, `REPORT_PATH`
- [adapters/threatcloud.py](src/secure_mcp/adapters/threatcloud.py) —
  `REPUTATION_PATH`, `CATEGORIZE_PATH`, `PHISHING_PATH`, and `CHECKPOINT_TC_BASE_URL`
- [adapters/lakera_guard.py](src/secure_mcp/adapters/lakera_guard.py) —
  `GUARD_PATH` and the project-id routing form
