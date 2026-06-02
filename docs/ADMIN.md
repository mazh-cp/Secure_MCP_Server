# Admin guide

Day-2 operations for `secure-mcp`. Use alongside [SETUP.md](SETUP.md).

## Identity files & scopes

Each running instance is bound to one identity file. The file declares:

- `caller_id` — a stable, human-meaningful name; appears in every audit
  entry and operational log line. Use values that map back to a real
  person, role, or system (e.g. `soc-analyst-desktop`,
  `triage-pipeline-prod`).
- `allowed_tools` — the subset of `{threat_emulation, file_sandboxing,
  ai_guard}` this instance is permitted to expose. **Always set the
  smallest set the caller actually needs.**

Identity files live in `/etc/secure-mcp/identities/<caller_id>.json`, and the
systemd instance name equals the caller_id, so caller `soc-analyst` maps to
`secure-mcp@soc-analyst.service`. Manage these from the admin console, or by
hand:

### Adding a new caller

```bash
sudo install -m 0600 -o secure-mcp /dev/stdin /etc/secure-mcp/identities/<caller_id>.json <<'EOF'
{ "caller_id": "<caller_id>", "allowed_tools": ["ai_guard"] }
EOF
sudo systemctl enable --now secure-mcp@<caller_id>
```

(In the console: Identities & Scopes → create, then Instances → restart.)

### Revoking a caller

```bash
sudo systemctl disable --now secure-mcp@<caller_id>
sudo rm /etc/secure-mcp/identities/<caller_id>.json
```

Audit log entries already written remain — that is intentional.

## Secret rotation

Both API keys are read from env at process start and held in memory only.
**There is no hot-reload.** To rotate:

1. Issue a new key in the upstream console (Check Point Infinity Portal /
   Lakera dashboard).
2. Update the value in your secrets manager (Vault / KMS).
3. Restart the server instance(s). The old key remains valid in the upstream
   until you revoke it — leave a brief overlap window so in-flight calls
   succeed during rolling restart.
4. Revoke the old key upstream.

The audit log records nothing about the keys themselves; key changes leave
no trace in `audit.jsonl`. Track rotations in your normal change log.

## Two log streams

`secure-mcp` produces two distinct streams. They serve different purposes
and should be routed to different sinks.

### Audit log (`SECURE_MCP_AUDIT_LOG_PATH`)

- **Format:** JSONL, one entry per tool call attempt
- **Fields:** `seq`, `ts`, `caller_id`, `tool`, `action`, `result`
  (`ok`/`error`), `details` (per-tool identifiers; secret-shaped keys
  auto-redacted; `dlp` findings as type+count), `prev_hash`, `hash`
- **Tamper-evidence:** each entry is hash-chained to its predecessor. With
  `SECURE_MCP_AUDIT_HMAC_KEY` set, edits/truncation/reordering are detectable
  and not forgeable without the key. See "Audit integrity verification" below.
- **Permissions:** file created `0600`; the underlying volume **must** be
  encrypted at rest
- **Retention:** drive by compliance requirements; rotate with logrotate or
  equivalent. Note: rotation breaks the single-file chain — verify each
  segment against the key, and keep the rotated segments immutable.
- **Routing:** to an authorized, encrypted sink only — never to a general
  ops aggregator that might forward outside the Check Point boundary

### Operational log (stderr)

- **Format:** JSON, one event per line — `ts`, `lvl`, `name`, `msg`, plus
  any structured extras
- **Use:** startup config, upstream connection failures, rate-limit
  saturations, retry attempts
- **Never contains:** customer content, file bytes, prompt/response text,
  or secret values. Secret-shaped keys in `extra={}` are auto-redacted by
  [logger.py](../src/secure_mcp/logger.py).
- **Routing:** safe for general operational log aggregation

## Audit review — what to look for

| Pattern                                              | Likely meaning                          |
| ---------------------------------------------------- | --------------------------------------- |
| Frequent `result: error` with `error_type: AuthorizationError` | Misconfigured client / probing |
| Bursts of `error_type: RateLimitExceeded`            | Runaway client or under-sized limit     |
| `error_type: ValidationError` cluster on one caller  | Bad input source — investigate the call site |
| `error_type: CheckpointTEError` / `LakeraGuardError` / `ThreatCloudError` | Upstream HTTP failure — check `lvl: WARNING` ops-log lines for status codes |
| `error_type: DLPViolation` (block mode)              | A caller tried to send secrets/PII through `ai_guard` — investigate the source |
| `error_type: QuotaExceeded`                          | Daily budget hit — runaway client or under-sized quota |
| `error_type: CircuitOpenError`                       | Upstream is down and the breaker is shedding load |
| `details.dlp` non-empty on `result: ok`              | Secrets were redacted before egress (redact mode) — recurring hits mean a leaky caller |
| Calls outside business hours from a desktop caller   | Possible credential misuse              |

A starter query (jq) to surface authorization denials:

```bash
jq -c 'select(.result=="error" and .details.error_type=="AuthorizationError")' \
  /var/log/secure-mcp/audit.jsonl
```

Surface every call where DLP caught something on the egress path:

```bash
jq -c 'select(.details.dlp != null and (.details.dlp | length) > 0)' \
  /var/log/secure-mcp/audit.jsonl
```

## Audit integrity verification

Run the verifier any time you need to prove the log hasn't been altered
(incident response, compliance audit, before archiving a rotated segment):

```bash
SECURE_MCP_AUDIT_HMAC_KEY=<same key used at write time> \
  python -m secure_mcp.audit_verify /var/log/secure-mcp/audit.jsonl
# exit 0 = intact, 1 = tampering detected, 2 = usage/IO error
```

The key MUST match the one in use when the entries were written. If you rotate
the HMAC key, start a fresh log segment at the same time and record which key
covers which segment — a key change mid-file reads as tampering.

## DLP egress filter

`ai_guard` runs every prompt/response through the local DLP filter before any
text reaches Lakera. Mode is set by `SECURE_MCP_DLP_MODE`:

- **`redact`** (default) — replace detected secrets with `[REDACTED:type]`,
  send the sanitized text onward, record findings in the audit `details.dlp`.
  Screening still works; the secret never leaves the host.
- **`block`** — reject the call entirely (`DLPViolation`). Use when no text
  containing secrets should ever be screened externally.
- **`flag`** — pass text through unchanged but record findings. Use only for
  tuning/measurement, never as a steady-state egress posture.

Detections cover labeled cloud keys (AWS/GitHub/Slack/OpenAI/Google), JWTs,
PEM private keys, US SSNs, and Luhn-valid card numbers. The ruleset is
deliberately high-precision — extend it in
[dlp.py](../src/secure_mcp/dlp.py) `_PATTERNS` and add a test before relying
on a new detector. A finding never carries the matched value, only its type
and count, so it is always safe to log.

## Rate limit tuning

Default: 60 calls/min per scope per process. Tune via `SECURE_MCP_RATE_LIMIT_PER_MIN`.

- Buckets are in-memory and per-process. Restart resets the bucket.
- For multi-process or HTTP-transport deployments, replace
  [rate_limit.py](../src/secure_mcp/rate_limit.py) with a shared-state
  backend (Redis with `INCR` + EXPIRE, or your gateway's built-in limiter)
  before scaling out.
- The limit is a defense against runaway clients and a soft cap on upstream
  quota burn — it is not a substitute for the upstream's own quota.

## Daily quota

`SECURE_MCP_DAILY_QUOTA` caps total calls per process per UTC day (effectively
per caller under stdio). `0` disables it. The rate limiter smooths bursts; the
quota caps the day's total spend. It fails closed (`QuotaExceeded`) and resets
at UTC midnight. Like the rate limiter it is in-memory per-process — move to a
shared backend before scaling to multiple processes.

## Circuit breaker

Each upstream (TE, ThreatCloud, Lakera) has its own breaker on its HTTP client.
After 5 consecutive failures it opens for 30s, rejecting calls fast with
`CircuitOpenError` instead of piling retries onto a struggling upstream; after
the cooldown it allows a single half-open trial. Defaults live in
[circuit_breaker.py](../src/secure_mcp/circuit_breaker.py). A burst of
`CircuitOpenError` in the audit log means an upstream is down — correlate with
the `lvl: WARNING` ops-log lines for the HTTP status codes that tripped it.

## Network egress

Allow only:

- `te.checkpoint.com:443`
- `rep.checkpoint.com:443` (only if an intel scope is granted)
- `api.lakera.ai:443`
- Your Vault / KMS endpoint (for the secret-load wrapper)

Block everything else outbound on the broker host. A misrouted request that
hits an unexpected destination is one of the few things that can leak
customer telemetry outside the Check Point boundary; the firewall is the
last line of defense.

## Incident response

### Suspected API key compromise

1. Revoke the key in the upstream console **immediately** (do not wait for
   the rolling restart).
2. Issue a replacement; update Vault.
3. Restart all instances (`systemctl restart secure-mcp@*`).
4. Pull the audit log for the affected period — look for unusual
   `caller_id` patterns, off-hours activity, or actions the legitimate
   caller does not normally perform.
5. Review network egress logs at the firewall for the same window.

### Suspected abusive client

1. Identify the `caller_id` from the audit log.
2. Stop the server instance bound to that identity file.
3. Delete or empty the identity file; restart to confirm the scope set is
   now empty (the server will refuse to start — that's the desired state).
4. Open a ticket against the owner of that caller_id.

### Upstream returning unexpected response shape

The TE and Lakera adapters fall through to returning the raw body when the
documented wrapper shape is absent (see `_first_item` in the TE adapter).
If you see this in production:

1. Capture the raw response from the operational log
2. Compare against the latest API docs for your subscription
3. Update the path constants and/or `_first_item` logic; re-run `pytest`
4. Deploy

Do not "fix" the unexpected shape by silently filtering — surface it to the
caller so they don't act on incomplete data.

## Upgrades

```bash
git pull
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest         # must pass before redeploy
sudo systemctl restart secure-mcp@<instance>
```

If any `pytest` failure relates to upstream adapter assumptions, treat that
as a blocker — the test suite encodes the security boundary.
