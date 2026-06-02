# Edge integration: browser plugin ⇄ secure-mcp as a centralized PDP

**Status: design exploration.** Nothing internet-facing has been built. This
documents how the existing Chrome plugin (`../Secure_Browser_Plugin`) and
`secure-mcp` converge into one centralized, internet-reachable policy point.

## The thesis: convergence, not greenfield

The plugin already has the right shape; it's just decentralized:

| Capability | Today (plugin) | Centralized (this design) |
|---|---|---|
| Verdict scanning (URL/file) | Local native host, **TE key on every endpoint** | secure-mcp edge API; **keys stay in Vault**, endpoints hold only a device token |
| Policy distribution | Standalone `policy-server/` (Ed25519-signed envelopes, WS push) | Same envelope format, **served/signed by secure-mcp**, authored in the admin console |
| Telemetry | Optional Infinity HTTP `POST /v1/events` | secure-mcp **tamper-evident audit log** (one fleet-wide trail) |
| Rate limit / quota / breaker | per-endpoint, none | central per-scope rate limit + daily quota + per-upstream circuit breaker (already built) |
| DLP egress guard | none | central DLP filter (already built) + client-side pre-filter |

**Why centralize:** no credential sprawl (TE/ThreatCloud/Lakera keys never
leave Vault), one consistent verdict cache + quota against upstream APIs, one
audit trail across the fleet, and the admin console becomes the single policy
authority for the environment.

## Roles (PEP / PDP / PIP / PAP)

```
   Browser (many, across the internet)             Check Point environment
 ┌───────────────────────────────┐
 │ Extension service worker (PEP) │  TLS 1.2+ / device token
 │  • pause downloads             │ ───────────────┐
 │  • gate navigation             │                │
 │  • (opt) AI-app I/O guard      │                ▼
 │  • enforce signed policy       │     ┌──────────────────────────┐      ┌────────────────┐
 │  • local cache + fail-policy   │     │ secure-mcp EDGE API (PDP) │────▶ │ TE / ThreatCloud│ (PIP)
 └───────────────────────────────┘     │  reuses adapters + guards │      │ Lakera Guard    │
            ▲   policy pull/push, telemetry │ + audit + Vault secrets │      └────────────────┘
            └──────────────────────────────│                          │
                                           │ admin console = PAP      │
                                           └──────────────────────────┘
```

- **PEP** — the extension (`background.ts`). Stays the enforcement point: it
  pauses/cancels downloads, blocks navigation, shows the block page. Unchanged
  enforcement model; it just gets verdicts/policy from the center.
- **PDP** — a **new internet-facing edge API on secure-mcp**. Returns verdicts
  and signed policy. Reuses the existing `ToolContext` (auth → quota → rate →
  validate → DLP → adapter → audit) and adapters.
- **PIP** — Check Point upstreams + Lakera, reached only by the PDP.
- **PAP** — the admin console authors policy and manages device identities.

## The two gaps to bridge

### 1. Transport: stdio MCP → internet-facing HTTPS

`secure-mcp` speaks MCP over stdio (one process per AI client). Browsers need
HTTPS. Add a separate front door — `secure_mcp/edge/` — analogous to the admin
console but **deliberately internet-facing** and built for many PEPs:

```
POST /edge/v1/enroll          device enrollment → short-lived device token
POST /edge/v1/url/verdict     {url}            → allow|warn|block + category/phishing/reputation
POST /edge/v1/file/verdict    {sha256}         → TE verdict (hash-first; see egress note)
POST /edge/v1/ai/screen       {text,direction} → DLP + Lakera screen (egress-sensitive; see note)
GET  /edge/v1/policy          → Ed25519-signed policy envelope for the device's group
WSS  /edge/v1/subscribe       → policy push (reuse plugin's WS frame format)
POST /edge/v1/events          → telemetry → tamper-evident audit
GET  /edge/v1/healthz
```

Every route authenticated, TLS 1.2+, rate-limited and quota'd per device, and
audited. The verdict routes are thin wrappers over the existing adapters via a
device-scoped `ToolContext`. The MCP/stdio surface stays for AI agents.

### 2. Identity at fleet scale, over the internet

The plugin's `policy-server` already models this: `POST /v1/enroll` with a
shared `ENROLLMENT_TOKEN` → per-tenant bearer. Fold into secure-mcp:

- **Enrollment**: an MDM/GPO-distributed enrollment secret → secure-mcp issues
  a **short-lived signed device token** (same HMAC-signed token scheme the admin
  console already uses), carrying a `group`/tenant claim.
- **Scopes**: add edge scopes `edge_url`, `edge_file`, `edge_ai` to the scope
  set. A device identity is granted only edge scopes — never the AI-agent tools.
- **Transport auth**: prefer **mTLS** at the edge gateway (client cert via MDM)
  where feasible; otherwise device token + optional OIDC/SSO (Entra/Okta) for
  user binding. Public key for policy verification distributed via GPO (the
  plugin already supports TOFU fallback).

## The crux: the data-egress boundary (org policy)

Centralizing "over the internet" means deciding *what leaves the browser*. This
maps directly onto secure-mcp's §4 boundary and the org data-handling rules.
Defaults below are conservative — **when in doubt, don't send it.**

| Data | Egress risk | Default posture |
|---|---|---|
| URL / domain / IP / **hash** | Low — indicators only, stay within CP/ThreatCloud | **Send to PDP.** Phase 1. |
| **Full file** (on hash NOT_FOUND) | High — customer file content leaves the endpoint | **Do NOT route through the central PDP by default.** Keep full-file emulation on the local native host (endpoint→te.checkpoint.com), or require explicit approval for a consented central-upload path. Hash-query centrally; upload locally. |
| **AI prompt/response text** | High — potentially sensitive content + a third party (Lakera) | **Client-side DLP pre-filter first** (port secure-mcp's `dlp.py` patterns to the extension) so secrets are redacted *before leaving the browser*; central DLP is defense-in-depth. Gate behind explicit policy/consent. |
| Full browsing history | Privacy — the PDP would see every URL visited | Local allow/block lists + local cache first; prefer **domain over full URL**; consider hash-prefix / k-anonymity reputation lookups (Safe-Browsing style) so the PDP never sees exact URLs. |

This is the single most important design axis. The whole point of the central
DLP filter is to stop secrets crossing a boundary — so the edge design must not
*create* a new uncontrolled egress of customer content. Indicator-only flows are
safe; content flows (files, prompt text) need a client-side guard + explicit
sign-off.

## Reliability: fail-open vs fail-closed

The plugin is fail-open today (resume on scan error). A central PDP adds a
network dependency, so offline behavior must be **policy-driven per decision**:

- Downloads: fail-open (don't block work on an outage) — current behavior.
- Navigation to **cached known-bad** or **policy blocklist**: fail-closed even
  offline (the PEP enforces last-known signed policy + local cache).
- The signed policy envelope + local verdict cache let the PEP keep enforcing
  during a PDP outage; secure-mcp's circuit breaker protects the upstreams.

## What's reused vs new

- **Reuse (plugin):** enrollment/signed-envelope/WS/telemetry shapes, block
  page, managed-policy merge (`policy.ts`), URL/hash caches, fail-open logic.
- **Reuse (secure-mcp):** adapters (TE/ThreatCloud/Lakera), `ToolContext`
  guards, DLP filter, tamper-evident audit, quota, rate limit, circuit breaker,
  admin console.
- **New:** `secure_mcp/edge/` HTTPS front door; device enrollment + token; edge
  scopes; policy authoring/signing in secure-mcp; a client-side DLP pre-filter
  in the extension; the extension pointing `scanUrl`/`scanFile` at the edge API.
- **Converge / retire:** the standalone `policy-server/` is absorbed by the edge
  API; per-endpoint TE keys are removed (keys → Vault).

## Phase 1 — BUILT (indicator-only URL verdicts)

The edge PDP is implemented in `secure_mcp/edge/` and runs as `secure-mcp-edge`:

```
POST /edge/v1/enroll        {enrollment_secret, group, device_id} → short-lived device token
POST /edge/v1/url/verdict   {url}  (Bearer device token)          → {action, classification}
GET  /edge/v1/healthz
```

- **Indicator-only:** only the URL leaves the browser. No file/AI-text paths exist yet.
- **Auth:** enrollment secret (constant-time) → HMAC-signed device token with a
  `group` claim; per-source login throttle; token verified on every verdict.
- **Reuses:** the ThreatCloud adapter, URL validator (SSRF guard), rate limiter,
  daily quota, and tamper-evident audit. Classification→action mapping lives in
  `edge/verdict.py` (`classify_response` is defensive — VERIFY against the real
  reputation API).
- **Privacy:** the audit log records the **host + decision only**, never the full
  URL/path/query.
- **Fail-closed config:** refuses to bind a non-loopback host without TLS;
  enrollment secret + ThreatCloud key required at startup.
- **Client:** `../Secure_Browser_Plugin/edge-client.ts` — enrolls, caches the
  token, fetches verdicts, and **fails open** on any error. Wire
  `getUrlVerdictViaEdge()` into the navigation gate in `background.ts`.

Run it:

```bash
SECURE_MCP_EDGE_ENROLLMENT_SECRET=... CHECKPOINT_TC_API_KEY=... \
SECURE_MCP_AUDIT_LOG_PATH=/var/log/secure-mcp/audit.jsonl \
secure-mcp-edge        # → http://127.0.0.1:8770  (front with a TLS proxy)
```

## Phase 2 — BUILT (central policy authority)

The admin console is the policy authority; the edge serves signed policy and
ingests telemetry into the tamper-evident audit log.

```
GET  /edge/v1/policy    (Bearer device token) → Ed25519-signed envelope for the device's group (ETag/304)
GET  /edge/v1/pubkey    → base64 Ed25519 public key (also distribute via GPO)
POST /edge/v1/events    (Bearer device token) → telemetry → tamper-evident audit
```

- **Authoring:** the console's **Browser Policy** tab writes per-group policy
  docs (`PolicyStore` in `secure_mcp/policy_store.py`); settings are validated
  against an allowlist of keys (mirrors the plugin's managed schema).
- **Signing:** Ed25519 over canonical-JSON; the keypair is **lazy** — the admin
  authors without ever holding the private key; only the edge (the signer)
  materializes it. Envelope format matches the plugin's existing verifier.
- **Client verify:** `../Secure_Browser_Plugin/edge-policy-client.ts` fetches
  the policy and **verifies the signature with WebCrypto before applying it**,
  decoding settings from the signed *payload* (not the convenience `document`).
  Fail-safe: a tampered/unsigned/unreachable response keeps the last good policy.
- **Device wiring (closed loop):** the extension refreshes the verified policy
  on install/startup and a 15-min alarm, persists it, and `getEffectiveSettings`
  consumes it with precedence **defaults < user < central < GPO managed**.
  Defense-in-depth: the client restricts central settings to the URL/protection
  key subset — a signed policy can NOT set the Edge* bootstrap or Infinity keys,
  so the channel can never repoint its own PDP or telemetry sink (verified test).
- **Distribution model:** devices **poll** (ETag → 304 when unchanged) — policy
  changes apply on the device's next poll; **no MCP server restart** (unlike
  op-config). The standalone `policy-server/` is superseded by this.
- **Privacy:** policy pulls audit group + version only.

## Phased plan (lowest egress risk first)

1. **URL-verdict edge API** — DONE. Indicator-only; removes endpoint keys for
   URL filtering. Highest value, lowest risk.
2. **Central policy authority** — DONE (see above). Author in the console;
   serve signed envelopes + ETag polling from the edge; telemetry → audit log.
3. **File hash verdicts** — central hash-query; keep upload local (or add a
   consented central-upload path with its own approval).
4. **AI-app guardrails** — client-side DLP pre-filter + central screening
   (highest egress sensitivity; explicit security sign-off required).

## Threat model note (internet-facing)

The admin console is loopback/TLS by default; the edge API is the opposite —
intentionally public. That demands: strong device auth (mTLS preferred),
aggressive per-device rate limiting + quota (already built), a hardened reverse
proxy / WAF, DDoS posture, strict input validation (URL/hash/domain validators
already exist), and no secret material ever in a response. Treat it as a new,
separately-threat-modeled service, not an extension of the console.

## Open decisions (need sign-off before building)

- Device auth: mTLS vs OIDC vs enrollment-secret→token (reuse plugin's model)?
- Is any content egress (central file upload, AI text screening) approved, or
  indicator-only for now?
- Does the edge API replace the standalone `policy-server/`, or sit beside it?
- Hosting / network exposure model (reverse proxy, WAF, allowed source ranges)?
