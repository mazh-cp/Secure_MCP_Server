# Competitive review & differentiator strategy

*Internal strategy note. Competitor facts are public positioning as of June 2026
(sources at the end); treat as directional, not a feature contract.*

## 1. What we've built (the current stack)

Three services + an MV3 extension, ~177 passing Python tests:

| Layer | Component | State |
|---|---|---|
| **Broker** | `secure-mcp` (stdio MCP) — Check Point TE + ThreatCloud + Lakera behind Vault; 6 scopes / 15 tools | Built, tested; upstream response shapes flagged "verify vs real API" |
| **Control plane** | DLP egress filter, tamper-evident HMAC-chained audit (+verify CLI), per-scope rate limit, daily quota, per-upstream circuit breaker, SSRF guards, TLS enforcement | Built, tested |
| **Management** | `secure-mcp-admin` — Check Point-branded console: identities/scopes, DLP mode/quota/rate, audit trail, upstream health, instance restart, browser-policy authoring | Built, tested, visually verified |
| **Edge PDP** | `secure-mcp-edge` — internet-facing: device enrollment, indicator-only URL verdicts, Ed25519-signed policy distribution, telemetry → audit | Built, tested |
| **Browser PEP** | MV3 extension: TE download scanning, zero-phishing/URL filtering, wired to the edge PDP, central signed-policy consume + refresh (defaults < user < central < GPO) | Built, type-checks, runtime-validated |

**The architectural through-line:** the browser is one *enforcement point*; the
real asset is a **standards-native (MCP) security broker** that is also a
*decision + audit + policy plane*. That framing is the differentiator — see §4.

## 2. The 2026 market, in four buckets

1. **Browser-security extensions** (deploy into existing Chrome/Edge) — **our
   category**: Check Point **Harmony Browse**, **LayerX**, **Push Security**.
2. **Enterprise browsers** (replace the browser): **Island**, **Palo Alto
   Prisma Access Browser** (ex-Talon). Deepest control, heaviest rollout.
3. **SSE/SASE** with browser hooks: Zscaler, Netskope, Cloudflare.
4. **Remote browser isolation**: Menlo.

**The decisive 2026 trend — "agentic browser security."** Everyone is racing to
(a) GenAI DLP (stop secrets pasted into ChatGPT/Copilot) and (b) protect *AI
agents acting in the browser* (prompt injection, agent hijacking, shadow AI
agents). LayerX announced the "first dedicated agentic browser protection";
Prisma (Mar 2026) added shadow-AI-agent / prompt-injection / agent-hijack
defenses; Chrome Enterprise Premium ($6/user/mo) added Auto Browse + Gemini 3 +
real-time DLP. **This validates our direction and exposes a gap none of them
fill (§4).**

## 3. Capability comparison

✓ = strong · ◑ = partial/designed · ✗ = not a focus

| Capability | Ours (secure-mcp + ext) | Harmony Browse | LayerX | Push | Prisma/Island (ent. browser) | Chrome Ent. Premium |
|---|---|---|---|---|---|---|
| File/download sandboxing (TE detonation) | ✓ | ✓ | ◑ | ✗ | ◑ | ◑ |
| Zero-phishing / URL reputation | ✓ | ✓ | ✓ | ◑ (identity-phish) | ✓ | ✓ |
| GenAI prompt/response DLP | ◑ (ai_guard+Lakera, designed PEP) | ◑ | ✓ | ✗ | ✓ | ✓ |
| **Local secret pre-filter before egress** | ✓ (DLP redacts pre-boundary) | ✗ | ◑ | ✗ | ◑ | ◑ |
| Malicious-extension detection | ✗ | ✗ | ✓ | ✓ | ◑ | ◑ |
| Identity/SaaS posture, AiTM, session hijack | ✗ | ◑ (cred reuse) | ✓ | ✓ | ✓ | ◑ |
| Shadow SaaS / shadow AI discovery | ✗ | ✗ | ✓ | ✓ | ✓ | ◑ |
| Remote browser isolation | ✗ | ✗ | ✗ | ✗ | ✓ (containerized) | ✗ |
| **MCP / agent tool-call governance** | ✓ **(unique)** | ✗ | ✗ | ✗ | ✗ | ✗ |
| **Tamper-evident (cryptographic) audit** | ✓ **(rare)** | ✗ | ◑ | ◑ | ◑ | ◑ |
| Centralized signed policy authority | ✓ | ✓ (Infinity) | ✓ | ✓ | ✓ | ✓ |
| Deployment | Extension + broker | Extension | Extension | Extension | New browser | Browser/SKU |

**Reading it honestly:**
- Against **Harmony Browse** we're largely *re-implementing* its extension
  surface (TE, zero-phishing) — so vs. our own portfolio the extension is not
  the differentiator; the **broker + MCP + audit** is.
- **LayerX/Push** out-cover us today on identity, malicious-extension, shadow
  SaaS, and session attacks — mature browser-native breadth we haven't built.
- **Prisma/Island** win on depth-of-control (own the browser, RBI) but lose on
  deployment friction.
- **Two columns are ours alone: MCP/agent tool-call governance and
  cryptographically tamper-evident audit.** That is the wedge.

## 4. The differentiator: the MCP-native AI Security Broker for the agentic enterprise

Everyone else is bolting GenAI DLP and "agent protection" onto **a browser**.
We already have something none of them do: a **standards-native security broker
that speaks MCP** — the emerging protocol AI agents use to call tools. As agents
(in the browser, the IDE, the SOC, CI) standardize on MCP, the high-value choke
point shifts from "the browser tab" to **"the agent's tool-calls."** Own that
choke point and the browser becomes *one* PEP among many.

**Positioning:** *"Check Point for AI agents — the policy, DLP, and verifiable-
audit plane for every tool an agent touches, with the browser as one enforcement
point."* The agentic wave is the competitors' marketing; MCP-nativeness is the
moat they can't quickly copy (their architectures are browser-bound).

### Four buildable differentiators (each leverages what already exists)

1. **MCP guard / proxy mode** *(highest-leverage, mostly built)*
   Turn `secure-mcp` from "broker of our 3 tool groups" into a **policy-enforcing
   MCP gateway** that proxies *arbitrary* MCP servers: every tool call from any
   client (Claude, Cursor, in-browser agents) passes through auth scopes, the DLP
   egress filter, tamper-evident audit, quota, and threat-intel enrichment. We
   already have the `ToolContext` gate, DLP, audit, scopes — extend it to forward
   to registered upstream MCP servers. *No competitor sits here.*

2. **MCP-specific threat defense: tool-poisoning & prompt-injection screening**
   MCP introduces new attack surface — malicious **tool descriptions** and
   poisoned tool **responses** that hijack the agent. Screen both through
   `ai_guard` (Lakera + our DLP) before they reach the model. This is a threat
   class browser-only vendors structurally cannot address. Pairs naturally with
   Check Point's threat-intel brand.

3. **In-browser agentic PEP** *(parity feature, our spin)*
   Extend the extension with a content-script that intercepts AI-app I/O
   (ChatGPT/Copilot/Gemini and agentic browsers) and routes prompt/response
   through the **client-side DLP pre-filter** (already designed) → edge `ai_guard`.
   Matches LayerX/Prisma's headline, but with redaction *before* egress and a
   verifiable audit trail behind it.

4. **The "agent flight recorder"** *(compliance wedge, already built)*
   Promote the tamper-evident HMAC-chained audit as a **verifiable forensic
   record of every agent action and egress decision** — host-only/privacy-aware,
   cryptographically checkable (`audit_verify`). Few competitors offer
   *provable* non-repudiation; it's a natural Check Point compliance story.

### Why this is defensible
- **Standards lock-in to the right layer:** MCP is becoming the agent-tool
  protocol; being the security broker for it is a durable position.
- **Reuses our real assets:** broker, DLP, tamper-evident audit, scopes, edge,
  signed policy, the plugin — items 1 & 4 are largely *repositioning + a proxy
  extension* of code we already have and test.
- **Rides the wave without competing head-on:** we don't need to out-build
  LayerX on identity or Island on RBI; we win a category they aren't in.

### Honest gaps to close to be credible
- Browser-native breadth (malicious-extension, identity/SaaS posture, session/
  AiTM, shadow-SaaS) — table stakes LayerX/Push already have; partner or build.
- The broker's upstream wiring is still flagged "verify vs real API"; the
  agentic PEP (item 3) is designed, not built.
- We are pre-product (architecture + tested components), not at competitor scale.

## 5. Recommended sequence
1. **MCP guard/proxy mode** (item 1) — ✅ **BUILT** ([MCP-GUARD.md](MCP-GUARD.md)).
   `secure-mcp-guard` runs the full gate (authz → quota → rate → outbound-arg DLP
   → forward → response screen → audit). Forwarder transport is the one pending piece.
2. **Tool-poisoning/prompt-injection screening** (item 2) — ✅ **BUILT**.
   Descriptor + response screening engine; standalone `screen_tool` / `screen_response`
   MCP tools. The threat class browser-only vendors can't address.
3. **Agent flight recorder** (item 4) — ✅ exercised: every guard action is written
   to the tamper-evident chain; packaging/UX remains.
4. **In-browser agentic PEP** (item 3) — pending (content-script → client DLP → edge ai_guard).
5. Backfill browser-native breadth or partner for it — pending.

**Status:** the two columns that are ours alone (MCP/agent tool-call governance +
tamper-evident audit) are now implemented and tested (199 tests), not just designed.

## Sources (public, June 2026)
- LayerX — GenAI DLP / agentic browser protection: https://layerxsecurity.com/genai-dlp/ , https://layerxsecurity.com/blog/layerx-announces-the-first-dedicated-solution-for-agentic-browser-protection/
- Push Security — browser/identity extension: https://pushsecurity.com/product , https://pushsecurity.com/help/how-does-push-browser-extension-work/
- Check Point Harmony Browse: https://www.checkpoint.com/harmony/advanced-endpoint-protection/browser-security/
- Enterprise browsers (Island, Prisma, Chrome Enterprise Premium): https://expertinsights.com/web-security/the-top-enterprise-browsers , https://www.paloaltonetworks.com/sase/prisma-browser-vs-island , https://thenextweb.com/news/google-chrome-enterprise-ai-coworker-agentic-browser
