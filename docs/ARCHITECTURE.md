# Architecture — v0.8 Guard-First Topology

Global system design for **secure-mcp** as a control plane in front of
[Check Point official MCP servers](https://github.com/CheckPointSW/mcp-servers)
(`@chkp/*`), without dual-exposing Threat Emulation / reputation surfaces.

## Design principles

1. **One policy plane for agent tool-calls** — Cursor talks to `secure-mcp-guard`,
   not to a pile of unguarded `@chkp/*` processes.
2. **No TE/intel double exposure** — file detonation + ThreatCloud stay on the
   hardened **broker** (`secure-mcp`). Official `@chkp/threat-emulation-mcp` and
   `@chkp/reputation-service-mcp` are **not** registered as guard upstreams by
   default.
3. **Complementary official MCPs behind the guard** — management, threat-
   prevention, Harmony SASE, GW diagnostics, WAF, docs tooling, etc.
4. **Docs can stay direct** — `@chkp/documentation-mcp` and Lakera docs are
   low-risk Q&A surfaces; optional to also put docs behind the guard.
5. **Fail closed** — registry allowlist only; HTTP upstreams require HTTPS
   (non-loopback); secrets via env/Vault with `${VAR}` expansion in the
   registry (never committed).

## Reference topology

```
┌──────────────────────────────────────────────────────────────────┐
│ Cursor / Claude Desktop                                          │
│  ├─ docs.lakera.ai              (remote, optional)               │
│  ├─ mcp.checkpoint.com          (@chkp/documentation-mcp)        │
│  ├─ secure-mcp-guard  ◀──────── PRIMARY agent security plane     │
│  │     │                                                         │
│  │     └─ SECURE_MCP_GUARD_REGISTRY                              │
│  │           ├─ chkp-management      @chkp/quantum-management-mcp│
│  │           ├─ chkp-threat-prevention                           │
│  │           ├─ chkp-harmony-sase                                │
│  │           ├─ chkp-gw-cli          (ops; high privilege)       │
│  │           └─ … other complementary @chkp/*                    │
│  └─ secure-mcp  (OPTIONAL)  — TE / ThreatCloud / Lakera broker   │
│        scopes: threat_emulation, file_sandboxing, ai_guard, …    │
└──────────────────────────────────────────────────────────────────┘
         │                              │
         ▼                              ▼
   Admin console (PAP)            Edge PDP (browser)
   secure-mcp-admin               secure-mcp-edge
   internal HTTPS                 internet HTTPS
```

## Component roles

| Component | Entry | Exposure | Owns |
|-----------|-------|----------|------|
| **MCP guard** | `secure-mcp-guard` | Client host (stdio) | Authz, quota, rate, outbound DLP, injection screen, audit for **upstream** MCP calls |
| **Broker** | `secure-mcp` | Client host (stdio) | TE / ThreatCloud / Lakera tools + same control plane for **first-party** tools |
| **Admin** | `secure-mcp-admin` | Internal only | Identities, config, keystore, browser policy authoring |
| **Edge** | `secure-mcp-edge` | Internet | Device enrollment, URL verdicts, signed policy |
| **Official CP MCPs** | `npx @chkp/…` | Spawned by guard | Product APIs (management, SASE, …) |

## Identity split

| File | Scopes | Use |
|------|--------|-----|
| `identity-guard.example.json` | `mcp_proxy` | Cursor → guard only (no broker TE keys required) |
| `identity-broker.example.json` | TE / sandbox / ai_guard / intel | Optional direct broker for detonation/intel |
| `identity.example.json` | Full demo set including `mcp_proxy` | Lab / all-in-one |

## Files in this topology

| Path | Purpose |
|------|---------|
| [deploy/topology/guard-registry.example.json](../deploy/topology/guard-registry.example.json) | Allowlisted complementary `@chkp/*` upstreams |
| [deploy/topology/mcp.cursor.example.json](../deploy/topology/mcp.cursor.example.json) | Recommended Cursor `mcp.json` |
| [deploy/topology/identity-guard.example.json](../deploy/topology/identity-guard.example.json) | Guard client identity |
| [deploy/topology/identity-broker.example.json](../deploy/topology/identity-broker.example.json) | Broker-only identity |
| [deploy/guard-env-load.sh.example](../deploy/guard-env-load.sh.example) | Vault/env launcher for the guard |
| [scripts/materialize_topology.py](../scripts/materialize_topology.py) | Copy examples into `.topology/` for local use |

## Operator quickstart

```bash
# 1. Install / refresh editable package
source .venv/bin/activate && pip install -e ".[dev]"

# 2. Materialize local topology (gitignored secrets dir pattern)
.venv/bin/python scripts/materialize_topology.py

# 3. Put real Check Point management / SASE credentials in the
#    process env (or Vault). Registry uses ${VAR} expansion.

# 4. Point Cursor mcp.json at deploy/topology/mcp.cursor.example.json
#    (or merge into ~/.cursor/mcp.json). Reload MCP.
```

Agent tools to use after cutover:

- `screen_tool` / `screen_response` — standalone screening
- `guard_list_tools(server)` — list + screen upstream descriptors
- `guard_call(server, tool, args)` — full gate through official CP MCP

## Explicit non-goals (v0.8)

- Replacing official `@chkp/*` packages with reimplementations
- Registering official TE + reputation alongside the broker (overlap)
- Publishing admin/edge on the public internet without TLS + enrollment

## Related docs

- [MCP-GUARD.md](MCP-GUARD.md) — gate internals
- [SECURITY.md](SECURITY.md) — trust boundaries
- [DEPLOY.md](DEPLOY.md) — VM / Docker for admin + edge
- Upstream monorepo: https://github.com/CheckPointSW/mcp-servers
