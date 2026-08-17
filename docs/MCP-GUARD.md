# MCP Guard — the policy plane for agent tool-calls

*Differentiators #1 (MCP guard/proxy mode) and #2 (tool-poisoning / prompt-
injection screening) from [COMPETITIVE-STRATEGY.md](COMPETITIVE-STRATEGY.md).
This is the layer browser-bound competitors structurally cannot reach.*

## Why

Browser security products protect the *tab*. As AI agents standardize on **MCP**
to call tools, the high-value choke point moves to the **tool-call**. A malicious
or compromised MCP server attacks the agent in two ways the browser never sees:

- **Tool poisoning** — the tool's *description* carries hidden instructions the
  model reads when deciding to call it ("…ignore previous instructions… do not
  tell the user…").
- **Response injection / exfiltration** — the tool's *response* injects
  instructions or smuggles out secrets.

`secure-mcp-guard` sits in front of upstream MCP servers and applies the same
control plane as our own tools.

## The gate

Every guarded call runs:

```
authorize(mcp_proxy scope) → quota → rate → DLP on OUTBOUND args →
forward to upstream → injection + DLP screen on RESPONSE → tamper-evident audit
```

- **Outbound-arg DLP**: secrets in arguments are redacted (or the call blocked,
  per DLP mode) *before* they reach a possibly-untrusted tool.
- **Descriptor screening**: at registration, each tool's name/description/schema
  is screened; poisoned descriptors are flagged `allowed: false`.
- **Response screening**: injected instructions or leaked secrets in the
  response block the result (configurable risk threshold).
- **Audit**: every registration, call, block, and denial is written to the
  tamper-evident HMAC-chained log — the "agent flight recorder" (#3).

Screening logic and thresholds live in
[mcpguard/injection.py](../src/secure_mcp/mcpguard/injection.py); "hard" signals
(ignore-previous, role-override, conceal-from-user, exfiltration, hidden
directive markers, zero-width text) → `malicious`; "soft" mentions (a param
named `api_key`, a `curl` snippet) → only `suspicious`, to avoid false positives.

## Tools exposed (`secure-mcp-guard`, scope `mcp_proxy`)

| Tool | Use | Needs upstream? |
|---|---|---|
| `screen_tool(name, description, schema)` | Vet an MCP tool descriptor before trusting it | No — standalone |
| `screen_response(text)` | Vet a tool/agent response for injection + leaked secrets | No — standalone |
| `guard_list_tools(server)` | List an upstream's tools, screening each descriptor | Yes |
| `guard_call(server, tool, args)` | Call an upstream tool through the full gate | Yes |

The two `screen_*` tools are immediately usable by any MCP client/orchestrator
with no upstream wiring.

## Run it

```bash
SECURE_MCP_IDENTITY_FILE=... CHECKPOINT_TE_API_KEY=... LAKERA_GUARD_API_KEY=... \
SECURE_MCP_AUDIT_LOG_PATH=... SECURE_MCP_UPLOAD_DIR=... \
SECURE_MCP_GUARD_UPSTREAMS=calc,docs \
secure-mcp-guard         # stdio MCP server
```

Grant a client the `mcp_proxy` scope in its identity file to use the guard.

## Live upstream proxying

`guard_call` / `guard_list_tools` proxy **real upstream MCP servers** via
[mcpguard/forwarder.py](../src/secure_mcp/mcpguard/forwarder.py) — an stdio MCP
client bridged into the synchronous guard by a thread-confined asyncio loop
(persistent sessions per upstream). Configure the allowlisted upstreams with a
registry JSON at `SECURE_MCP_GUARD_REGISTRY`:

```json
{
  "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"] },
  "calc":       { "command": "python", "args": ["/opt/tools/calc_server.py"] },
  "intel":      { "transport": "streamable-http", "url": "https://mcp.internal/intel/mcp",
                  "headers": { "Authorization": "Bearer ${TOKEN}" } },
  "legacy":     { "transport": "sse", "url": "https://mcp.internal/legacy/sse" }
}
```

Transports: **stdio** (spawn `command`/`args`), **streamable-http** (default for a
`url`), and **sse** (legacy). Registry `env` / `headers` values support `${VAR}`
expansion from the guard process environment; stdio `env` is merged with the
parent environment so `npx` keeps `PATH`. HTTP/SSE upstreams must be **https**
unless loopback (fail-closed TLS), and may carry auth `headers` (never logged).
Only servers in the registry can be reached; every listed descriptor is screened
for poisoning and every call goes through the gate. With no registry set, the
two `screen_*` tools still work standalone.

**v0.8 topology:** register complementary official packages from
[CheckPointSW/mcp-servers](https://github.com/CheckPointSW/mcp-servers)
(`@chkp/quantum-management-mcp`, threat-prevention, harmony-sase, …). Keep TE and
reputation on `secure-mcp` — see [ARCHITECTURE.md](ARCHITECTURE.md) and
`deploy/topology/guard-registry.example.json`. Verified end-to-end against real
subprocess upstreams (stdio + Streamable-HTTP) in `tests/test_mcpguard_forwarder.py`
and `tests/test_mcpguard_http.py`.
