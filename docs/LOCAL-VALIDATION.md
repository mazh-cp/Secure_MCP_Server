# Local validation

Two scripts let you validate the whole stack locally — no real Check Point /
Lakera keys, no network (a mock ThreatCloud is used).

## Automated end-to-end check

```bash
.venv/bin/python scripts/validate_local.py
```

Spins up the **edge PDP** and **admin console** in-process on loopback ephemeral
ports, exercises the full flow, and prints a PASS/FAIL report (exit 0 = all
green). It validates, in one run:

- Edge: health, device enrollment, URL verdicts (malicious→block, benign→allow),
  SSRF rejection, auth required.
- Admin: login (good/bad token), create identity, set op-config, author browser
  policy, **provision a secret (write-only — asserts the value is never echoed)**.
- Edge: signed-policy round-trip with **signature verification**, ETag→304,
  telemetry→202.
- MCP Guard: flags a poisoned tool descriptor, passes a clean call, **blocks an
  outbound secret**.
- **Tamper-evident audit chains** (edge + admin) verify.

Use it as a smoke test after changes; 22 checks across all four services.

## Interactive instance (browser / plugin)

```bash
.venv/bin/python scripts/run_local.py
```

Runs the admin console (`http://127.0.0.1:8765`) and edge PDP
(`http://127.0.0.1:8770`) with **ephemeral dev secrets printed at launch** and a
mock ThreatCloud. Open the console in a browser and sign in with the printed
admin token; drive the edge with the printed enrollment secret. The banner also
prints the values to set in the plugin's managed policy (`EdgePdpUrl`,
`EdgeGroup`, `EdgeEnrollmentSecret`, `EdgePolicyPublicKey`). Ctrl-C to stop.

> Dev only: secrets are generated per launch and never persisted; the workspace
> is a throwaway temp dir. Never use these in production — real deployments
> inject secrets from Vault/KMS (see [SETUP.md](SETUP.md)).
