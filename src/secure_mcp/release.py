"""Single source of truth for the console's Read Me + Release Notes.

Kept as structured data (not free markdown) so the console renders it safely
without a markdown dependency, and so version bumps live in one place.
"""

from __future__ import annotations

from . import __version__

# Short, audience-oriented help shown on the console's "Read Me" tab.
CONSOLE_README: list[dict[str, str]] = [
    {
        "title": "What this is",
        "body": (
            "secure-mcp is a hardened broker that fronts Check Point Threat Emulation, "
            "ThreatCloud, and Lakera Guard, and acts as a data-egress control plane for "
            "AI agents and browser policy. This console is the management plane (PAP): "
            "it administers identities, policy, secrets, and the audit trail — it never "
            "performs detonation or stores customer content."
        ),
    },
    {
        "title": "Tabs",
        "body": (
            "- Overview: status cards + contextual guidance.\n"
            "- Identities & Scopes: per-caller capability grants (least privilege).\n"
            "- Configuration: DLP mode, daily quota, rate limit (applied on service restart).\n"
            "- Audit Trail: tamper-evident HMAC-chained log with verification.\n"
            "- Upstream Health: live reachability of TE / ThreatCloud / Lakera.\n"
            "- Instances: restart managed systemd units to apply changes.\n"
            "- Browser Policy: author Ed25519-signed policy served to browser plugins.\n"
            "- Keys & Secrets: provision/rotate API keys — write-only, AES-256-GCM, "
            "fingerprint-only display."
        ),
    },
    {
        "title": "Security model",
        "body": (
            "- Sign-in: admin token (constant-time) → short-lived HMAC session; failed "
            "logins are throttled.\n"
            "- Transport: loopback by default; non-loopback binding requires TLS (HSTS set).\n"
            "- No ambient credentials: the SPA sends a bearer token, so there is no CSRF "
            "surface.\n"
            "- Secrets are never returned by any endpoint — only a non-reversible "
            "fingerprint is shown.\n"
            "- Every mutation is written to the tamper-evident audit log."
        ),
    },
    {
        "title": "Documentation",
        "body": (
            "Full docs ship with the repo: docs/INDEX.md (start here), SETUP.md, "
            "CONSOLE.md, DEPLOY.md, EDGE-INTEGRATION.md, MCP-GUARD.md, SECURITY.md, "
            "and LOCAL-VALIDATION.md."
        ),
    },
]

# Newest first. Each entry: version, date (ISO), title, changes[].
RELEASE_NOTES: list[dict] = [
    {
        "version": "0.7.0", "date": "2026-06-15", "title": "Live MCP forwarder + cross-browser packaging",
        "changes": [
            "MCP guard proxies real upstream MCP servers (stdio client bridged into the "
            "sync gate; allowlisted via SECURE_MCP_GUARD_REGISTRY) — guard_call is now live.",
            "Cross-browser plugin generator: Chrome/Edge/Firefox packages + Safari converter, "
            "one bundled background, branded icons, cross-browser native-host installer + the "
            "native-messaging host bridge (scan_file/scan_url/query_report/cache_stats).",
        ],
    },
    {
        "version": "0.6.0", "date": "2026-06-02", "title": "VM / server deployment",
        "changes": [
            "Docker Compose deployment for the edge PDP + admin console (TLS, persistent "
            "volumes, non-root, read-only rootfs, fail-closed secret injection).",
            "systemd unit for the edge PDP + Vault env wrapper; completed deploy assets.",
            "Security review: added HSTS on TLS for admin + edge; SECURITY.md threat model.",
            "Console: Read Me + Release Notes sections.",
        ],
    },
    {
        "version": "0.5.0", "date": "2026-06-01", "title": "Keys & Secrets management",
        "changes": [
            "AES-256-GCM encrypted keystore with a KMS-injected master key; values are "
            "write-only and never returned (fingerprint-only display).",
            "load_settings resolves upstream keys env > keystore.",
            "Console Keys & Secrets tab with masked set/rotate, connectivity test, delete.",
        ],
    },
    {
        "version": "0.4.0", "date": "2026-05-30", "title": "MCP Guard (differentiator)",
        "changes": [
            "Policy-enforcing MCP gateway: authz → quota → rate → outbound-arg DLP → "
            "forward → response injection+DLP screen → audit.",
            "Tool-poisoning / prompt-injection screening of tool descriptors and responses.",
            "secure-mcp-guard server exposing screen_tool / screen_response standalone.",
        ],
    },
    {
        "version": "0.3.0", "date": "2026-05-28", "title": "Edge PDP + central policy",
        "changes": [
            "Internet-facing edge PDP: device enrollment, indicator-only URL verdicts.",
            "Central policy authority: Ed25519-signed per-group policy, ETag polling, "
            "telemetry → audit. Browser plugin wired to consume it (verify-before-apply).",
        ],
    },
    {
        "version": "0.2.0", "date": "2026-05-25", "title": "Admin console",
        "changes": [
            "Check Point-branded management console: identities, config, audit, health, "
            "instance restart, browser-policy authoring.",
        ],
    },
    {
        "version": "0.1.0", "date": "2026-05-20", "title": "Broker + control plane",
        "changes": [
            "MCP broker for TE / ThreatCloud / Lakera (6 scopes, 15 tools).",
            "DLP egress filter, tamper-evident audit, per-scope rate limit, daily quota, "
            "per-upstream circuit breaker, SSRF/TLS guards.",
        ],
    },
]


def about() -> dict:
    return {"version": __version__, "readme": CONSOLE_README, "release_notes": RELEASE_NOTES}
