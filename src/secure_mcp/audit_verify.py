"""CLI to verify audit-log integrity.

    python -m secure_mcp.audit_verify /var/log/secure-mcp/audit.jsonl

Reads the HMAC key from SECURE_MCP_AUDIT_HMAC_KEY (hex) if set — it MUST match
the key used when the log was written, or verification will report a mismatch.
Exit code 0 = intact, 1 = tampering detected, 2 = usage/IO error."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .audit import verify_chain


def _load_key() -> bytes | None:
    raw = os.environ.get("SECURE_MCP_AUDIT_HMAC_KEY")
    if not raw:
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("usage: python -m secure_mcp.audit_verify <audit.jsonl>", file=sys.stderr)
        return 2
    path = Path(args[0])
    if not path.is_file():
        print(f"file not found: {path}", file=sys.stderr)
        return 2
    ok, err = verify_chain(path, _load_key())
    if ok:
        print(f"OK: audit chain intact ({path})")
        return 0
    print(f"TAMPERING DETECTED: {err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
