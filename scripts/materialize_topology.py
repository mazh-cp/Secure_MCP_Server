#!/usr/bin/env python3
"""Materialize the v0.8 guard-first topology into .topology/ for local Cursor use.

  .venv/bin/python scripts/materialize_topology.py
  .venv/bin/python scripts/materialize_topology.py --write-cursor-mcp

Creates:
  .topology/uploads/
  .topology/guard-audit.jsonl (touch)
  .topology/mcp.cursor.json   (paths rewritten to this repo)
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOPO = ROOT / "deploy" / "topology"
OUT = ROOT / ".topology"
CURSOR_MCP = Path.home() / ".cursor" / "mcp.json"


def materialize() -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "uploads").mkdir(exist_ok=True)
    (OUT / "guard-audit.jsonl").touch()
    (OUT / "broker-audit.jsonl").touch()

    src = TOPO / "mcp.cursor.example.json"
    data = json.loads(src.read_text(encoding="utf-8"))
    raw = json.dumps(data)
    raw = raw.replace("REPLACE_REPO", str(ROOT))
    out_mcp = OUT / "mcp.cursor.json"
    out_mcp.write_text(raw + "\n", encoding="utf-8")
    return out_mcp


def merge_cursor_mcp(generated: Path) -> None:
    """Merge guard-first servers into ~/.cursor/mcp.json (preserves others)."""
    new = json.loads(generated.read_text(encoding="utf-8"))
    existing: dict = {"mcpServers": {}}
    if CURSOR_MCP.is_file():
        existing = json.loads(CURSOR_MCP.read_text(encoding="utf-8"))
        existing.setdefault("mcpServers", {})
    # Drop legacy broken secure-mcp entry; install new topology keys.
    servers = existing["mcpServers"]
    servers.pop("secure-mcp", None)
    for name, cfg in new.get("mcpServers", {}).items():
        if name == "secure-mcp-broker":
            # Keep broker optional — only add if operator already had keys intent.
            # Default: skip broker until secrets are set.
            continue
        # Strip helper keys MCP clients may reject
        clean = {k: v for k, v in cfg.items() if not k.startswith("_")}
        servers[name] = clean
    CURSOR_MCP.parent.mkdir(parents=True, exist_ok=True)
    backup = CURSOR_MCP.with_suffix(".json.bak")
    if CURSOR_MCP.is_file():
        shutil.copy2(CURSOR_MCP, backup)
    CURSOR_MCP.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    print(f"updated {CURSOR_MCP} (backup: {backup})")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write-cursor-mcp", action="store_true",
                    help=f"Merge into {CURSOR_MCP}")
    args = ap.parse_args()
    out = materialize()
    print(f"wrote {out}")
    print(f"registry: {TOPO / 'guard-registry.example.json'}")
    print(f"identity: {TOPO / 'identity-guard.example.json'}")
    if args.write_cursor_mcp:
        merge_cursor_mcp(out)
        print("Reload MCP in Cursor Settings to apply.")
    else:
        print("Preview only. Re-run with --write-cursor-mcp to update ~/.cursor/mcp.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
