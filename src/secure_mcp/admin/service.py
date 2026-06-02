from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from ..audit import AuditLogger, verify_chain
from ..policy_store import PolicyStore
from ..scopes import ALL_SCOPES
from .config import AdminConfig
from .restart import RestartManager, Runner

_CALLER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_DLP_MODES = {"block", "redact", "flag"}
_OP_DEFAULTS = {"dlp_mode": "redact", "daily_quota": 0, "rate_limit_per_minute": 60}


class AdminValidationError(ValueError):
    pass


def _atomic_write(path: Path, data: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class AdminService:
    def __init__(self, cfg: AdminConfig, *, restart_runner: Runner | None = None) -> None:
        self.cfg = cfg
        self._audit = AuditLogger(cfg.admin_audit_log_path, "admin-console",
                                  hmac_key=cfg.audit_hmac_key)
        self._restart = RestartManager(cfg.managed_units, use_sudo=cfg.restart_use_sudo,
                                       runner=restart_runner, audit=self._audit)
        self._policy = PolicyStore(cfg.policy_dir, cfg.keys_dir)

    # ---- identity management (persistent; applied on MCP server restart) ----

    def _identity_path(self, caller_id: str) -> Path:
        if not _CALLER_RE.match(caller_id):
            raise AdminValidationError(
                "caller_id must match [A-Za-z0-9._-]{1,64} (no path separators)"
            )
        base = self.cfg.identity_dir.resolve()
        path = (base / f"{caller_id}.json").resolve()
        if path.parent != base:
            raise AdminValidationError("resolved identity path escapes identity_dir")
        return path

    def list_identities(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        if not self.cfg.identity_dir.is_dir():
            return out
        for f in sorted(self.cfg.identity_dir.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                out.append({
                    "file": f.name,
                    "caller_id": data.get("caller_id"),
                    "allowed_tools": sorted(data.get("allowed_tools", [])),
                    "valid": bool(data.get("caller_id")) and
                             set(data.get("allowed_tools", [])) <= ALL_SCOPES,
                })
            except (ValueError, OSError):
                out.append({"file": f.name, "caller_id": None,
                            "allowed_tools": [], "valid": False})
        return out

    def upsert_identity(self, caller_id: str, allowed_tools: list[str]) -> dict[str, Any]:
        path = self._identity_path(caller_id)
        if not isinstance(allowed_tools, list) or not allowed_tools:
            raise AdminValidationError("allowed_tools must be a non-empty list")
        scopes = sorted({str(s) for s in allowed_tools})
        unknown = set(scopes) - ALL_SCOPES
        if unknown:
            raise AdminValidationError(f"unknown scopes: {sorted(unknown)}")
        body = {"caller_id": caller_id, "allowed_tools": scopes}
        existed = path.exists()
        _atomic_write(path, json.dumps(body, indent=2) + "\n")
        self._audit.record(tool="admin", action="upsert_identity", result="ok",
                           details={"caller_id": caller_id, "allowed_tools": scopes,
                                    "created": not existed})
        return {"file": path.name, **body}

    def delete_identity(self, caller_id: str) -> bool:
        path = self._identity_path(caller_id)
        existed = path.exists()
        if existed:
            path.unlink()
        self._audit.record(tool="admin", action="delete_identity", result="ok",
                           details={"caller_id": caller_id, "existed": existed})
        return existed

    # ---- operational config (persistent; applied on MCP server restart) ----

    def get_op_config(self) -> dict[str, Any]:
        cfg = dict(_OP_DEFAULTS)
        if self.cfg.op_config_file.is_file():
            try:
                cfg.update({k: v for k, v in
                            json.loads(self.cfg.op_config_file.read_text()).items()
                            if k in _OP_DEFAULTS})
            except (ValueError, OSError):
                pass
        return cfg

    def set_op_config(self, *, dlp_mode: str | None = None,
                      daily_quota: int | None = None,
                      rate_limit_per_minute: int | None = None) -> dict[str, Any]:
        cfg = self.get_op_config()
        if dlp_mode is not None:
            if dlp_mode not in _DLP_MODES:
                raise AdminValidationError(f"dlp_mode must be one of {sorted(_DLP_MODES)}")
            cfg["dlp_mode"] = dlp_mode
        if daily_quota is not None:
            if not isinstance(daily_quota, int) or daily_quota < 0:
                raise AdminValidationError("daily_quota must be an integer >= 0")
            cfg["daily_quota"] = daily_quota
        if rate_limit_per_minute is not None:
            if not isinstance(rate_limit_per_minute, int) or rate_limit_per_minute <= 0:
                raise AdminValidationError("rate_limit_per_minute must be an integer > 0")
            cfg["rate_limit_per_minute"] = rate_limit_per_minute
        _atomic_write(self.cfg.op_config_file, json.dumps(cfg, indent=2) + "\n")
        self._audit.record(tool="admin", action="set_op_config", result="ok",
                           details=dict(cfg))
        return cfg

    # ---- inspection (read-only) ----

    def audit_summary(self, *, limit: int = 50) -> dict[str, Any]:
        path = self.cfg.audit_log_path
        if not path.is_file():
            return {"exists": False, "verified": None, "total": 0,
                    "by_result": {}, "by_error": {}, "by_tool": {},
                    "dlp_findings": 0, "recent": []}
        ok, err = verify_chain(path, self.cfg.audit_hmac_key)
        entries: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    entries.append(json.loads(line))
                except ValueError:
                    continue
        by_result: dict[str, int] = {}
        by_error: dict[str, int] = {}
        by_tool: dict[str, int] = {}
        dlp_total = 0
        for e in entries:
            by_result[e.get("result", "?")] = by_result.get(e.get("result", "?"), 0) + 1
            by_tool[e.get("tool", "?")] = by_tool.get(e.get("tool", "?"), 0) + 1
            det = e.get("details", {}) or {}
            if e.get("result") == "error":
                et = det.get("error_type", "?")
                by_error[et] = by_error.get(et, 0) + 1
            for f in det.get("dlp", []) or []:
                dlp_total += int(f.get("count", 0))
        return {
            "exists": True,
            "verified": ok,
            "verify_error": err,
            "total": len(entries),
            "by_result": by_result,
            "by_error": by_error,
            "by_tool": by_tool,
            "dlp_findings": dlp_total,
            "recent": entries[-limit:][::-1],
        }

    def upstream_health(self) -> list[dict[str, Any]]:
        targets = [
            ("threat_emulation", self.cfg.te_base_url),
            ("threatcloud", self.cfg.tc_base_url),
            ("lakera_guard", self.cfg.lakera_base_url),
        ]
        results = []
        for name, url in targets:
            entry: dict[str, Any] = {"name": name, "url": url}
            try:
                # Verify=on, no auth, short timeout. Any HTTP response (even
                # 401/403) proves reachability; only transport errors are "down".
                with httpx.Client(timeout=5.0, verify=True, follow_redirects=False) as c:
                    r = c.get(url)
                entry.update({"reachable": True, "status": r.status_code})
            except Exception as e:  # noqa: BLE001 - report any failure mode
                entry.update({"reachable": False, "error": type(e).__name__})
            results.append(entry)
        return results

    def overview(self) -> dict[str, Any]:
        """Single aggregate for the dashboard — probes upstreams once and
        reuses the result for guidance to avoid duplicate network calls."""
        health = self.upstream_health()
        return {
            "audit": self.audit_summary(),
            "op_config": self.get_op_config(),
            "identities": self.list_identities(),
            "health": health,
            "guidance": self.guidance(health=health),
            "restart": self.restart_status(),
        }

    # ---- managed-instance restart (opt-in, allowlisted) ----

    def restart_status(self) -> dict[str, Any]:
        if not self._restart.enabled:
            return {"enabled": False, "units": []}
        return {"enabled": True, "units": self._restart.status()}

    def restart_unit(self, unit: str) -> dict[str, Any]:
        return self._restart.restart(unit)

    def restart_all(self) -> dict[str, Any]:
        if not self._restart.enabled:
            return {"enabled": False, "results": []}
        return {"enabled": True, "results": self._restart.restart_all()}

    # ---- browser policy authoring (Phase 2; served signed by the edge PDP) ----

    def list_browser_policies(self) -> list[dict[str, Any]]:
        out = []
        for group in self._policy.list_groups():
            doc = self._policy.get_document(group) or {}
            out.append({"group": group, "version": doc.get("version"),
                        "issuedAt": doc.get("issuedAt"), "settings": doc.get("settings", {})})
        return out

    def get_browser_policy(self, group: str) -> dict[str, Any]:
        return self._policy.get_document(group) or {"group": group, "settings": {}}

    def set_browser_policy(self, group: str, settings: dict[str, Any]) -> dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        doc = self._policy.set_settings(group, settings, now_iso=now_iso)
        self._audit.record(tool="admin", action="set_browser_policy", result="ok",
                           details={"group": group, "version": doc["version"],
                                    "keys": sorted(settings.keys())})
        return doc

    def guidance(self, *, health: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
        tips: list[dict[str, str]] = []
        summary = self.audit_summary(limit=1)
        op = self.get_op_config()
        identities = self.list_identities()

        if summary["exists"] and summary["verified"] is False:
            tips.append({"level": "critical", "title": "Audit chain verification FAILED",
                         "detail": f"{summary.get('verify_error')}. Investigate possible tampering immediately."})
        if self.cfg.audit_hmac_key is None:
            tips.append({"level": "warning", "title": "Audit log has no HMAC key",
                         "detail": "Tamper-evidence is best-effort. Inject SECURE_MCP_AUDIT_HMAC_KEY from Vault/KMS."})
        if op["dlp_mode"] == "flag":
            tips.append({"level": "warning", "title": "DLP is in flag mode",
                         "detail": "Secrets pass through to Lakera unredacted. Use redact (default) or block in production."})
        if op["daily_quota"] == 0:
            tips.append({"level": "info", "title": "Daily quota disabled",
                         "detail": "No daily call cap is set. Consider a quota to bound upstream cost / abuse."})
        for ident in identities:
            if not ident["valid"]:
                tips.append({"level": "warning", "title": f"Invalid identity file: {ident['file']}",
                             "detail": "caller_id missing or contains unknown scopes."})
            elif set(ident["allowed_tools"]) == ALL_SCOPES:
                tips.append({"level": "warning", "title": f"Caller '{ident['caller_id']}' has ALL scopes",
                             "detail": "Apply least privilege — grant only the scopes this caller needs."})
        if not identities:
            tips.append({"level": "info", "title": "No identity files configured",
                         "detail": "Create at least one caller identity to expose tools."})
        for up in (health if health is not None else self.upstream_health()):
            if not up.get("reachable"):
                tips.append({"level": "warning", "title": f"Upstream unreachable: {up['name']}",
                             "detail": f"{up['url']} — {up.get('error')}. Check egress allowlist / DNS."})
        if not tips:
            tips.append({"level": "ok", "title": "No issues detected",
                         "detail": "Audit chain intact, DLP active, scopes look reasonable."})
        return tips

    def close(self) -> None:
        self._audit.close()
