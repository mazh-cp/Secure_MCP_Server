from __future__ import annotations

import re
import subprocess
from typing import Callable

from ..audit import AuditLogger

# Runner contract: takes an argv LIST, returns (returncode, stdout, stderr).
# Injectable so tests never invoke systemctl.
Runner = Callable[[list[str]], "tuple[int, str, str]"]

# Defense-in-depth format check; the real gate is allowlist membership.
_UNIT_RE = re.compile(r"^[A-Za-z0-9@._-]{1,128}$")


class RestartError(RuntimeError):
    pass


def _default_runner(args: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=30, check=False)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "systemctl not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


class RestartManager:
    """Restarts MCP server systemd units so console-written config/identity
    changes take effect.

    Security: this NEVER builds a shell command from user input. Execution uses
    a fixed argv list passed to subprocess (no shell=True, no interpolation),
    and the unit must be a member of an operator-configured allowlist. User
    input only *selects* a pre-authorized target — it never composes the
    command. The feature is disabled unless an allowlist is configured, and the
    console process must be granted narrow privilege (polkit/sudoers) to manage
    exactly those units.
    """

    def __init__(self, units, *, use_sudo: bool = False,
                 runner: Runner | None = None, audit: AuditLogger | None = None) -> None:
        self._units = tuple(units)
        self._allow = set(self._units)
        self._use_sudo = use_sudo
        self._run = runner or _default_runner
        self._audit = audit

    @property
    def enabled(self) -> bool:
        return bool(self._units)

    def _cmd(self, *parts: str) -> list[str]:
        prefix = ["sudo", "-n"] if self._use_sudo else []
        return [*prefix, "systemctl", *parts]

    def _check(self, unit: str) -> None:
        if not self.enabled:
            raise RestartError("restart feature disabled — no managed units configured")
        if not isinstance(unit, str) or not _UNIT_RE.match(unit) or unit not in self._allow:
            raise RestartError(f"unit '{unit}' is not in the managed allowlist")

    def status(self) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for u in self._units:
            rc, so, _se = self._run(self._cmd("show", u, "-p", "ActiveState", "-p", "SubState"))
            props: dict[str, str] = {}
            for line in (so or "").splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    props[k] = v.strip()
            out.append({
                "unit": u,
                "active_state": props.get("ActiveState", "unknown") if rc == 0 else "unknown",
                "sub_state": props.get("SubState", ""),
            })
        return out

    def restart(self, unit: str) -> dict:
        try:
            self._check(unit)
        except RestartError:
            if self._audit:
                self._audit.record(tool="admin", action="restart_unit", result="error",
                                   details={"unit": str(unit), "error_type": "RestartError"})
            raise
        rc, so, se = self._run(self._cmd("restart", unit))
        ok = rc == 0
        if self._audit:
            self._audit.record(tool="admin", action="restart_unit",
                               result="ok" if ok else "error",
                               details={"unit": unit, "returncode": rc})
        return {"unit": unit, "ok": ok, "returncode": rc,
                "message": (se or so or "").strip()[:500]}

    def restart_all(self) -> list[dict]:
        """Restart every allowlisted unit (used by 'apply & restart'). Each
        unit goes through the same validated, audited single-unit path."""
        return [self.restart(u) for u in self._units]
