import json
from pathlib import Path

import pytest

from secure_mcp.admin.restart import RestartError, RestartManager
from secure_mcp.audit import AuditLogger, verify_chain

UNIT = "secure-mcp@soc.service"


class FakeRunner:
    def __init__(self, rc=0, stdout="", stderr=""):
        self.calls = []
        self.rc, self.stdout, self.stderr = rc, stdout, stderr

    def __call__(self, args):
        self.calls.append(args)
        return self.rc, self.stdout, self.stderr


def test_disabled_without_allowlist():
    r = FakeRunner()
    mgr = RestartManager([], runner=r)
    assert mgr.enabled is False
    assert mgr.status() == []
    with pytest.raises(RestartError, match="disabled"):
        mgr.restart(UNIT)
    assert r.calls == []  # nothing executed


def test_rejects_unit_not_in_allowlist():
    r = FakeRunner()
    mgr = RestartManager([UNIT], runner=r)
    with pytest.raises(RestartError, match="allowlist"):
        mgr.restart("secure-mcp@evil.service")
    with pytest.raises(RestartError):
        mgr.restart("soc; rm -rf /")  # injection attempt — rejected by allowlist+regex
    assert r.calls == []  # never executed


def test_restart_uses_fixed_argv_no_shell():
    r = FakeRunner(rc=0)
    mgr = RestartManager([UNIT], runner=r)
    out = mgr.restart(UNIT)
    assert out["ok"] is True
    assert r.calls == [["systemctl", "restart", UNIT]]  # exact argv list, no shell string


def test_sudo_prefix_when_enabled():
    r = FakeRunner(rc=0)
    mgr = RestartManager([UNIT], use_sudo=True, runner=r)
    mgr.restart(UNIT)
    assert r.calls[0] == ["sudo", "-n", "systemctl", "restart", UNIT]


def test_restart_failure_reports_and_does_not_raise():
    r = FakeRunner(rc=1, stderr="Failed to restart: unit not found")
    mgr = RestartManager([UNIT], runner=r)
    out = mgr.restart(UNIT)
    assert out["ok"] is False
    assert "Failed to restart" in out["message"]


def test_status_parses_systemctl_show():
    r = FakeRunner(rc=0, stdout="ActiveState=active\nSubState=running\n")
    mgr = RestartManager([UNIT], runner=r)
    st = mgr.status()
    assert st == [{"unit": UNIT, "active_state": "active", "sub_state": "running"}]
    assert r.calls[0] == ["systemctl", "show", UNIT, "-p", "ActiveState", "-p", "SubState"]


def test_restart_all_restarts_every_unit():
    units = ["secure-mcp@soc.service", "secure-mcp@triage.service"]
    r = FakeRunner(rc=0)
    mgr = RestartManager(units, runner=r)
    results = mgr.restart_all()
    assert [x["unit"] for x in results] == units
    assert all(x["ok"] for x in results)
    assert ["systemctl", "restart", units[0]] in r.calls
    assert ["systemctl", "restart", units[1]] in r.calls


def test_restart_all_empty_when_disabled():
    r = FakeRunner()
    assert RestartManager([], runner=r).restart_all() == []
    assert r.calls == []


def test_restart_is_audited(tmp_path: Path):
    key = b"k"
    audit = AuditLogger(tmp_path / "admin-audit.jsonl", "admin-console", hmac_key=key)
    mgr = RestartManager([UNIT], runner=FakeRunner(rc=0), audit=audit)
    mgr.restart(UNIT)
    with pytest.raises(RestartError):
        mgr.restart("not-allowed.service")
    audit.close()
    log = tmp_path / "admin-audit.jsonl"
    ok, err = verify_chain(log, key)
    assert ok, err
    rows = [json.loads(l) for l in log.read_text().splitlines()]
    assert rows[0]["action"] == "restart_unit" and rows[0]["result"] == "ok"
    assert rows[1]["result"] == "error"  # denied attempt audited too
