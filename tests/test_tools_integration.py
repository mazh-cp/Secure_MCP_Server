import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from secure_mcp.audit import AuditLogger
from secure_mcp.auth import AuthorizationError
from secure_mcp.config import Identity, Settings
from secure_mcp.context import ToolContext
from secure_mcp.dlp import DLPScanner, DLPViolation
from secure_mcp.quota import DailyQuota, QuotaExceeded
from secure_mcp.rate_limit import RateLimitExceeded, ScopedRateLimiter
from secure_mcp.tools import ai_guard, threat_emulation, threat_intel
from secure_mcp.validation import ValidationError


class FakeMCP:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


def _settings(tmp_path: Path, scopes: set[str], **over: Any) -> Settings:
    upload = tmp_path / "uploads"
    upload.mkdir(exist_ok=True)
    base = dict(
        identity=Identity(caller_id="test-caller", allowed_tools=frozenset(scopes)),
        checkpoint_te_base_url="https://te.checkpoint.com",
        checkpoint_te_api_key="k",
        lakera_guard_base_url="https://api.lakera.ai",
        lakera_guard_api_key="k",
        audit_log_path=tmp_path / "audit.jsonl",
        upload_dir=upload,
        max_upload_bytes=1024 * 1024,
        rate_limit_per_minute=60,
    )
    base.update(over)
    return Settings(**base)


def _ctx(tmp_path: Path, scopes: set[str], *, rate_per_min: int = 60,
         daily_quota: int = 0, dlp_mode: str = "redact") -> tuple[ToolContext, AuditLogger]:
    s = _settings(tmp_path, scopes, rate_limit_per_minute=rate_per_min,
                  daily_quota=daily_quota, dlp_mode=dlp_mode)
    audit = AuditLogger(s.audit_log_path, s.identity.caller_id)
    ctx = ToolContext(
        settings=s,
        audit=audit,
        rate=ScopedRateLimiter(per_minute=s.rate_limit_per_minute),
        quota=DailyQuota(daily_limit=s.daily_quota),
        dlp=DLPScanner(mode=s.dlp_mode),
    )
    return ctx, audit


def _last_entry(path: Path) -> dict:
    return json.loads(path.read_text().strip().splitlines()[-1])


def test_scope_denial_short_circuits_before_adapter(tmp_path: Path):
    ctx, audit = _ctx(tmp_path, scopes={"ai_guard"})
    te = MagicMock()
    mcp = FakeMCP()
    threat_emulation.register(mcp, ctx, te)
    with pytest.raises(AuthorizationError):
        mcp.tools["query_verdict"]("a" * 64)
    te.query_verdict.assert_not_called()
    audit.close()
    entry = _last_entry(ctx.settings.audit_log_path)
    assert entry["result"] == "error"
    assert entry["details"]["error_type"] == "AuthorizationError"


def test_authorized_call_invokes_adapter_and_audits(tmp_path: Path):
    ctx, audit = _ctx(tmp_path, scopes={"threat_emulation"})
    te = MagicMock()
    te.query_verdict.return_value = {"verdict": "benign", "sha256": "a" * 64}
    mcp = FakeMCP()
    threat_emulation.register(mcp, ctx, te)

    out = mcp.tools["query_verdict"]("A" * 64)

    te.query_verdict.assert_called_once_with("a" * 64)
    assert out["verdict"] == "benign"
    audit.close()
    entry = _last_entry(ctx.settings.audit_log_path)
    assert entry["tool"] == "threat_emulation"
    assert entry["result"] == "ok"
    assert entry["details"]["sha256"] == "a" * 64


def test_invalid_input_raises_before_adapter(tmp_path: Path):
    ctx, audit = _ctx(tmp_path, scopes={"threat_emulation"})
    te = MagicMock()
    mcp = FakeMCP()
    threat_emulation.register(mcp, ctx, te)
    with pytest.raises(ValidationError):
        mcp.tools["query_verdict"]("not-a-sha")
    te.query_verdict.assert_not_called()
    audit.close()


def test_adapter_error_is_audited(tmp_path: Path):
    ctx, audit = _ctx(tmp_path, scopes={"ai_guard"})
    lakera = MagicMock()
    lakera.screen_prompt.side_effect = RuntimeError("upstream down")
    mcp = FakeMCP()
    ai_guard.register(mcp, ctx, lakera)

    with pytest.raises(RuntimeError):
        mcp.tools["screen_prompt"]("hello world")
    audit.close()
    entry = _last_entry(ctx.settings.audit_log_path)
    assert entry["result"] == "error"
    assert entry["details"]["error_type"] == "RuntimeError"


def test_rate_limit_blocks_after_burst(tmp_path: Path):
    ctx, audit = _ctx(tmp_path, scopes={"threat_emulation"}, rate_per_min=2)
    te = MagicMock()
    te.query_verdict.return_value = {"verdict": "benign"}
    mcp = FakeMCP()
    threat_emulation.register(mcp, ctx, te)
    mcp.tools["query_verdict"]("a" * 64)
    mcp.tools["query_verdict"]("b" * 64)
    with pytest.raises(RateLimitExceeded):
        mcp.tools["query_verdict"]("c" * 64)
    assert te.query_verdict.call_count == 2
    audit.close()


def test_daily_quota_blocks(tmp_path: Path):
    ctx, audit = _ctx(tmp_path, scopes={"threat_emulation"}, daily_quota=1)
    te = MagicMock()
    te.query_verdict.return_value = {"verdict": "benign"}
    mcp = FakeMCP()
    threat_emulation.register(mcp, ctx, te)
    mcp.tools["query_verdict"]("a" * 64)
    with pytest.raises(QuotaExceeded):
        mcp.tools["query_verdict"]("b" * 64)
    assert te.query_verdict.call_count == 1
    audit.close()


def test_dlp_redacts_before_lakera(tmp_path: Path):
    ctx, audit = _ctx(tmp_path, scopes={"ai_guard"}, dlp_mode="redact")
    lakera = MagicMock()
    lakera.screen_prompt.return_value = {"flagged": False}
    mcp = FakeMCP()
    ai_guard.register(mcp, ctx, lakera)

    mcp.tools["screen_prompt"]("my key AKIAIOSFODNN7EXAMPLE please screen")

    # The secret must have been redacted BEFORE reaching the Lakera adapter.
    sent = lakera.screen_prompt.call_args.args[0]
    assert "AKIAIOSFODNN7EXAMPLE" not in sent
    assert "[REDACTED:aws_access_key_id]" in sent
    audit.close()
    entry = _last_entry(ctx.settings.audit_log_path)
    assert entry["details"]["dlp"] == [{"type": "aws_access_key_id", "count": 1}]


def test_dlp_block_mode_prevents_egress(tmp_path: Path):
    ctx, audit = _ctx(tmp_path, scopes={"ai_guard"}, dlp_mode="block")
    lakera = MagicMock()
    mcp = FakeMCP()
    ai_guard.register(mcp, ctx, lakera)

    with pytest.raises(DLPViolation):
        mcp.tools["screen_prompt"]("leaking AKIAIOSFODNN7EXAMPLE")
    lakera.screen_prompt.assert_not_called()  # never reached the boundary
    audit.close()
    entry = _last_entry(ctx.settings.audit_log_path)
    assert entry["result"] == "error"
    assert entry["details"]["error_type"] == "DLPViolation"


def test_threat_intel_validates_and_audits(tmp_path: Path):
    ctx, audit = _ctx(tmp_path, scopes={"threat_intel"})
    tc = MagicMock()
    tc.lookup_ip.return_value = {"reputation": "malicious", "confidence": 90}
    mcp = FakeMCP()
    threat_intel.register(mcp, ctx, tc)

    out = mcp.tools["lookup_ip"]("8.8.8.8")
    tc.lookup_ip.assert_called_once_with("8.8.8.8")
    assert out["reputation"] == "malicious"

    with pytest.raises(ValidationError):
        mcp.tools["lookup_ip"]("not-an-ip")
    audit.close()
