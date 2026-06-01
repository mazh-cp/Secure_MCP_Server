from pathlib import Path

import pytest

from secure_mcp.auth import AuthorizationError, require_scope
from secure_mcp.config import Identity, Settings


def _settings(scopes: set[str]) -> Settings:
    return Settings(
        identity=Identity(caller_id="test", allowed_tools=frozenset(scopes)),
        checkpoint_te_base_url="https://te.checkpoint.com",
        checkpoint_te_api_key="k",
        lakera_guard_base_url="https://api.lakera.ai",
        lakera_guard_api_key="k",
        audit_log_path=Path("/tmp/audit.jsonl"),
        upload_dir=Path("/tmp"),
        max_upload_bytes=1024,
        rate_limit_per_minute=60,
    )


def test_require_scope_allows():
    require_scope(_settings({"ai_guard"}), "ai_guard")


def test_require_scope_denies():
    with pytest.raises(AuthorizationError):
        require_scope(_settings({"ai_guard"}), "threat_emulation")
