import json
from pathlib import Path

from secure_mcp.audit import AuditLogger, verify_chain


def test_record_writes_jsonl(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    a = AuditLogger(log, "caller-1")
    a.record(tool="ai_guard", action="screen_prompt", result="ok", details={"text_len": 42})
    a.close()
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["caller_id"] == "caller-1"
    assert entry["tool"] == "ai_guard"
    assert entry["action"] == "screen_prompt"
    assert entry["result"] == "ok"
    assert entry["details"] == {"text_len": 42}
    assert entry["seq"] == 0
    assert "ts" in entry and "hash" in entry and "prev_hash" in entry


def test_redacts_secret_keys(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    a = AuditLogger(log, "caller-1")
    a.record(tool="x", action="y", result="ok", details={
        "api_key": "sk-real-key",
        "Authorization": "Bearer real",
        "nested": {"token": "tok-x", "user": "alice"},
        "list_of_secrets": [{"password": "pw"}, {"safe": "ok"}],
    })
    a.close()
    d = json.loads(log.read_text().strip())["details"]
    assert d["api_key"] == "[REDACTED]"
    assert d["Authorization"] == "[REDACTED]"
    assert d["nested"]["token"] == "[REDACTED]"
    assert d["nested"]["user"] == "alice"
    assert d["list_of_secrets"][0]["password"] == "[REDACTED]"
    assert d["list_of_secrets"][1]["safe"] == "ok"


def test_file_created_with_owner_only_mode(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    a = AuditLogger(log, "caller-1")
    a.close()
    # No records written -> file may be empty; ensure one record so it exists.
    a = AuditLogger(log, "caller-1")
    a.record(tool="x", action="y", result="ok")
    a.close()
    mode = log.stat().st_mode & 0o777
    assert mode == 0o600


def test_chain_verifies_intact(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    key = b"unit-test-key"
    a = AuditLogger(log, "caller-1", hmac_key=key)
    for i in range(5):
        a.record(tool="t", action="a", result="ok", details={"i": i})
    a.close()
    ok, err = verify_chain(log, key)
    assert ok, err


def test_chain_detects_edited_entry(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    key = b"unit-test-key"
    a = AuditLogger(log, "caller-1", hmac_key=key)
    a.record(tool="t", action="a", result="ok", details={"i": 0})
    a.record(tool="t", action="a", result="ok", details={"i": 1})
    a.close()

    lines = log.read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["result"] = "error"  # flip a field without recomputing the hash
    lines[0] = json.dumps(tampered, separators=(",", ":"))
    log.write_text("\n".join(lines) + "\n")

    ok, err = verify_chain(log, key)
    assert not ok
    assert "hash mismatch" in err


def test_chain_detects_deleted_entry(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    key = b"unit-test-key"
    a = AuditLogger(log, "caller-1", hmac_key=key)
    for i in range(3):
        a.record(tool="t", action="a", result="ok", details={"i": i})
    a.close()

    lines = log.read_text().splitlines()
    del lines[1]  # remove the middle entry
    log.write_text("\n".join(lines) + "\n")

    ok, err = verify_chain(log, key)
    assert not ok


def test_chain_resumes_across_restart(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    key = b"unit-test-key"
    a = AuditLogger(log, "caller-1", hmac_key=key)
    a.record(tool="t", action="a", result="ok")
    a.close()
    # New logger instance must continue the chain, not restart seq/prev_hash.
    b = AuditLogger(log, "caller-1", hmac_key=key)
    b.record(tool="t", action="a", result="ok")
    b.close()
    entries = [json.loads(l) for l in log.read_text().splitlines()]
    assert entries[1]["seq"] == 1
    assert entries[1]["prev_hash"] == entries[0]["hash"]
    ok, err = verify_chain(log, key)
    assert ok, err


def test_wrong_key_fails_verification(tmp_path: Path):
    log = tmp_path / "audit.jsonl"
    a = AuditLogger(log, "caller-1", hmac_key=b"right-key")
    a.record(tool="t", action="a", result="ok")
    a.close()
    ok, _ = verify_chain(log, b"wrong-key")
    assert not ok
