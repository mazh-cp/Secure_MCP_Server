from __future__ import annotations

import json
import logging
import sys
from typing import Any

_STD_LOG_KEYS = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName", "taskName",
}

_REDACT_KEYS = {"api_key", "authorization", "token", "secret", "password", "cookie"}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if k.lower() in _REDACT_KEYS else _redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v) for v in value]
    return value


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": record.created,
            "lvl": record.levelname,
            "name": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        for k, v in record.__dict__.items():
            if k not in _STD_LOG_KEYS and not k.startswith("_"):
                payload[k] = _redact(v)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=True, default=str)


def get_logger(name: str = "secure_mcp") -> logging.Logger:
    """Operational stderr logger (separate from the audit log). Never write
    customer content, secrets, or PII via this logger — use audit.AuditLogger
    for security-relevant events that need persistent, authorized storage."""
    log = logging.getLogger(name)
    if log.handlers:
        return log
    # stderr only: MCP stdio transport uses stdout for the protocol.
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JSONFormatter())
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False
    return log
