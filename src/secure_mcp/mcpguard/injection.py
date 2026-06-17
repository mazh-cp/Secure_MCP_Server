"""Prompt-injection & tool-poisoning screening for MCP traffic.

This is the threat surface a browser-only security product structurally cannot
address: a malicious MCP server can poison the *tool description* (hidden
instructions the model reads when deciding to call a tool) or the *tool
response* (injected instructions / exfiltrated secrets). We screen both.

Design notes:
- "Hard" signals are imperative instructions aimed at the model (ignore previous
  instructions, role override, conceal-from-user, exfiltration, hidden directive
  markers, zero-width text). Any one → malicious.
- "Soft" signals (a description merely mentioning api_key, a curl snippet) are
  common in legitimate tools, so they only raise "suspicious" — avoiding the
  false positives that get a screener disabled.
- Findings carry the signal *type*, never raw secret values.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ..dlp import scan as dlp_scan

RISK_NONE = "none"
RISK_SUSPICIOUS = "suspicious"
RISK_MALICIOUS = "malicious"

_HARD = 5
_SOFT = 2

# (signal type, regex, weight)
_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("ignore_previous", re.compile(
        r"(?is)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b.{0,25}"
        r"\b(instruction|prompt|context|message|rule)", ), _HARD),
    ("role_override", re.compile(
        r"(?i)\b(you are now|act as|pretend to be|from now on you|new (system )?instructions?\s*:|"
        r"your (new )?system prompt)\b"), _HARD),
    ("conceal_from_user", re.compile(
        r"(?is)\b(do not|don'?t|never|without)\b.{0,25}\b(tell|inform|mention|reveal|show|notify|alert)\b"
        r".{0,20}\b(the\s+)?(user|human|operator)\b"), _HARD),
    ("exfiltration", re.compile(
        r"(?is)\b(exfiltrat\w*|leak|send|forward|post|upload)\b.{0,40}\b(to|http|https|email|webhook|"
        r"endpoint)\b"), _HARD),
    ("hidden_directive_marker", re.compile(
        r"(?i)(<\s*system\s*>|\[\s*system\s*\]|<\|im_start\|>|<\|system\|>|###\s*instruction|"
        r"<important>|<secret>)"), _HARD),
    # soft signals
    ("secret_reference", re.compile(
        r"(?i)(~/\.ssh|\bid_rsa\b|\.env\b|\bapi[_-]?key\b|\bsecret[_-]?key\b|\bcredential|\bpassword\b)"),
        _SOFT),
    ("remote_fetch", re.compile(r"(?i)(curl\s+https?://|wget\s+https?://|base64\s+-d|data:text/)"), _SOFT),
    ("tool_chain_injection", re.compile(
        r"(?is)\b(call|invoke|trigger|use)\b.{0,25}\b(the\s+)?\w+\s+tool\b.{0,40}\b(with|using|and pass)\b"),
        _SOFT),
]

_ZERO_WIDTH = re.compile(r"[​‌‍⁠﻿]")


@dataclass(frozen=True)
class InjectionFinding:
    type: str
    weight: int


def scan_for_injection(text: str) -> list[InjectionFinding]:
    if not isinstance(text, str) or not text:
        return []
    findings: list[InjectionFinding] = []
    for typ, rx, weight in _PATTERNS:
        if rx.search(text):
            findings.append(InjectionFinding(typ, weight))
    if _ZERO_WIDTH.search(text):
        findings.append(InjectionFinding("hidden_unicode", _HARD))
    return findings


def _risk(findings: list[InjectionFinding]) -> str:
    if any(f.weight >= _HARD for f in findings):
        return RISK_MALICIOUS
    if findings:
        return RISK_SUSPICIOUS
    return RISK_NONE


def screen_text(text: str) -> dict[str, Any]:
    findings = scan_for_injection(text)
    return {"risk": _risk(findings), "signals": [f.type for f in findings]}


def screen_tool_descriptor(name: str, description: str, schema: Any = None) -> dict[str, Any]:
    """Screen an MCP tool's advertised name/description/schema for poisoning —
    the instructions the model reads before deciding to call the tool."""
    blob = f"{name}\n{description}\n{json.dumps(schema, ensure_ascii=False) if schema else ''}"
    return screen_text(blob)


def screen_tool_response(text: str) -> dict[str, Any]:
    """Screen a tool's response for injected instructions AND leaked secrets."""
    findings = scan_for_injection(text)
    secrets = dlp_scan(text)
    risk = _risk(findings)
    if secrets and risk == RISK_NONE:
        risk = RISK_SUSPICIOUS
    return {
        "risk": risk,
        "signals": [f.type for f in findings],
        "dlp": [{"type": s.type, "count": s.count} for s in secrets],
    }
