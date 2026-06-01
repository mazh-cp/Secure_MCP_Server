"""Local DLP egress filter.

Runs entirely on the broker host — no network calls, no data leaves. Its job
is to catch secrets and PII *before* any text crosses an external trust
boundary (notably the Lakera Guard egress in ai_guard). This is the broker's
own control, independent of any upstream.

Findings never carry the matched value — only the finding type and a count —
so the filter is safe to feed into the audit log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class DLPFinding:
    type: str
    count: int


class DLPViolation(ValueError):
    """Raised in 'block' mode when sensitive data is detected on an egress path."""


# Labeled, high-precision patterns. Deliberately conservative: a DLP filter
# that cries wolf gets disabled, which is worse than a tighter ruleset.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    # US SSN with the standard invalid-range guards (no 000/666/9xx area, etc.)
    ("us_ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
]

_CC_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _credit_card_spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for m in _CC_CANDIDATE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            spans.append((m.start(), m.end(), "credit_card"))
    return spans


def _all_spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for typ, rx in _PATTERNS:
        for m in rx.finditer(text):
            spans.append((m.start(), m.end(), typ))
    spans.extend(_credit_card_spans(text))
    return spans


def _dedupe_overlaps(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    # Prefer earlier start, then longer match, dropping anything that overlaps
    # an already-chosen span.
    spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
    chosen: list[tuple[int, int, str]] = []
    last_end = -1
    for s, e, t in spans:
        if s >= last_end:
            chosen.append((s, e, t))
            last_end = e
    return chosen


def scan(text: str) -> list[DLPFinding]:
    chosen = _dedupe_overlaps(_all_spans(text))
    counts: dict[str, int] = {}
    for _s, _e, t in chosen:
        counts[t] = counts.get(t, 0) + 1
    return [DLPFinding(t, c) for t, c in sorted(counts.items())]


def sanitize(text: str) -> tuple[str, list[DLPFinding]]:
    chosen = _dedupe_overlaps(_all_spans(text))
    counts: dict[str, int] = {}
    out = text
    for s, e, t in sorted(chosen, key=lambda x: x[0], reverse=True):
        out = out[:s] + f"[REDACTED:{t}]" + out[e:]
        counts[t] = counts.get(t, 0) + 1
    return out, [DLPFinding(t, c) for t, c in sorted(counts.items())]


class DLPScanner:
    """Applies the DLP policy on an egress path.

    mode:
      - "block"  : raise DLPViolation if anything is detected
      - "redact" : replace matches with [REDACTED:type], return sanitized text
      - "flag"   : pass text through unchanged, return findings for audit only
    """

    _MODES = frozenset({"block", "redact", "flag"})

    def __init__(self, mode: str = "redact") -> None:
        if mode not in self._MODES:
            raise ValueError(f"invalid DLP mode '{mode}' (expected one of {sorted(self._MODES)})")
        self.mode = mode

    def apply(self, text: str) -> tuple[str, list[DLPFinding]]:
        findings = scan(text)
        if not findings:
            return text, []
        if self.mode == "block":
            summary = ", ".join(f"{f.type} x{f.count}" for f in findings)
            raise DLPViolation(f"egress blocked by DLP: {summary}")
        if self.mode == "redact":
            return sanitize(text)
        return text, findings  # flag
