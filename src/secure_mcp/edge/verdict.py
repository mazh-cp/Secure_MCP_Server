from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

# Decision actions returned to the browser PEP.
ALLOW = "allow"
WARN = "warn"
BLOCK = "block"


@dataclass(frozen=True)
class UrlPolicy:
    block_malicious: bool = True
    block_phishing: bool = True
    block_suspicious: bool = False


def classify_response(resp: dict[str, Any]) -> str:
    """Normalize a ThreatCloud reputation response into a classification:
    malicious | phishing | suspicious | benign | unknown.

    VERIFY against your subscription's reputation API: the field names below
    are a defensive best-effort across common shapes, not a contract. Keep this
    function and its tests as the single place that encodes the mapping.
    """
    fields: list[str] = []
    for k in ("classification", "verdict", "reputation", "risk", "severity", "category"):
        v = resp.get(k)
        if isinstance(v, str):
            fields.append(v.lower())
    blob = " ".join(fields) if fields else json.dumps(resp).lower()

    if "malicious" in blob or "malware" in blob:
        return "malicious"
    if "phish" in blob:
        return "phishing"
    if "suspicious" in blob:
        return "suspicious"
    if "benign" in blob or "clean" in blob or "safe" in blob or "low" in blob:
        return "benign"
    return "unknown"


def decide(classification: str, policy: UrlPolicy) -> dict[str, str]:
    """Map a classification to an enforcement action under the given policy.
    Unknown/benign fail open (allow) — the PEP keeps the user working; only a
    positive bad classification blocks."""
    action = ALLOW
    if classification == "malicious" and policy.block_malicious:
        action = BLOCK
    elif classification == "phishing" and policy.block_phishing:
        action = BLOCK
    elif classification == "suspicious":
        action = BLOCK if policy.block_suspicious else WARN
    return {"action": action, "classification": classification}
