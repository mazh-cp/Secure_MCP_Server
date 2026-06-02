from __future__ import annotations

# Single source of truth for the tool scopes the broker can expose. Used by the
# admin console to validate identity-file edits, and available for the server
# to reference. Keep in sync with the tool modules under tools/.
ALL_SCOPES: frozenset[str] = frozenset({
    "threat_emulation",
    "file_sandboxing",
    "ai_guard",
    "threat_intel",
    "url_category",
    "anti_phishing",
})

# Scopes that route indicators to ThreatCloud (require CHECKPOINT_TC_API_KEY).
THREATCLOUD_SCOPES: frozenset[str] = frozenset({
    "threat_intel",
    "url_category",
    "anti_phishing",
})
