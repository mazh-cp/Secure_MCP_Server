from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditLogger
from .config import Settings
from .dlp import DLPScanner
from .quota import DailyQuota
from .rate_limit import ScopedRateLimiter


@dataclass
class ToolContext:
    """Cross-cutting guards threaded into every tool group. Bundling them keeps
    register() signatures stable as new controls are added."""

    settings: Settings
    audit: AuditLogger
    rate: ScopedRateLimiter
    quota: DailyQuota
    dlp: DLPScanner

    def preflight(self, scope: str) -> None:
        """Run the standard gate every tool performs before touching an
        upstream: authorization, then daily quota, then per-minute rate.
        Raises (AuthorizationError / QuotaExceeded / RateLimitExceeded) on deny."""
        from .auth import require_scope

        require_scope(self.settings, scope)
        self.quota.check()
        self.rate.check(scope)
