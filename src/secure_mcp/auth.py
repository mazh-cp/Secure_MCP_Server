from __future__ import annotations

from .config import Settings


class AuthorizationError(PermissionError):
    pass


# Under stdio transport, the caller is the parent process that spawned this
# server, so the identity file functions as a deploy-time capability
# constraint rather than per-request authentication. Switch to HTTP/SSE
# transport with mTLS or signed tokens before exposing beyond local IPC.
def require_scope(settings: Settings, scope: str) -> None:
    if scope not in settings.identity.allowed_tools:
        raise AuthorizationError(
            f"caller '{settings.identity.caller_id}' is not authorized for scope '{scope}'"
        )
