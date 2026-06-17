"""Live MCP forwarder — connects the guard to real upstream MCP servers over
stdio, Streamable HTTP, or SSE.

The guard's gate is synchronous (and heavily tested as such); the MCP client SDK
is async. This forwarder runs a dedicated asyncio loop on a background thread and
bridges via run_coroutine_threadsafe, so `list_tools()`/`call()` stay synchronous
for the guard while persistent sessions to upstreams live on the loop.

Only servers in the operator-provided registry can be reached (allowlist). HTTP
upstreams must be https unless loopback (fail-closed TLS posture).
"""

from __future__ import annotations

import asyncio
import ipaddress
import threading
import warnings
from contextlib import AsyncExitStack
from typing import Any
from urllib.parse import urlparse

from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client

# The newer streamable_http_client takes headers via a pre-built httpx client;
# the (deprecated) streamablehttp_client takes headers= directly, which is what
# we need for auth headers to HTTP upstreams. Silence only that rename notice.
warnings.filterwarnings("ignore", message=r".*streamable_http_client.*", category=DeprecationWarning)

_HTTP_TRANSPORTS = {"http", "streamable-http", "streamable_http"}


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in {"localhost", "ip6-localhost"}


def validate_upstream_url(url: str) -> str:
    """HTTPS required for non-loopback HTTP/SSE upstreams (TLS posture)."""
    p = urlparse(url)
    if p.scheme == "https":
        return url
    if p.scheme == "http":
        if _is_loopback(p.hostname or ""):
            return url
        raise ValueError(f"http MCP upstream '{url}' must use https (or be loopback)")
    raise ValueError(f"unsupported MCP upstream URL scheme: '{p.scheme}'")


def _infer_transport(spec: dict) -> str:
    t = (spec.get("transport") or "").lower()
    if t:
        return t
    if "command" in spec:
        return "stdio"
    if "url" in spec:
        return "streamable-http"
    return ""


class MCPForwarder:
    """Transport-aware forwarder. Registry entries:
        stdio: {"command": "...", "args": [...], "env": {..}?}
        http:  {"transport": "streamable-http", "url": "https://...", "headers": {..}?}
        sse:   {"transport": "sse", "url": "https://...", "headers": {..}?}
    """

    def __init__(self, registry: dict[str, dict], *, timeout: float = 30.0) -> None:
        self._registry = dict(registry)
        self._timeout = timeout
        self._sessions: dict[str, ClientSession] = {}
        self._stacks: dict[str, AsyncExitStack] = {}
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, name="mcp-forwarder", daemon=True)
        self._thread.start()

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result(timeout=self._timeout)

    async def _open(self, stack: AsyncExitStack, spec: dict):
        transport = _infer_transport(spec)
        if transport == "stdio":
            params = StdioServerParameters(command=spec["command"], args=list(spec.get("args", [])),
                                           env=spec.get("env"))
            read, write = await stack.enter_async_context(stdio_client(params))
            return read, write
        if transport in _HTTP_TRANSPORTS:
            url = validate_upstream_url(spec["url"])
            # streamablehttp yields (read, write, get_session_id)
            read, write, _ = await stack.enter_async_context(
                streamablehttp_client(url, headers=spec.get("headers")))
            return read, write
        if transport == "sse":
            url = validate_upstream_url(spec["url"])
            read, write = await stack.enter_async_context(
                sse_client(url, headers=spec.get("headers")))
            return read, write
        raise ValueError(f"unknown/unspecified transport for upstream (got '{transport}')")

    async def _session(self, server: str) -> ClientSession:
        if server in self._sessions:
            return self._sessions[server]
        spec = self._registry.get(server)
        if not spec:
            raise ValueError(f"unknown upstream MCP server '{server}' (not in registry)")
        stack = AsyncExitStack()
        read, write = await self._open(stack, spec)
        session = await stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        self._sessions[server] = session
        self._stacks[server] = stack
        return session

    # ---- sync Forwarder protocol (used by MCPGuard) ----
    def list_tools(self, server: str) -> list[dict[str, Any]]:
        return self._submit(self._list_tools(server))

    async def _list_tools(self, server: str) -> list[dict[str, Any]]:
        s = await self._session(server)
        r = await s.list_tools()
        return [{"name": t.name, "description": t.description or "", "inputSchema": t.inputSchema}
                for t in r.tools]

    def call(self, server: str, tool: str, args: dict[str, Any]) -> str:
        return self._submit(self._call(server, tool, args or {}))

    async def _call(self, server: str, tool: str, args: dict[str, Any]) -> str:
        s = await self._session(server)
        r = await s.call_tool(tool, args)
        text = "".join(getattr(c, "text", "") for c in (r.content or []))
        if r.isError:
            return text or "[upstream tool error]"
        return text

    def close(self) -> None:
        async def _shutdown():
            for stack in list(self._stacks.values()):
                try:
                    await stack.aclose()
                except Exception:  # noqa: BLE001 - best-effort teardown
                    pass
            self._stacks.clear()
            self._sessions.clear()
        try:
            asyncio.run_coroutine_threadsafe(_shutdown(), self._loop).result(timeout=10)
        except Exception:  # noqa: BLE001
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)


# Backwards-compatible alias (transport inferred from the registry entry).
StdioMCPForwarder = MCPForwarder
