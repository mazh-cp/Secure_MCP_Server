"""HTTP/SSE upstream support for the guard forwarder: URL validation (offline)
and a real Streamable-HTTP integration against a subprocess MCP server."""

import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from secure_mcp.mcpguard.forwarder import MCPForwarder, validate_upstream_url

FIXTURE = str(Path(__file__).parent / "fixtures" / "fake_http_server.py")


# ---- URL validation (no network) ----
def test_https_allowed():
    assert validate_upstream_url("https://mcp.example.com/mcp").startswith("https://")


def test_loopback_http_allowed():
    assert validate_upstream_url("http://127.0.0.1:9000/mcp")
    assert validate_upstream_url("http://localhost:9000/mcp")


def test_non_loopback_http_rejected():
    with pytest.raises(ValueError, match="must use https"):
        validate_upstream_url("http://mcp.example.com/mcp")


def test_bad_scheme_rejected():
    with pytest.raises(ValueError, match="scheme"):
        validate_upstream_url("ftp://example.com/x")


def test_unknown_transport_rejected():
    fwd = MCPForwarder({"x": {"transport": "carrier-pigeon", "url": "https://x/y"}})
    try:
        with pytest.raises(ValueError, match="transport"):
            fwd.list_tools("x")
    finally:
        fwd.close()


# ---- live Streamable-HTTP integration ----
def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port: int, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def test_streamable_http_upstream_through_forwarder():
    port = _free_port()
    proc = subprocess.Popen([sys.executable, FIXTURE, str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _wait_port(port):
        proc.terminate()
        pytest.fail("HTTP MCP fixture did not start")
    fwd = MCPForwarder({"web": {"transport": "streamable-http",
                                "url": f"http://127.0.0.1:{port}/mcp"}})
    try:
        names = [t["name"] for t in fwd.list_tools("web")]
        assert "echo" in names
        assert fwd.call("web", "echo", {"text": "hi"}) == "echo:hi"
    finally:
        fwd.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
