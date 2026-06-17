#!/usr/bin/env python3
"""A Streamable-HTTP upstream MCP server for the forwarder integration test.

    python fake_http_server.py <port>
"""

import sys

from mcp.server.fastmcp import FastMCP

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
mcp = FastMCP("fake-http-upstream", host="127.0.0.1", port=port)


@mcp.tool()
def echo(text: str) -> str:
    return f"echo:{text}"


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
