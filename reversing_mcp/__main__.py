"""Run the unified MCP server over stdio."""

from .server import mcp

mcp.run(transport="stdio")
