#!/usr/bin/env python3
"""
MCP server for ILSpy -- proxies Claude Code tool calls to an
ICSharpCode.Decompiler-backed bridge process loaded with a .NET assembly.

Usage:
    python ilspy/mcp_server.py              # stdio mode for Claude Code
    python ilspy/mcp_server.py --list       # list active instances
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

from common import call_instance, discover_instances, list_instances_text

REG_DIR = os.path.expanduser("~/.ilspy_mcp")
TOOL = "ILSpy"
NAME_KEYS = ("assembly", "assembly_path")

mcp = FastMCP("ilspy")


def _call(endpoint, body=None, assembly=None):
    return call_instance(REG_DIR, endpoint, body, target=assembly,
                         tool_name=TOOL, name_keys=NAME_KEYS, timeout=120)


@mcp.tool()
def list_instances() -> str:
    """List active ILSpy bridges and the assembly each one loaded."""
    return list_instances_text(REG_DIR, TOOL, name_key="assembly")


@mcp.tool()
def info(assembly: str = "") -> dict:
    """Get info about the loaded assembly (name, version, type/method counts).

    Args:
        assembly: Assembly filename substring to target a specific bridge (optional)
    """
    return _call("/info", assembly=assembly or None)


@mcp.tool()
def list_assemblies(assembly: str = "") -> dict:
    """List referenced assemblies for the loaded module.

    Args:
        assembly: Assembly filename substring to target (optional)
    """
    return _call("/list_assemblies", assembly=assembly or None)


@mcp.tool()
def list_types(prefix: str = "", limit: int = 200, assembly: str = "") -> dict:
    """List full type names, optionally filtered by namespace/name prefix.

    Args:
        prefix: Only include types whose full name starts with this string
        limit: Max results (default 200)
        assembly: Assembly filename substring to target (optional)
    """
    return _call("/list_types", {"prefix": prefix, "limit": limit},
                 assembly=assembly or None)


@mcp.tool()
def search_types(pattern: str, limit: int = 100, assembly: str = "") -> dict:
    """Substring (case-insensitive) search across full type names.

    Args:
        pattern: Substring to search for
        limit: Max results (default 100)
        assembly: Assembly filename substring to target (optional)
    """
    return _call("/search_types",
                 {"pattern": pattern, "limit": limit},
                 assembly=assembly or None)


@mcp.tool()
def decompile_type(name: str, assembly: str = "") -> dict:
    """Decompile a type to C#.

    Args:
        name: Full type name (e.g., System.Collections.Generic.List`1) or substring
        assembly: Assembly filename substring to target (optional)
    """
    return _call("/decompile_type", {"name": name}, assembly=assembly or None)


@mcp.tool()
def list_methods(type_name: str, assembly: str = "") -> dict:
    """List methods of a type with their signatures.

    Args:
        type_name: Full type name (or substring)
        assembly: Assembly filename substring to target (optional)
    """
    return _call("/list_methods", {"type": type_name}, assembly=assembly or None)


@mcp.tool()
def decompile_method(type_name: str, method: str, assembly: str = "") -> dict:
    """Decompile a single method to C#.

    Args:
        type_name: Full type name
        method: Method name (or full signature to disambiguate overloads)
        assembly: Assembly filename substring to target (optional)
    """
    return _call("/decompile_method",
                 {"type": type_name, "method": method},
                 assembly=assembly or None)


@mcp.tool()
def get_il(type_name: str, method: str, assembly: str = "") -> dict:
    """Get raw IL for a method.

    Args:
        type_name: Full type name
        method: Method name (or full signature)
        assembly: Assembly filename substring to target (optional)
    """
    return _call("/get_il",
                 {"type": type_name, "method": method},
                 assembly=assembly or None)


@mcp.tool()
def search_strings(pattern: str, limit: int = 100, assembly: str = "") -> dict:
    """Search string literals embedded in the assembly's user-strings heap.

    Args:
        pattern: Substring to search for (case-sensitive)
        limit: Max results (default 100)
        assembly: Assembly filename substring to target (optional)
    """
    return _call("/search_strings",
                 {"pattern": pattern, "limit": limit},
                 assembly=assembly or None)


if __name__ == "__main__":
    if "--list" in sys.argv:
        instances = discover_instances(REG_DIR)
        if not instances:
            print("No active ILSpy instances.")
        else:
            print(f"{len(instances)} active instance(s):")
            for inst in instances:
                print(f"  port:{inst['port']}  pid:{inst.get('pid','?')}  assembly:{inst.get('assembly','?')}")
                print(f"    path: {inst.get('assembly_path', '?')}")
    else:
        mcp.run(transport="stdio")
