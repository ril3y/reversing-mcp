#!/usr/bin/env python3
"""
MCP server for jadx -- proxies Claude Code tool calls to a jadx-core
headless bridge process loaded with an APK/JAR/DEX.

Usage:
    python jadx/mcp_server.py              # stdio mode for Claude Code
    python jadx/mcp_server.py --list       # list active instances
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

from common import call_instance, discover_instances, list_instances_text

REG_DIR = os.path.expanduser("~/.jadx_mcp")
TOOL = "jadx"
NAME_KEYS = ("jar", "jar_path")

mcp = FastMCP("jadx")


def _call(endpoint, body=None, jar=None):
    return call_instance(REG_DIR, endpoint, body, target=jar,
                         tool_name=TOOL, name_keys=NAME_KEYS, timeout=120)


@mcp.tool()
def list_instances() -> str:
    """List active jadx bridge processes and the JAR/APK each one loaded."""
    return list_instances_text(REG_DIR, TOOL, name_key="jar")


@mcp.tool()
def info(jar: str = "") -> dict:
    """Get info about the loaded archive (path, class count, method count).

    Args:
        jar: Archive filename substring to target a specific bridge (optional)
    """
    return _call("/info", jar=jar or None)


@mcp.tool()
def list_classes(prefix: str = "", limit: int = 200, jar: str = "") -> dict:
    """List class full names, optionally filtered by package/name prefix.

    Args:
        prefix: Only include classes whose full name starts with this string
        limit: Max results (default 200)
        jar: Archive filename substring to target (optional)
    """
    return _call("/list_classes", {"prefix": prefix, "limit": limit}, jar=jar or None)


@mcp.tool()
def get_class(name: str, jar: str = "") -> dict:
    """Get class metadata (full name, source file, method list) without source.

    Args:
        name: Full class name (e.g., com.example.Foo) or substring
        jar: Archive filename substring to target (optional)
    """
    return _call("/get_class", {"name": name}, jar=jar or None)


@mcp.tool()
def decompile_class(name: str, jar: str = "") -> dict:
    """Decompile a class to Java source.

    Args:
        name: Full class name (e.g., com.example.Foo) or substring
        jar: Archive filename substring to target (optional)
    """
    return _call("/decompile_class", {"name": name}, jar=jar or None)


@mcp.tool()
def decompile_method(class_name: str, method: str, jar: str = "") -> dict:
    """Decompile a single method and return the Java source for that method only.

    Args:
        class_name: Full class name
        method: Method name (or 'name(descriptor)' to disambiguate overloads)
        jar: Archive filename substring to target (optional)
    """
    return _call("/decompile_method",
                 {"class": class_name, "method": method},
                 jar=jar or None)


@mcp.tool()
def list_methods(class_name: str, jar: str = "") -> dict:
    """List method names + descriptors in a class.

    Args:
        class_name: Full class name (or substring)
        jar: Archive filename substring to target (optional)
    """
    return _call("/list_methods", {"class": class_name}, jar=jar or None)


@mcp.tool()
def search_classes(pattern: str, limit: int = 100, jar: str = "") -> dict:
    """Substring (case-insensitive) search across class full names.

    Args:
        pattern: Substring to search for
        limit: Max results (default 100)
        jar: Archive filename substring to target (optional)
    """
    return _call("/search_classes",
                 {"pattern": pattern, "limit": limit},
                 jar=jar or None)


@mcp.tool()
def search_strings(pattern: str, limit: int = 100, jar: str = "") -> dict:
    """Search string constants embedded in the archive.

    Args:
        pattern: Substring to search for
        limit: Max results (default 100)
        jar: Archive filename substring to target (optional)
    """
    return _call("/search_strings",
                 {"pattern": pattern, "limit": limit},
                 jar=jar or None)


@mcp.tool()
def xrefs_to(class_name: str, method: str = "", jar: str = "") -> dict:
    """Find usages of a class or method (call sites, field refs).

    Args:
        class_name: Full class name
        method: Optional method name to narrow the query
        jar: Archive filename substring to target (optional)
    """
    body = {"class": class_name}
    if method:
        body["method"] = method
    return _call("/xrefs_to", body, jar=jar or None)


if __name__ == "__main__":
    if "--list" in sys.argv:
        instances = discover_instances(REG_DIR)
        if not instances:
            print("No active jadx instances.")
        else:
            print(f"{len(instances)} active instance(s):")
            for inst in instances:
                print(f"  port:{inst['port']}  pid:{inst.get('pid','?')}  jar:{inst.get('jar','?')}")
                print(f"    path: {inst.get('jar_path', '?')}")
    else:
        mcp.run(transport="stdio")
