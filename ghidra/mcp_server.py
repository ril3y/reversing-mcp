#!/usr/bin/env python3
"""
MCP server for Ghidra — proxies Claude Code tool calls to Ghidra HTTP bridge(s).

Usage:
    python ghidra/mcp_server.py              # stdio mode for Claude Code
    python ghidra/mcp_server.py --list       # list active instances
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

from common import call_instance, discover_instances, list_instances_text

REG_DIR = os.path.expanduser("~/.ghidra_mcp")
TOOL = "Ghidra"
NAME_KEYS = ("program", "program_path")

mcp = FastMCP("ghidra")


def _call(endpoint, body=None, program=None):
    return call_instance(REG_DIR, endpoint, body, target=program,
                         tool_name=TOOL, name_keys=NAME_KEYS, timeout=60)


@mcp.tool()
def list_instances() -> str:
    """List all active Ghidra instances with their loaded programs."""
    return list_instances_text(REG_DIR, TOOL, name_key="program")


@mcp.tool()
def idb_info(program: str = "") -> dict:
    """Get basic info about a loaded program (functions, segments, processor, bits).

    Args:
        program: Program name substring to target (optional)
    """
    return _call("/info", program=program or None)


@mcp.tool()
def get_function(address: str = "", name: str = "", program: str = "") -> dict:
    """Get function info (name, start, end, size) by address or name.

    Args:
        address: Function address (hex)
        name: Function name or substring
        program: Program name substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    return _call("/function", body, program=program or None)


@mcp.tool()
def disassemble(address: str = "", name: str = "", start: str = "", end: str = "", program: str = "") -> dict:
    """Disassemble a function or address range.

    Args:
        address: Function address to disassemble
        name: Function name to disassemble
        start: Start address for range disassembly
        end: End address for range disassembly
        program: Program name substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    if start: body["start"] = start
    if end: body["end"] = end
    return _call("/disassemble", body, program=program or None)


@mcp.tool()
def decompile(address: str = "", name: str = "", program: str = "") -> dict:
    """Decompile a function to C pseudocode using Ghidra's decompiler.

    Args:
        address: Function address
        name: Function name
        program: Program name substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    return _call("/decompile", body, program=program or None)


@mcp.tool()
def xrefs_to(address: str = "", name: str = "", program: str = "") -> dict:
    """Get all cross-references TO an address or function.

    Args:
        address: Target address
        name: Function name
        program: Program name substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    return _call("/xrefs_to", body, program=program or None)


@mcp.tool()
def xrefs_from(address: str, program: str = "") -> dict:
    """Get all cross-references FROM an address.

    Args:
        address: Source address
        program: Program name substring to target (optional)
    """
    return _call("/xrefs_from", {"address": address}, program=program or None)


@mcp.tool()
def get_callers(address: str = "", name: str = "", program: str = "") -> dict:
    """Get all functions that call a given function.

    Args:
        address: Function address
        name: Function name
        program: Program name substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    return _call("/callers", body, program=program or None)


@mcp.tool()
def get_callees(address: str = "", name: str = "", program: str = "") -> dict:
    """Get all functions called by a given function.

    Args:
        address: Function address
        name: Function name
        program: Program name substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    return _call("/callees", body, program=program or None)


@mcp.tool()
def search_functions(pattern: str, program: str = "") -> dict:
    """Search function names by substring (case-insensitive, max 100 results).

    Args:
        pattern: Substring to search for
        program: Program name substring to target (optional)
    """
    return _call("/search_functions", {"pattern": pattern}, program=program or None)


@mcp.tool()
def search_strings(pattern: str, program: str = "") -> dict:
    """Search strings by substring (max 100 results).

    Args:
        pattern: Substring to search for
        program: Program name substring to target (optional)
    """
    return _call("/search_strings", {"pattern": pattern}, program=program or None)


@mcp.tool()
def get_segments(program: str = "") -> dict:
    """List all memory segments/blocks.

    Args:
        program: Program name substring to target (optional)
    """
    return _call("/segments", program=program or None)


@mcp.tool()
def get_bytes(address: str, size: int = 256, program: str = "") -> dict:
    """Read raw bytes at an address.

    Args:
        address: Start address (hex)
        size: Number of bytes to read (max 4096)
        program: Program name substring to target (optional)
    """
    return _call("/bytes", {"address": address, "size": size}, program=program or None)


@mcp.tool()
def rename(address: str, name: str, program: str = "") -> dict:
    """Rename a function or address.

    Args:
        address: Address to rename (hex)
        name: New name
        program: Program name substring to target (optional)
    """
    return _call("/rename", {"address": address, "name": name}, program=program or None)


@mcp.tool()
def add_comment(address: str, comment: str, repeatable: bool = False, program: str = "") -> dict:
    """Add a comment at an address.

    Args:
        address: Address (hex)
        comment: Comment text
        repeatable: If True, comment shows at all xrefs
        program: Program name substring to target (optional)
    """
    return _call("/comment", {"address": address, "comment": comment, "repeatable": repeatable}, program=program or None)


@mcp.tool()
def create_function(address: str, end: str = "", program: str = "") -> dict:
    """Create a function at an address.

    Args:
        address: Start address (hex)
        end: Optional end address (hex)
        program: Program name substring to target (optional)
    """
    body = {"address": address}
    if end: body["end"] = end
    return _call("/create_function", body, program=program or None)


@mcp.tool()
def delete_function(address: str, program: str = "") -> dict:
    """Delete a function at an address.

    Args:
        address: Function address (hex)
        program: Program name substring to target (optional)
    """
    return _call("/delete_function", {"address": address}, program=program or None)


if __name__ == "__main__":
    if "--list" in sys.argv:
        instances = discover_instances(REG_DIR)
        if not instances:
            print("No active Ghidra instances.")
        else:
            print(f"{len(instances)} active instance(s):")
            for inst in instances:
                print(f"  port:{inst['port']}  pid:{inst.get('pid','?')}  program:{inst.get('program','?')}")
                print(f"    path: {inst.get('program_path', '?')}")
    else:
        mcp.run(transport="stdio")
