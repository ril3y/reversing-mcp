#!/usr/bin/env python3
"""
MCP server for Unicorn Engine -- proxies Claude Code tool calls to a
standalone Python bridge that owns one ``Uc`` instance.

Usage:
    python unicorn/mcp_server.py              # stdio mode for Claude Code
    python unicorn/mcp_server.py --list       # list active bridges
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

from common import call_instance, discover_instances, list_instances_text

REG_DIR = os.path.expanduser("~/.unicorn_mcp")
TOOL = "Unicorn"
NAME_KEYS = ("arch",)

mcp = FastMCP("unicorn")


def _call(endpoint, body=None, arch=None):
    return call_instance(REG_DIR, endpoint, body, target=arch,
                         tool_name=TOOL, name_keys=NAME_KEYS, timeout=120)


@mcp.tool()
def list_instances() -> str:
    """List active Unicorn bridge processes and their CPU arch."""
    return list_instances_text(REG_DIR, TOOL, name_key="arch")


@mcp.tool()
def info(arch: str = "") -> dict:
    """Get bridge state: arch, mapped regions, current PC, hook/snapshot counts.

    Args:
        arch: Arch substring to target a specific bridge (e.g. "thumb", "x86_64")
    """
    return _call("/info", arch=arch or None)


@mcp.tool()
def list_regions(arch: str = "") -> dict:
    """List currently mapped memory regions with start/size/perms.

    Args:
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/list_regions", arch=arch or None)


@mcp.tool()
def map_region(start: str, size: str, perms: str = "rwx", arch: str = "") -> dict:
    """Map a region of guest memory.

    Args:
        start: Start address (hex string like "0x10000000" or decimal)
        size:  Region size in bytes (hex or decimal)
        perms: Permission string, any subset of "rwx" (default "rwx")
        arch:  Arch substring to target a specific bridge (optional)
    """
    return _call("/map_region",
                 {"start": start, "size": size, "perms": perms},
                 arch=arch or None)


@mcp.tool()
def unmap_region(start: str, size: str, arch: str = "") -> dict:
    """Unmap a previously-mapped region.

    Args:
        start: Region start address
        size:  Region size
        arch:  Arch substring to target a specific bridge (optional)
    """
    return _call("/unmap_region",
                 {"start": start, "size": size},
                 arch=arch or None)


@mcp.tool()
def load_bytes(addr: str, hex: str, arch: str = "") -> dict:
    """Write hex-encoded bytes into already-mapped guest memory.

    Args:
        addr: Destination guest address
        hex:  Hex string of bytes (no 0x prefix, e.g. "deadbeef")
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/load_bytes", {"addr": addr, "hex": hex}, arch=arch or None)


@mcp.tool()
def load_file(addr: str, path: str, arch: str = "") -> dict:
    """Load a host file into already-mapped guest memory at addr.

    Args:
        addr: Destination guest address
        path: Host filesystem path to the binary blob
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/load_file", {"addr": addr, "path": path}, arch=arch or None)


@mcp.tool()
def read_mem(addr: str, size: str, arch: str = "") -> dict:
    """Read guest memory and return it as a hex string.

    Args:
        addr: Source guest address
        size: Number of bytes to read
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/read_mem", {"addr": addr, "size": size}, arch=arch or None)


@mcp.tool()
def write_mem(addr: str, hex: str, arch: str = "") -> dict:
    """Write hex-encoded bytes into guest memory (alias of load_bytes).

    Args:
        addr: Destination guest address
        hex:  Hex string of bytes
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/write_mem", {"addr": addr, "hex": hex}, arch=arch or None)


@mcp.tool()
def read_reg(name: str, arch: str = "") -> dict:
    """Read a CPU register by name. Returns {name, value} with value as hex.

    Args:
        name: Register name (arch-specific; e.g. "pc", "r0", "rax", "x0")
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/read_reg", {"name": name}, arch=arch or None)


@mcp.tool()
def write_reg(name: str, value: str, arch: str = "") -> dict:
    """Write a CPU register.

    Args:
        name:  Register name (arch-specific)
        value: New register value (hex or decimal)
        arch:  Arch substring to target a specific bridge (optional)
    """
    return _call("/write_reg", {"name": name, "value": value},
                 arch=arch or None)


@mcp.tool()
def disasm(addr: str, size: str, arch: str = "") -> dict:
    """Disassemble guest memory using capstone with the bridge's arch settings.

    Args:
        addr: Address to start disassembly at
        size: Byte count to disassemble
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/disasm", {"addr": addr, "size": size}, arch=arch or None)


@mcp.tool()
def step(count: int = 1, arch: str = "") -> dict:
    """Single-step ``count`` instructions starting at the current PC.

    Args:
        count: Number of instructions to execute (default 1)
        arch:  Arch substring to target a specific bridge (optional)
    """
    return _call("/step", {"count": count}, arch=arch or None)


@mcp.tool()
def run_until(pc: str = "", max_instructions: int = 0, timeout_ms: int = 0,
              arch: str = "") -> dict:
    """Run until a target PC, instruction budget, or timeout. Returns the stop reason.

    Args:
        pc: Optional target PC to stop at (0 / empty means run until budget/timeout)
        max_instructions: Optional instruction budget (0 = unlimited)
        timeout_ms: Optional wall-clock timeout in milliseconds (0 = unlimited)
        arch: Arch substring to target a specific bridge (optional)
    """
    body: dict = {
        "max_instructions": max_instructions,
        "timeout_ms": timeout_ms,
    }
    if pc:
        body["pc"] = pc
    return _call("/run_until", body, arch=arch or None)


@mcp.tool()
def add_hook(type: str, range: str, action: str,
             value: str = "", return_value: str = "",
             arch: str = "") -> dict:
    """Add a generic hook. Returns the hook id.

    Args:
        type: One of "mem_read", "mem_write", "code", "block"
        range: Address or "0x...-0x..." pair. Single address means "this address only".
        action: One of "stub", "trace", "break"
        value: For mem_read+stub: value returned on read. Hex or decimal.
        return_value: For code+stub: value to place in the return register before
            jumping to LR (so the rest of the program sees a stubbed-out function).
        arch: Arch substring to target a specific bridge (optional)
    """
    body: dict = {"type": type, "range": range, "action": action}
    if value:
        body["value"] = value
    if return_value:
        body["return_value"] = return_value
    return _call("/add_hook", body, arch=arch or None)


@mcp.tool()
def remove_hook(id: int, arch: str = "") -> dict:
    """Remove a hook by id.

    Args:
        id: Hook id previously returned from add_hook
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/remove_hook", {"id": id}, arch=arch or None)


@mcp.tool()
def list_hooks(arch: str = "") -> dict:
    """List all registered hooks (id, type, action, range, ...).

    Args:
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/list_hooks", arch=arch or None)


@mcp.tool()
def snapshot(name: str, arch: str = "") -> dict:
    """Capture register state + contents of every non-MMIO mapped region under ``name``.

    Args:
        name: Snapshot label (overwrites any prior snapshot with the same name)
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/snapshot", {"name": name}, arch=arch or None)


@mcp.tool()
def restore(name: str, arch: str = "") -> dict:
    """Restore a previously captured snapshot (regs + region bytes). Hooks are not touched.

    Args:
        name: Snapshot label
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/restore", {"name": name}, arch=arch or None)


@mcp.tool()
def list_snapshots(arch: str = "") -> dict:
    """List captured snapshots with their region/byte counts.

    Args:
        arch: Arch substring to target a specific bridge (optional)
    """
    return _call("/list_snapshots", arch=arch or None)


if __name__ == "__main__":
    if "--list" in sys.argv:
        instances = discover_instances(REG_DIR)
        if not instances:
            print("No active Unicorn instances.")
        else:
            print(f"{len(instances)} active instance(s):")
            for inst in instances:
                print(f"  port:{inst['port']}  pid:{inst.get('pid','?')}  arch:{inst.get('arch','?')}")
    else:
        mcp.run(transport="stdio")
