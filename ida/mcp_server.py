#!/usr/bin/env python3
"""
MCP server for IDA Pro — proxies Claude Code tool calls to IDA HTTP plugin(s).

Usage:
    python ida/mcp_server.py              # stdio mode for Claude Code
    python ida/mcp_server.py --list       # list active instances
"""

import os
import sys

# Allow imports from parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

from common import call_instance, discover_instances, list_instances_text

REG_DIR = os.path.expanduser("~/.ida_mcp")
TOOL = "IDA"
NAME_KEYS = ("idb", "idb_path")

mcp = FastMCP("ida")


def _call(endpoint, body=None, idb=None):
    return call_instance(REG_DIR, endpoint, body, target=idb,
                         tool_name=TOOL, name_keys=NAME_KEYS, timeout=30)


@mcp.tool()
def list_instances() -> str:
    """List all active IDA instances with their loaded IDBs."""
    return list_instances_text(REG_DIR, TOOL, name_key="idb")


@mcp.tool()
def idb_info(idb: str = "") -> dict:
    """Get basic info about a loaded IDB (functions, segments, processor, bits).

    Args:
        idb: IDB filename substring to target a specific instance (optional)
    """
    return _call("/info", idb=idb or None)


@mcp.tool()
def get_function(address: str = "", name: str = "", idb: str = "") -> dict:
    """Get function info (name, start, end, size) by address or name.

    Args:
        address: Function address (hex)
        name: Function name or substring
        idb: IDB filename substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    return _call("/function", body, idb=idb or None)


@mcp.tool()
def disassemble(address: str = "", name: str = "", start: str = "", end: str = "", idb: str = "") -> dict:
    """Disassemble a function or address range.

    Args:
        address: Function address to disassemble
        name: Function name to disassemble
        start: Start address for range disassembly
        end: End address for range disassembly
        idb: IDB filename substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    if start: body["start"] = start
    if end: body["end"] = end
    return _call("/disassemble", body, idb=idb or None)


@mcp.tool()
def decompile(address: str = "", name: str = "", idb: str = "") -> dict:
    """Decompile a function to pseudocode using Hex-Rays.

    Args:
        address: Function address
        name: Function name
        idb: IDB filename substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    return _call("/decompile", body, idb=idb or None)


@mcp.tool()
def xrefs_to(address: str = "", name: str = "", idb: str = "") -> dict:
    """Get all cross-references TO an address or function.

    Args:
        address: Target address
        name: Function name
        idb: IDB filename substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    return _call("/xrefs_to", body, idb=idb or None)


@mcp.tool()
def xrefs_from(address: str, idb: str = "") -> dict:
    """Get all cross-references FROM an address.

    Args:
        address: Source address
        idb: IDB filename substring to target (optional)
    """
    return _call("/xrefs_from", {"address": address}, idb=idb or None)


@mcp.tool()
def get_callers(address: str = "", name: str = "", idb: str = "") -> dict:
    """Get all functions that call a given function.

    Args:
        address: Function address
        name: Function name
        idb: IDB filename substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    return _call("/callers", body, idb=idb or None)


@mcp.tool()
def get_callees(address: str = "", name: str = "", idb: str = "") -> dict:
    """Get all functions called by a given function.

    Args:
        address: Function address
        name: Function name
        idb: IDB filename substring to target (optional)
    """
    body = {}
    if address: body["address"] = address
    if name: body["name"] = name
    return _call("/callees", body, idb=idb or None)


@mcp.tool()
def search_functions(pattern: str, idb: str = "") -> dict:
    """Search function names by substring (case-insensitive, max 100 results).

    Args:
        pattern: Substring to search for in function names
        idb: IDB filename substring to target (optional)
    """
    return _call("/search_functions", {"pattern": pattern}, idb=idb or None)


@mcp.tool()
def search_strings(pattern: str, idb: str = "") -> dict:
    """Search strings in the IDB by substring (max 100 results).

    Args:
        pattern: Substring to search for
        idb: IDB filename substring to target (optional)
    """
    return _call("/search_strings", {"pattern": pattern}, idb=idb or None)


@mcp.tool()
def get_segments(idb: str = "") -> dict:
    """List all memory segments in the IDB.

    Args:
        idb: IDB filename substring to target (optional)
    """
    return _call("/segments", idb=idb or None)


@mcp.tool()
def get_bytes(address: str, size: int = 256, idb: str = "") -> dict:
    """Read raw bytes from the IDB at an address.

    Args:
        address: Start address (hex)
        size: Number of bytes to read (max 4096)
        idb: IDB filename substring to target (optional)
    """
    return _call("/bytes", {"address": address, "size": size}, idb=idb or None)


@mcp.tool()
def rename(address: str, name: str, idb: str = "") -> dict:
    """Rename a function or address in the IDB.

    Args:
        address: Address to rename (hex)
        name: New name
        idb: IDB filename substring to target (optional)
    """
    return _call("/rename", {"address": address, "name": name}, idb=idb or None)


@mcp.tool()
def add_comment(address: str, comment: str, repeatable: bool = False, idb: str = "") -> dict:
    """Add a comment at an address in the IDB.

    Args:
        address: Address (hex)
        comment: Comment text
        repeatable: If True, comment shows at all xrefs
        idb: IDB filename substring to target (optional)
    """
    return _call("/comment", {"address": address, "comment": comment, "repeatable": repeatable}, idb=idb or None)


@mcp.tool()
def create_function(address: str, end: str = "", idb: str = "") -> dict:
    """Create a function at an address.

    Args:
        address: Start address (hex)
        end: Optional end address (hex)
        idb: IDB filename substring to target (optional)
    """
    body = {"address": address}
    if end: body["end"] = end
    return _call("/create_function", body, idb=idb or None)


@mcp.tool()
def delete_function(address: str, idb: str = "") -> dict:
    """Delete a function at an address.

    Args:
        address: Function address (hex)
        idb: IDB filename substring to target (optional)
    """
    return _call("/delete_function", {"address": address}, idb=idb or None)


@mcp.tool()
def make_code(address: str, size: int = 0, idb: str = "") -> dict:
    """Force bytes to be analyzed as code.

    Args:
        address: Start address (hex)
        size: Number of bytes to convert (0 = single instruction)
        idb: IDB filename substring to target (optional)
    """
    return _call("/make_code", {"address": address, "size": size}, idb=idb or None)


@mcp.tool()
def find_micromips_prologues(idb: str = "") -> dict:
    """Scan for microMIPS function prologues in data regions.

    Args:
        idb: IDB filename substring to target (optional)
    """
    return _call("/find_micromips_prologues", {}, idb=idb or None)


@mcp.tool()
def define_type(decl: str, idb: str = "") -> dict:
    """Parse C struct/union/typedef/function declarations into the IDB type library.

    Multiple declarations in one call are supported. The parsed types become
    available to apply_type / set_function_prototype.

    Args:
        decl: C source. Example:
              'struct CaptureCmd { uint32_t cmd_id; uint16_t channel_mask; uint16_t sample_rate_div; };'
        idb: IDB filename substring to target (optional)
    """
    return _call("/define_type", {"decl": decl}, idb=idb or None)


@mcp.tool()
def apply_type(address: str, type: str, idb: str = "") -> dict:
    """Apply a type to an address (struct overlay, variable type, etc.).

    Args:
        address: Target address (hex).
        type: Either a named type (e.g. 'CaptureCmd') or an inline C
              declaration (e.g. 'unsigned int sample_count;').
        idb: IDB filename substring to target (optional)
    """
    return _call("/apply_type", {"address": address, "type": type}, idb=idb or None)


@mcp.tool()
def set_function_prototype(address: str, prototype: str, idb: str = "") -> dict:
    """Set a function's prototype (calling convention + return type + args).

    Args:
        address: Function start address (hex).
        prototype: Full C function declaration including calling convention.
                   Example: 'void __fastcall Write(void *self, void *ep, unsigned char *buf, unsigned int size);'
        idb: IDB filename substring to target (optional)
    """
    return _call("/set_function_prototype",
                 {"address": address, "prototype": prototype},
                 idb=idb or None)


@mcp.tool()
def add_segment(start: str, end: str, name: str, perms: str = "rwx",
                sclass: str = "DATA", idb: str = "") -> dict:
    """Create a new memory segment in the IDB.

    Args:
        start: Start address (hex, inclusive).
        end: End address (hex, exclusive).
        name: Segment name (e.g. 'MMIO_UART', 'SRAM').
        perms: Permissions — any subset of 'r', 'w', 'x' (default 'rwx').
        sclass: Segment class — 'CODE' | 'DATA' | 'BSS' | 'XTRN' | 'CONST' | 'STACK'.
        idb: IDB filename substring to target (optional)
    """
    return _call("/add_segment",
                 {"start": start, "end": end, "name": name,
                  "perms": perms, "class": sclass},
                 idb=idb or None)


@mcp.tool()
def set_segment_attrs(address: str, name: str = "", perms: str = "",
                      sclass: str = "", idb: str = "") -> dict:
    """Modify attributes (name/perms/class) of the segment containing the address.

    Only fields you pass are changed. Empty strings are ignored.

    Args:
        address: Any address inside the target segment (hex).
        name: New segment name (optional).
        perms: New permissions string (optional).
        sclass: New segment class (optional).
        idb: IDB filename substring to target (optional)
    """
    body: dict = {"address": address}
    if name:   body["name"] = name
    if perms:  body["perms"] = perms
    if sclass: body["class"] = sclass
    return _call("/set_segment_attrs", body, idb=idb or None)


# ===========================================================================
# Debugger control
# ===========================================================================

@mcp.tool()
def dbg_state(idb: str = "") -> dict:
    """Return the current debugger state (detached/paused/running) + PID/PC.

    Args:
        idb: IDB filename substring to target (optional)
    """
    return _call("/dbg_state", {}, idb=idb or None)


@mcp.tool()
def dbg_attach(pid: int, idb: str = "") -> dict:
    """Attach the debugger to a running process by PID.

    Args:
        pid: Target process ID
        idb: IDB filename substring to target (optional)
    """
    return _call("/dbg_attach", {"pid": pid}, idb=idb or None)


@mcp.tool()
def dbg_launch(path: str, args: str = "", idb: str = "") -> dict:
    """Launch a new process under the debugger.

    Args:
        path: Executable path
        args: Command-line args (optional)
        idb: IDB filename substring to target (optional)
    """
    return _call("/dbg_launch", {"path": path, "args": args}, idb=idb or None)


@mcp.tool()
def dbg_detach(idb: str = "") -> dict:
    """Detach from the current debuggee (it keeps running)."""
    return _call("/dbg_detach", {}, idb=idb or None)


@mcp.tool()
def dbg_terminate(idb: str = "") -> dict:
    """Kill the debuggee."""
    return _call("/dbg_terminate", {}, idb=idb or None)


@mcp.tool()
def dbg_continue(idb: str = "") -> dict:
    """Resume execution. Returns when the debuggee suspends again or hits a BP."""
    return _call("/dbg_continue", {}, idb=idb or None)


@mcp.tool()
def dbg_pause(idb: str = "") -> dict:
    """Suspend the running debuggee."""
    return _call("/dbg_pause", {}, idb=idb or None)


@mcp.tool()
def dbg_step_into(idb: str = "") -> dict:
    """Single-step into. Calls are followed."""
    return _call("/dbg_step_into", {}, idb=idb or None)


@mcp.tool()
def dbg_step_over(idb: str = "") -> dict:
    """Single-step over. Calls are treated as one instruction."""
    return _call("/dbg_step_over", {}, idb=idb or None)


@mcp.tool()
def dbg_step_out(timeout_s: int = 30, idb: str = "") -> dict:
    """Step out of the current function — same as 'run until return'.

    Args:
        timeout_s: Max seconds to wait before reporting timeout (default 30)
        idb: IDB filename substring to target (optional)
    """
    return _call("/dbg_step_out", {"timeout_s": timeout_s}, idb=idb or None)


@mcp.tool()
def dbg_run_until_ret(timeout_s: int = 30, idb: str = "") -> dict:
    """Alias for dbg_step_out — execute until the current function returns."""
    return _call("/dbg_run_until_ret", {"timeout_s": timeout_s}, idb=idb or None)


@mcp.tool()
def dbg_run_to(address: str, timeout_s: int = 30, idb: str = "") -> dict:
    """Continue execution until the debuggee hits ``address``.

    Args:
        address: Target address (hex)
        timeout_s: Max seconds to wait (default 30)
        idb: IDB filename substring to target (optional)
    """
    return _call("/dbg_run_to", {"address": address, "timeout_s": timeout_s},
                 idb=idb or None)


@mcp.tool()
def dbg_set_breakpoint(address: str, type: str = "sw", size: int = 1,
                       idb: str = "") -> dict:
    """Add a breakpoint.

    Args:
        address: Address to break at (hex)
        type: 'sw' (int3) | 'hw_exec' | 'hw_write' | 'hw_read' | 'hw_rw'
        size: For hardware watches: range size in bytes (1/2/4/8)
        idb: IDB filename substring to target (optional)
    """
    return _call("/dbg_set_breakpoint",
                 {"address": address, "type": type, "size": size},
                 idb=idb or None)


@mcp.tool()
def dbg_del_breakpoint(address: str, idb: str = "") -> dict:
    """Remove the breakpoint at the given address."""
    return _call("/dbg_del_breakpoint", {"address": address}, idb=idb or None)


@mcp.tool()
def dbg_list_breakpoints(idb: str = "") -> dict:
    """List all active breakpoints with their addresses, sizes, and types."""
    return _call("/dbg_list_breakpoints", {}, idb=idb or None)


@mcp.tool()
def dbg_read_memory(address: str, size: int = 16, idb: str = "") -> dict:
    """Read live debuggee memory (hex-encoded). Auto-pauses if running.

    Args:
        address: Start address (hex)
        size: Number of bytes (max 65536)
        idb: IDB filename substring to target (optional)
    """
    return _call("/dbg_read_memory", {"address": address, "size": size},
                 idb=idb or None)


@mcp.tool()
def dbg_write_memory(address: str, hex: str, idb: str = "") -> dict:
    """Write live debuggee memory. Requires the debuggee to be paused.

    Args:
        address: Target address (hex)
        hex: Bytes to write, as a hex string
        idb: IDB filename substring to target (optional)
    """
    return _call("/dbg_write_memory", {"address": address, "hex": hex},
                 idb=idb or None)


@mcp.tool()
def dbg_get_reg(name: str, idb: str = "") -> dict:
    """Read a single register (e.g. 'rax', 'rip', 'rcx'). Auto-pauses."""
    return _call("/dbg_get_reg", {"name": name}, idb=idb or None)


@mcp.tool()
def dbg_set_reg(name: str, value: str, idb: str = "") -> dict:
    """Write a single register. Requires paused.

    Args:
        name: Register name
        value: New value (hex string or decimal)
        idb: IDB filename substring to target (optional)
    """
    return _call("/dbg_set_reg", {"name": name, "value": value}, idb=idb or None)


@mcp.tool()
def dbg_get_regs(idb: str = "") -> dict:
    """Return all general-purpose registers + flags of the current thread."""
    return _call("/dbg_get_regs", {}, idb=idb or None)


@mcp.tool()
def dbg_wait_event(timeout_s: int = 30, idb: str = "") -> dict:
    """Block until the next debug event (BP hit, exception, exit, ...).

    Returns ``{event_code, state, pc}``. Useful for 'continue, then wait'.
    """
    return _call("/dbg_wait_event", {"timeout_s": timeout_s}, idb=idb or None)


@mcp.tool()
def dbg_callstack(idb: str = "") -> dict:
    """Return the current thread's call stack."""
    return _call("/dbg_callstack", {}, idb=idb or None)


@mcp.tool()
def dbg_threads(idb: str = "") -> dict:
    """List threads in the debuggee."""
    return _call("/dbg_threads", {}, idb=idb or None)


@mcp.tool()
def dbg_modules(idb: str = "") -> dict:
    """List loaded modules of the debuggee (name + base + size)."""
    return _call("/dbg_modules", {}, idb=idb or None)


# ===========================================================================
# Hex-Rays local variable manipulation
# ===========================================================================

@mcp.tool()
def rename_local_var(function: str, old_name: str, new_name: str,
                     idb: str = "") -> dict:
    """Rename a Hex-Rays local variable inside a function.

    Args:
        function: Function start address (hex)
        old_name: Current name (e.g. 'v40')
        new_name: New name (e.g. 'Buffer')
        idb: IDB filename substring to target (optional)
    """
    return _call("/rename_local_var",
                 {"function": function, "old_name": old_name, "new_name": new_name},
                 idb=idb or None)


@mcp.tool()
def set_local_var_type(function: str, name: str, type: str,
                       idb: str = "") -> dict:
    """Apply a C type to a Hex-Rays local variable.

    Args:
        function: Function start address (hex)
        name: Local variable name
        type: C type declaration (e.g. 'unsigned char *' or 'struct CaptureCmd')
        idb: IDB filename substring to target (optional)
    """
    return _call("/set_local_var_type",
                 {"function": function, "name": name, "type": type},
                 idb=idb or None)


if __name__ == "__main__":
    if "--list" in sys.argv:
        instances = discover_instances(REG_DIR)
        if not instances:
            print("No active IDA instances.")
        else:
            print(f"{len(instances)} active instance(s):")
            for inst in instances:
                print(f"  port:{inst['port']}  pid:{inst.get('pid','?')}  idb:{inst.get('idb','?')}")
                print(f"    path: {inst.get('idb_path', '?')}")
    else:
        mcp.run(transport="stdio")
