#!/usr/bin/env python3
"""
MCP server for IDA Pro — proxies Claude Code tool calls to IDA HTTP plugin(s).

Usage:
    python ida/mcp_server.py                         # local instances via ~/.ida_mcp/
    python ida/mcp_server.py --remote 192.168.1.5   # remote IDA (port 13337)
    python ida/mcp_server.py --remote 192.168.1.5:13338
    python ida/mcp_server.py --list                  # list local instances

Remote mode: set IDA_MCP_REMOTE=host[:port] in the environment, or pass --remote.
On the remote machine, launch IDA with IDA_MCP_BIND=0.0.0.0 so the plugin
listens on all interfaces instead of 127.0.0.1.
"""

import os
import sys

# Allow imports from parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

from common import call_instance, call_remote, discover_instances, list_instances_text

REG_DIR = os.path.expanduser("~/.ida_mcp")
TOOL = "IDA"
NAME_KEYS = ("idb", "idb_path")

# Remote override: env var or --remote flag
_remote_arg = None
if "--remote" in sys.argv:
    _remote_arg = sys.argv[sys.argv.index("--remote") + 1]
# TEMP: hardcoded BEAST LAN IP as the default remote target so no env/config
# change is needed. Precedence: IDA_MCP_REMOTE env > --remote flag > this default.
# Set IDA_MCP_REMOTE="" (or remove this fallback) to go back to local mode.
REMOTE = os.environ.get("IDA_MCP_REMOTE") or _remote_arg or "192.168.1.189,192.168.1.35"


def _remote_hosts():
    """REMOTE may be a comma-separated list of bare hosts (or host:port entries)."""
    return [h.strip() for h in REMOTE.split(",") if h.strip()] if REMOTE else []

mcp = FastMCP("ida")


# ---------------------------------------------------------------------------
# Remote multi-instance support.
# IDA_MCP_REMOTE may be a bare host ("192.168.1.189") or host:port.
#   - host:port  -> target that one instance (explicit).
#   - bare host  -> scan its port range once (cached) and route by `idb`,
#                   mirroring local discovery. Plugin must bind non-localhost
#                   (IDA_MCP_BIND=0.0.0.0, the new default).
# ---------------------------------------------------------------------------
_REMOTE_CACHE = {"host": None, "instances": []}


def _remote_has_port():
    # only the explicit single-host:port form skips discovery
    hosts = _remote_hosts()
    return len(hosts) == 1 and ":" in hosts[0]


def _remote_scan(force=False):
    """Discover instances across ALL remote hosts in the REMOTE list (cached across calls)."""
    if _REMOTE_CACHE["host"] == REMOTE and _REMOTE_CACHE["instances"] and not force:
        return _REMOTE_CACHE["instances"]
    found = _scan_hosts(_remote_hosts())
    _REMOTE_CACHE.update(host=REMOTE, instances=found)
    return found


def _remote_resolve(idb=None):
    """Pick a remote instance by idb substring, else the first."""
    insts = _remote_scan()
    if not insts:
        return None
    if idb:
        t = idb.lower()
        return next((i for i in insts if t in i.get("idb", "").lower()), None)
    return insts[0]


def _remote_call(endpoint, body=None, idb=None, timeout=10):
    inst = _remote_resolve(idb)
    if inst is None:                      # stale cache? rescan once
        insts = _remote_scan(force=True)
        inst = _remote_resolve(idb)
        if inst is None:
            names = [i.get("idb", "?") for i in insts]
            who = f" matching '{idb}'" if idb else ""
            return {"error": f"No remote IDA instance{who} on {REMOTE}. Available: {names}"}
    return call_remote(f"{inst['host']}:{inst['port']}", endpoint, body, timeout=timeout)


def _call(endpoint, body=None, idb=None, timeout=10):
    """HTTP call into the IDA bridge.

    Default timeout 10s — short enough to surface plugin failures fast
    instead of hanging. Endpoints that legitimately wait longer (today
    only dbg_wait_event) must pass an explicit ``timeout``.
    """
    if REMOTE:
        if _remote_has_port():
            return call_remote(REMOTE, endpoint, body, timeout=timeout)
        return _remote_call(endpoint, body, idb=idb, timeout=timeout)
    return call_instance(REG_DIR, endpoint, body, target=idb,
                         tool_name=TOOL, name_keys=NAME_KEYS, timeout=timeout)


@mcp.tool()
def list_instances() -> str:
    """List all active IDA instances with their loaded IDBs."""
    if REMOTE:
        if _remote_has_port():
            result = call_remote(REMOTE, "/info", timeout=10)
            return f"Remote IDA at {REMOTE}: {result}"
        insts = _remote_scan(force=True)
        if not insts:
            return f"No active IDA instances on remote {REMOTE} (is IDA open with the LAN-bound plugin?)."
        lines = [f"  {i['host']}:{i['port']}  idb:{i.get('idb','?')}" for i in insts]
        return f"{len(insts)} active remote IDA instance(s) on {REMOTE}:\n" + "\n".join(lines)
    return list_instances_text(REG_DIR, TOOL, name_key="idb")


@mcp.tool()
def set_remote(hosts: str) -> str:
    """Point the MCP at IDA host(s) at RUNTIME -- no env var, no restart.

    Args:
        hosts: comma-separated host or host:port entries, e.g.
            "10.2.0.2:13340"          one explicit instance
            "10.2.0.2"                scan that host's port range, route by idb
            "10.2.0.2,192.168.1.189"  scan several
            ""                        clear remote -> fall back to local

    Returns the instances discovered so the connection is confirmed immediately.
    """
    global REMOTE
    REMOTE = (hosts or "").strip()
    _REMOTE_CACHE.update(host=None, instances=[])  # invalidate discovery cache
    if not REMOTE:
        return "Remote cleared -- using local IDA instances."
    if _remote_has_port():
        return f"Remote set to {REMOTE}. Instance: {call_remote(REMOTE, '/info', timeout=10)}"
    insts = _remote_scan(force=True)
    if not insts:
        return f"Remote set to {REMOTE}, but no instances answered (is IDA open + plugin LAN-bound?)."
    lines = [f"  {i['host']}:{i['port']}  idb:{i.get('idb','?')}" for i in insts]
    return f"Remote set to {REMOTE}. {len(insts)} instance(s):\n" + "\n".join(lines)


@mcp.tool()
def get_remote() -> str:
    """Show the remote host(s) the MCP is currently targeting."""
    return REMOTE or "(local mode -- no remote set)"


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
def execute_python(code: str, idb: str = "") -> dict:
    """Run arbitrary IDAPython in the target IDB's main thread; returns stdout + `_result`.

    Assign a variable named ``_result`` in your code to return a value. Use for load-time
    fixups (set_processor_type, rebase_program, Thumb sreg ranges, add_entry), bulk edits,
    or anything without a dedicated tool.

    Args:
        code: Python source executed inside IDA.
        idb: IDB filename substring to target (optional).
    """
    return _call("/execute_python", {"code": code}, idb=idb or None, timeout=180)


@mcp.tool()
def setup_arm_firmware(base: str = "", thumb: bool = True, bits: int = 32,
                       seed_prologues: bool = True, analyze: bool = True, idb: str = "") -> dict:
    """Load-fix a raw ARM firmware IDB (MTK preloader/DA etc.) in ONE call.

    Encodes the MediaTek profile and the common gotchas:
      * forces segment **bitness** (IDA often mis-defaults ARMv8 chips to AArch64 — wrong for a
        32-bit preloader; that makes every instruction decode as garbage),
      * **rebases** to the right base — auto-parsed from the MTK GFH FILE_INFO header when ``base``
        is omitted (base = load_addr - content_offset),
      * sets the **Thumb** default,
      * **seeds** functions from Thumb-2 ``E92D`` (PUSH.W) prologues so analysis cascades,
      * runs auto-analysis.

    Args:
        base: segment load address (hex). Omit to auto-derive from the GFH header.
        thumb: Thumb-2 code (default True — MTK preloaders/DAs).
        bits: 32 or 64 (default 32).
        seed_prologues: seed functions from PUSH.W prologues (default True).
        analyze: run auto-analysis afterwards (default True).
        idb: IDB filename substring to target (optional).
    """
    base_expr = "None" if not base else str(int(base, 16))
    code = (
        "import ida_segment, ida_idp, ida_segregs, ida_bytes, ida_ua, ida_funcs, ida_auto, idaapi, struct, re\n"
        + f"BASE={base_expr}; THUMB={bool(thumb)}; BITS={int(bits)}; SEED={bool(seed_prologues)}; ANALYZE={bool(analyze)}\n"
        + r'''steps=[]
seg=ida_segment.get_first_seg()
seg.bitness = 1 if BITS==32 else (2 if BITS==64 else 0); seg.update(); steps.append("bitness=%d"%BITS)
cur=seg.start_ea; base=BASE
if base is None:
    h=ida_bytes.get_bytes(cur,0x140) or b""
    gi=h.find(b"FILE_INFO")
    if gi>=0 and gi+36<=len(h):
        la=struct.unpack("<I",h[gi+20:gi+24])[0]; co=struct.unpack("<I",h[gi+32:gi+36])[0]
        base=la-co; steps.append("GFH load=%#x content=%#x -> base=%#x"%(la,co,base))
    else:
        base=cur; steps.append("no GFH; base kept")
delta=base-cur
if delta:
    ida_segment.rebase_program(delta, ida_segment.MSF_FIXONCE); seg=ida_segment.get_first_seg(); steps.append("rebased %+#x"%delta)
treg=ida_idp.str2reg("T")
if treg>=0:
    ida_segregs.set_default_sreg_value(seg, treg, 1 if THUMB else 0); steps.append("default T=%d"%(1 if THUMB else 0))
created=0
if SEED and treg>=0:
    data=ida_bytes.get_bytes(seg.start_ea, seg.size()) or b""
    for m in re.finditer(rb"\x2d\xe9", data):
        fa=seg.start_ea+m.start()
        if (fa & 1) or idaapi.is_code(ida_bytes.get_flags(fa)): continue
        ida_segregs.split_sreg_range(fa, treg, 1 if THUMB else 0, ida_segregs.SR_user, True)
        if ida_ua.create_insn(fa) and ida_funcs.add_func(fa): created+=1
        if created>6000: break
    steps.append("seeded %d prologues"%created)
if ANALYZE:
    ida_auto.plan_range(seg.start_ea, seg.end_ea); ida_auto.auto_wait(); steps.append("analyzed")
_result={"base":hex(base),"bitness":seg.bitness,"thumb":THUMB,"funcs":idaapi.get_func_qty(),"steps":steps}
'''
    )
    return _call("/execute_python", {"code": code}, idb=idb or None, timeout=300)


@mcp.tool()
def find_micromips_prologues(idb: str = "") -> dict:
    """Scan for microMIPS function prologues in data regions.

    Args:
        idb: IDB filename substring to target (optional)
    """
    return _call("/find_micromips_prologues", {}, idb=idb or None)


@mcp.tool()
def open_file(local_path: str, remote_filename: str = "", spawn: bool = True, idb: str = "") -> dict:
    """Upload a local binary to the remote IDA machine and open it in a new IDA instance.

    The file is base64-encoded and POSTed to /upload. Two receivers are tried in order:

    1. An existing IDA plugin instance (port 13337+) — works when IDA is already open.
    2. The standalone spawn server (port 13336) — works when NO IDA is open yet.
       Run  `python ida/spawn_server.py`  on the remote machine once to enable this.

    After IDA opens and finishes auto-analysis, run --scan to find the new port,
    then reconnect with --remote host:new_port.

    Args:
        local_path: Path to the binary on THIS machine
        remote_filename: Filename to use on the remote (default: basename of local_path)
        spawn: If True (default), launch a new IDA process on the uploaded file
        idb: IDB substring to target a specific instance (optional)
    """
    import base64
    import os as _os
    fname = remote_filename or _os.path.basename(local_path)
    try:
        with open(local_path, "rb") as f:
            data_b64 = base64.b64encode(f.read()).decode()
    except OSError as e:
        return {"error": f"Cannot read {local_path}: {e}"}

    body = {"filename": fname, "data": data_b64, "spawn": spawn}

    # Try existing IDA plugin first
    result = _call("/upload", body, idb=idb or None, timeout=120)
    if "error" not in result:
        return result

    # Fall back to standalone spawn server on port 13336 (first remote host)
    if REMOTE:
        _hs = _remote_hosts()
        host = (_hs[0] if _hs else REMOTE).split(":")[0]
        spawn_target = f"{host}:13336"
    else:
        spawn_target = None

    if spawn_target:
        fallback = call_remote(spawn_target, "/upload", body, timeout=120)
        if "error" not in fallback:
            fallback["note"] = (
                (fallback.get("note") or "") +
                " (via spawn_server on port 13336)"
            )
            return fallback
        return {
            "error": (
                f"No IDA instance found and spawn server unreachable at {spawn_target}. "
                "Run `python ida/spawn_server.py` on the remote machine first."
            ),
            "ida_error": result.get("error"),
            "spawn_error": fallback.get("error"),
        }

    return result


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
def dbg_silence(idb: str = "") -> dict:
    """Silence IDA debugger popups + mark all exceptions as pass-through.

    Done automatically on dbg_attach / dbg_launch. Use this manually if
    the process is already being debugged (started from IDA's UI rather
    than via this MCP) and the user is fighting popups + exception loops.

    Specifically:
    - DOPT_EXCDLG -> EXCDLG_NEVER (no modal exception dialog)
    - every known exception's flags: clear EXC_BREAK, set EXC_HANDLE + EXC_SILENT
      (target's SEH handler gets the exception, IDA does not pause)

    Without this, iLok/VMProtect-style protections trap IDA in an
    exception loop at the first protected code region.
    """
    return _call("/dbg_silence", {}, idb=idb or None)


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
def dbg_set_trace_bp(address: str, label: str = "",
                     addr_reg: str = "r8", size_reg: str = "r9",
                     idb: str = "") -> dict:
    """Arm a NON-PAUSING trace BP that dumps regs + memory on hit.

    Use this instead of dbg_set_breakpoint when reversing protocols that
    have a timing watchdog (iLok / VMProtect / custom firmware checks).
    Standard BPs pause the process for hundreds of ms during the MCP
    roundtrip, which trips the watchdog and corrupts device state.
    Trace BPs handle the hit inside IDA in microseconds and never pause.

    On each hit the plugin:
    - reads all common x86_64 registers
    - reads memory at [addr_reg] for size_reg bytes (Win64 fastcall:
      arg3=r8, arg4=r9 — that's WinUsb_WritePipe's buf + size)
    - appends a record to the in-process trace log
    - resumes the process

    Pull the captured records with dbg_get_trace_log.

    Args:
        address: hex address to break on (e.g. "0x1814C4BBB")
        label: free-form tag stored with each dump
        addr_reg: register holding the data pointer (default r8)
        size_reg: register holding the size (default r9)
    """
    return _call("/dbg_set_trace_bp",
                 {"address": address, "label": label,
                  "addr_reg": addr_reg, "size_reg": size_reg},
                 idb=idb or None)


@mcp.tool()
def dbg_clear_trace_bp(address: str, idb: str = "") -> dict:
    """Unregister a trace BP and remove the underlying breakpoint."""
    return _call("/dbg_clear_trace_bp", {"address": address}, idb=idb or None)


@mcp.tool()
def dbg_get_trace_log(clear: bool = False, idb: str = "") -> dict:
    """Return all captured trace-BP hits.

    Returns ``{entries: [...], count: N, cleared: bool}``. Each entry has
    ``{ts, label, ea, tid, regs, addr, size, data}`` where data is the
    hex-encoded memory at addr_reg for size_reg bytes.

    Pass clear=True to drain the log atomically (return + reset).
    """
    return _call("/dbg_get_trace_log", {"clear": clear}, idb=idb or None)


@mcp.tool()
def dbg_clear_trace_log(idb: str = "") -> dict:
    """Empty the trace log without returning entries."""
    return _call("/dbg_clear_trace_log", {}, idb=idb or None)


@mcp.tool()
def reload_plugin(idb: str = "") -> dict:
    """Re-import the IDA plugin module from disk and restart its HTTP
    server. Avoids the per-iteration manual ``importlib.reload`` paste
    in IDA's Python console after every plugin code change.

    The reload runs on a background thread so this call returns first
    (~0.5s later the server stops, module reloads, server restarts on
    the same port). The IDB, all breakpoints, and the scratch netnode
    persist.

    Wait ~1s after this returns before issuing further MCP calls so the
    new server is up.
    """
    return _call("/reload_plugin", {}, idb=idb or None)


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
    HTTP timeout = ``timeout_s`` + 5s slack so we don't cut the wait short.
    """
    return _call("/dbg_wait_event", {"timeout_s": timeout_s},
                 idb=idb or None, timeout=timeout_s + 5)


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


# ===========================================================================
# Per-IDB scratch / lab notebook
#
# Persistent free-form markdown buffer stored inside the IDB (in a named
# netnode). Auto-saves with the IDB; survives IDA restarts; multiple
# sessions can append to it. Use scratch_log for the common case of
# 'remember this discovery for next time'.
# ===========================================================================

@mcp.tool()
def scratch_read(idb: str = "") -> dict:
    """Return the current scratch / lab-notebook markdown for this IDB.

    Args:
        idb: IDB filename substring to target (optional)
    """
    return _call("/scratch_read", {}, idb=idb or None)


@mcp.tool()
def scratch_log(category: str, content: str, idb: str = "") -> dict:
    """Append a timestamped markdown section to the IDB scratch.

    The most-common entry point. Output format:

        ## [2026-05-16 14:32:08 UTC] {category}

        {content}

    Args:
        category: Short heading (e.g. 'Discovery', 'Dynamic capture',
                  'Hypothesis', 'Open question').
        content: Free-form markdown body (multi-line OK).
        idb: IDB filename substring to target (optional)
    """
    return _call("/scratch_log",
                 {"category": category, "content": content},
                 idb=idb or None)


@mcp.tool()
def scratch_append(text: str, idb: str = "") -> dict:
    """Append raw text (no timestamp/heading) to the scratch.

    Use scratch_log for normal entries; scratch_append is for fine
    control when you're building up a multi-piece markdown structure.
    """
    return _call("/scratch_append", {"text": text}, idb=idb or None)


@mcp.tool()
def scratch_replace(content: str, idb: str = "") -> dict:
    """Replace the entire scratch with new markdown."""
    return _call("/scratch_replace", {"content": content}, idb=idb or None)


@mcp.tool()
def scratch_clear(idb: str = "") -> dict:
    """Empty the scratch buffer entirely. Irreversible."""
    return _call("/scratch_clear", {}, idb=idb or None)


@mcp.tool()
def scratch_show(idb: str = "") -> dict:
    """Open the in-IDA markdown notebook viewer.

    Renders the scratch netnode as live markdown inside a dockable
    QTextBrowser. Auto-refreshes on scratch writes (200ms poll). Click
    on a `sub_XXXXXX` or `0x...` link to jumpto. Embed live pseudocode
    in markdown source with `{{decompile:0xADDR}}` — re-expands at
    every render so renames propagate.

    Hotkey inside IDA: Ctrl+Shift+N also opens the viewer.
    """
    return _call("/scratch_show", {}, idb=idb or None)


@mcp.tool()
def scratch_refresh(idb: str = "") -> dict:
    """Force the notebook viewer to re-render now.

    Useful after applying renames so the embedded `{{decompile:...}}`
    blocks pick up new names without waiting for the next scratch write.
    """
    return _call("/scratch_refresh", {}, idb=idb or None)


def _scan(host: str, port_range: range = range(13337, 13400)) -> list[dict]:
    """Probe a single host for IDA MCP plugin instances by pinging the port range."""
    return _scan_hosts([host], port_range)


def _scan_hosts(hosts, port_range: range = range(13337, 13361)) -> list[dict]:
    """Probe multiple hosts' port ranges IN PARALLEL for IDA MCP instances.

    Parallel so a down host (or many closed ports) doesn't serialize into a long wait; the
    result is aggregated across every host so routing-by-idb works across the whole fleet.
    """
    import httpx
    from concurrent.futures import ThreadPoolExecutor

    def probe(hp):
        host, port = hp
        try:
            r = httpx.get(f"http://{host}:{port}/ping", timeout=0.4)
            info = r.json()
            if info.get("status") == "ok":
                return {"host": host, "port": port, "idb": info.get("idb", "?")}
        except Exception:
            return None
        return None

    pairs = [(h.split(":")[0], p) for h in hosts for p in port_range]
    found = []
    with ThreadPoolExecutor(max_workers=64) as ex:
        for res in ex.map(probe, pairs):
            if res:
                found.append(res)
    return found


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
    elif "--scan" in sys.argv:
        idx = sys.argv.index("--scan")
        host = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else "127.0.0.1"
        print(f"Scanning {host} for IDA MCP instances (ports 13337-13399)...")
        found = _scan(host)
        if not found:
            print("  None found.")
        else:
            for inst in found:
                print(f"  {inst['host']}:{inst['port']}  idb:{inst['idb']}")
            print(f"\nTo use: --remote {found[0]['host']}:{found[0]['port']}")
    else:
        mcp.run(transport="stdio")
