# -*- coding: utf-8 -*-
"""
IDA Pro plugin -- embedded HTTP server for MCP integration.

Install: copy to IDA plugins directory or load via File > Script File.
Each IDA instance gets its own port and registers in ~/.ida_mcp/.

Supports multiple simultaneous IDA instances (different IDBs).
"""

import http.server
import json
import os
import socket
import threading
import traceback
from datetime import datetime, timezone

import ida_auto
import ida_bytes
import ida_dbg
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_idd
import ida_kernwin
import ida_netnode
import ida_lines
import ida_name
import ida_nalt
import ida_segment
import ida_typeinf
import ida_xref
import idautils
import idc

# IDA 9.2 removed ida_xref.get_xref_type_name -- map manually
_XREF_TYPE_NAMES = {
    0: "Data_Unknown", 1: "Data_Offset", 2: "Data_Write", 3: "Data_Read",
    4: "Data_Text", 5: "Data_Informational",
    16: "Code_Far_Call", 17: "Code_Near_Call",
    18: "Code_Far_Jump", 19: "Code_Near_Jump",
    20: "Code_User", 21: "Code_Ordinary_Flow",
}


def _xref_type_name(t):
    return _XREF_TYPE_NAMES.get(t, f"type_{t}")

REGISTRATION_DIR = os.path.expanduser("~/.ida_mcp")
BASE_PORT = 13337
MAX_PORT = 13400


_request_queue = []
_request_lock = threading.Lock()


def _run_on_main_thread(func, *args, **kwargs):
    """Execute a function on IDA's main thread and return its result.

    IDA's API is not thread-safe -- all ida_*/idc/idautils calls must
    run on the main thread. The HTTP server runs in a background thread.

    We put work on a queue and a UI timer drains it on the main thread.
    The HTTP handler thread blocks on an Event until the result is ready.
    This never deadlocks because we never call execute_sync.

    If the request stays queued for >5 s we log a warning to IDA's
    Output window — the most common cause is a modal dialog blocking
    IDA's main thread (e.g. "save changes? Y/N", a Hex-Rays warning,
    or "type already exists, overwrite?"). idc.batch(1) wrapping in
    _MainThreadTimer._tick suppresses most of these, but anything that
    leaks through is now visible.
    """
    result = [None]
    error = [None]
    done = threading.Event()

    item = (func, args, kwargs, result, error, done)
    with _request_lock:
        _request_queue.append(item)

    # Wait for the timer to process our request; surface a warning after 5s.
    if not done.wait(timeout=5.0):
        fn_name = getattr(func, "__name__", repr(func))
        ida_kernwin.msg(
            f"[MCP] WARNING: {fn_name} queued for >5s — "
            f"check for a modal dialog blocking IDA's main thread.\n"
        )
        done.wait()  # block until the dialog is dismissed and the timer fires

    if error[0] is not None:
        raise error[0]
    return result[0]


class _MainThreadTimer(object):
    """UI timer that drains the request queue on IDA's main thread."""

    def __init__(self, interval_ms=100):
        self._interval = interval_ms
        self._timer = ida_kernwin.register_timer(interval_ms, self._tick)
        if self._timer is None:
            print("[MCP] WARNING: failed to register UI timer")

    def _tick(self):
        with _request_lock:
            batch = list(_request_queue)
            _request_queue.clear()

        # Wrap every handler in idc.batch(1) so IDA suppresses modal dialogs
        # for the duration of the call. Without this, a stray "type already
        # exists, overwrite?" / "save Y/N?" popup blocks IDA's main thread,
        # which blocks this timer, which wedges every queued request until
        # the user notices and clicks the dialog. batch(1) makes IDA take
        # the default action silently. Per-request scope: we restore the
        # previous batch mode after each call so the user's interactive UI
        # is unaffected.
        for func, args, kwargs, result, error, done in batch:
            prev_batch = 0
            try:
                prev_batch = idc.batch(1)
                result[0] = func(*args, **kwargs)
            except Exception as e:
                error[0] = e
            finally:
                try:
                    idc.batch(prev_batch)
                except Exception:
                    pass
                done.set()

        return self._interval  # return interval to keep timer alive

    def stop(self):
        if self._timer is not None:
            ida_kernwin.unregister_timer(self._timer)
            self._timer = None


_ui_timer = None


def _find_free_port():
    """Find the next free port starting from BASE_PORT."""
    for port in range(BASE_PORT, MAX_PORT):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise RuntimeError(f"No free ports in range {BASE_PORT}-{MAX_PORT}")


def _idb_path():
    return ida_nalt.get_input_file_path() or ""


def _idb_name():
    path = _idb_path()
    return os.path.basename(path) if path else "unknown"


# ---------------------------------------------------------------------------
# IDA query functions
# ---------------------------------------------------------------------------

def get_function_at(addr):
    """Get function info at an address."""
    func = ida_funcs.get_func(addr)
    if not func:
        return None
    name = ida_name.get_name(func.start_ea) or f"sub_{func.start_ea:X}"
    return {
        "name": name,
        "start": func.start_ea,
        "end": func.end_ea,
        "size": func.size(),
    }


def get_function_by_name(name):
    """Find function by name (exact or substring)."""
    # Exact match first
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if ea != ida_idaapi.BADADDR:
        return get_function_at(ea)
    # Substring search
    for func_ea in idautils.Functions():
        fname = ida_name.get_name(func_ea) or ""
        if name.lower() in fname.lower():
            return get_function_at(func_ea)
    return None


def disassemble_function(addr):
    """Disassemble a function, return list of {addr, disasm, bytes}."""
    func = ida_funcs.get_func(addr)
    if not func:
        return None

    name = ida_name.get_name(func.start_ea) or f"sub_{func.start_ea:X}"
    lines = []
    ea = func.start_ea
    while ea < func.end_ea:
        disasm = idc.generate_disasm_line(ea, 0)
        size = idc.get_item_size(ea)
        raw = ida_bytes.get_bytes(ea, size)
        hex_bytes = raw.hex() if raw else ""
        lines.append({
            "address": f"0x{ea:08X}",
            "disasm": disasm,
            "bytes": hex_bytes,
        })
        ea = idc.next_head(ea, func.end_ea + 0x100)
        if ea == idc.BADADDR:
            break

    return {
        "name": name,
        "start": f"0x{func.start_ea:08X}",
        "end": f"0x{func.end_ea:08X}",
        "size": func.size(),
        "lines": lines,
    }


def disassemble_range(start, end):
    """Disassemble an arbitrary address range."""
    lines = []
    ea = start
    while ea < end:
        disasm = idc.generate_disasm_line(ea, 0)
        size = idc.get_item_size(ea)
        raw = ida_bytes.get_bytes(ea, size)
        hex_bytes = raw.hex() if raw else ""
        lines.append({
            "address": f"0x{ea:08X}",
            "disasm": disasm,
            "bytes": hex_bytes,
        })
        ea = idc.next_head(ea, end + 0x100)
        if ea == idc.BADADDR:
            break
    return lines


def get_xrefs_to(addr):
    """Get all cross-references to an address."""
    refs = []
    for xref in idautils.XrefsTo(addr, 0):
        func = ida_funcs.get_func(xref.frm)
        func_name = ""
        if func:
            func_name = ida_name.get_name(func.start_ea) or f"sub_{func.start_ea:X}"
        refs.append({
            "from": f"0x{xref.frm:08X}",
            "from_func": func_name,
            "type": xref.type,
            "type_name": _xref_type_name(xref.type),
        })
    return refs


def get_xrefs_from(addr):
    """Get all cross-references from an address (callees, data refs)."""
    refs = []
    for xref in idautils.XrefsFrom(addr, 0):
        name = ida_name.get_name(xref.to) or ""
        refs.append({
            "to": f"0x{xref.to:08X}",
            "name": name,
            "type": xref.type,
            "type_name": _xref_type_name(xref.type),
        })
    return refs


def get_callees(func_addr):
    """Get all functions called by a function."""
    func = ida_funcs.get_func(func_addr)
    if not func:
        return []
    callees = set()
    ea = func.start_ea
    while ea < func.end_ea:
        for xref in idautils.XrefsFrom(ea, 0):
            if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF,
                             ida_xref.fl_JN, ida_xref.fl_JF):
                target_func = ida_funcs.get_func(xref.to)
                if target_func and target_func.start_ea != func.start_ea:
                    name = ida_name.get_name(target_func.start_ea) or f"sub_{target_func.start_ea:X}"
                    callees.add((target_func.start_ea, name))
        ea = idc.next_head(ea, func.end_ea + 1)
        if ea == idc.BADADDR:
            break
    return [{"address": f"0x{a:08X}", "name": n} for a, n in sorted(callees)]


def get_callers(func_addr):
    """Get all functions that call a function."""
    callers = set()
    for xref in idautils.XrefsTo(func_addr, 0):
        if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF,
                         ida_xref.fl_JN, ida_xref.fl_JF):
            caller_func = ida_funcs.get_func(xref.frm)
            if caller_func:
                name = ida_name.get_name(caller_func.start_ea) or f"sub_{caller_func.start_ea:X}"
                callers.add((caller_func.start_ea, name, xref.frm))
    return [{"address": f"0x{a:08X}", "name": n, "call_site": f"0x{cs:08X}"}
            for a, n, cs in sorted(callers)]


def search_functions(pattern):
    """Search function names by substring (case-insensitive). Max 100."""
    pattern_lower = pattern.lower()
    results = []
    for func_ea in idautils.Functions():
        name = ida_name.get_name(func_ea) or ""
        if pattern_lower in name.lower():
            func = ida_funcs.get_func(func_ea)
            results.append({
                "address": f"0x{func_ea:08X}",
                "name": name,
                "size": func.size() if func else 0,
            })
            if len(results) >= 100:
                break
    return results


def search_strings(pattern):
    """Search strings in the IDB by substring. Max 100."""
    pattern_lower = pattern.lower()
    results = []
    sc = idautils.Strings()
    for s in sc:
        val = str(s)
        if pattern_lower in val.lower():
            results.append({
                "address": f"0x{s.ea:08X}",
                "value": val,
                "length": s.length,
            })
            if len(results) >= 100:
                break
    return results


def get_segments():
    """List all segments."""
    segs = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        name = ida_segment.get_segm_name(seg)
        perms = ""
        if seg.perm & 4: perms += "R"
        if seg.perm & 2: perms += "W"
        if seg.perm & 1: perms += "X"
        segs.append({
            "name": name,
            "start": f"0x{seg.start_ea:08X}",
            "end": f"0x{seg.end_ea:08X}",
            "size": seg.end_ea - seg.start_ea,
            "perms": perms,
        })
    return segs


def get_bytes_at(addr, size):
    """Read raw bytes from the IDB."""
    data = ida_bytes.get_bytes(addr, min(size, 4096))
    if data is None:
        return None
    return data.hex()


def decompile_function(addr):
    """Decompile a function using Hex-Rays (if available)."""
    if not ida_hexrays.init_hexrays_plugin():
        return {"error": "Hex-Rays not available"}
    try:
        cfunc = ida_hexrays.decompile(addr)
        if cfunc:
            return {
                "pseudocode": str(cfunc),
                "address": f"0x{addr:08X}",
            }
        return {"error": "Decompilation failed"}
    except ida_hexrays.DecompilationFailure as e:
        return {"error": f"Decompilation failed: {e}"}


def _mcp_log(msg, addr=None):
    """Log MCP write operations to IDA's output window.

    Uses ida_kernwin.msg() so addresses are clickable in the output window.
    If addr is provided, also jumps the disassembly view to that address.
    """
    ida_kernwin.msg(f"[MCP] {msg}\n")
    if addr is not None:
        ida_kernwin.jumpto(addr)


def rename_address(addr, new_name):
    """Rename a function or address."""
    old_name = ida_name.get_name(addr) or f"0x{addr:08X}"
    ok = ida_name.set_name(addr, new_name, ida_name.SN_CHECK)
    if ok:
        _mcp_log(f"RENAME 0x{addr:08X}: {old_name} -> {new_name}", addr)
    else:
        _mcp_log(f"RENAME FAILED 0x{addr:08X}: {old_name} -> {new_name}")
    return {"success": ok, "address": f"0x{addr:08X}", "name": new_name}


def add_comment(addr, comment, repeatable=False):
    """Add a comment at an address."""
    ctype = "repeatable" if repeatable else "regular"
    if repeatable:
        idc.set_cmt(addr, comment, 1)
    else:
        idc.set_cmt(addr, comment, 0)
    _mcp_log(f"COMMENT 0x{addr:08X} ({ctype}): {comment[:80]}", addr)
    return {"success": True, "address": f"0x{addr:08X}"}


def create_function_at(addr, end=None):
    """Force-create a function at an address."""
    end_str = f"-0x{end:08X}" if end else ""
    _mcp_log(f"CREATE FUNC 0x{addr:08X}{end_str} ...")
    if end:
        ok = ida_funcs.add_func(addr, end)
    else:
        ok = ida_funcs.add_func(addr)
    if ok:
        func = ida_funcs.get_func(addr)
        name = ida_name.get_name(addr) or f"sub_{addr:X}"
        size = func.size() if func else 0
        _mcp_log(f"CREATE FUNC 0x{addr:08X}: OK -> {name} ({size} bytes)", addr)
        return {
            "success": True,
            "address": f"0x{addr:08X}",
            "name": name,
            "size": size,
        }
    _mcp_log(f"CREATE FUNC 0x{addr:08X}: FAILED (may need make_code first)")
    return {"success": False, "address": f"0x{addr:08X}",
            "error": "add_func failed (may need make_code first)"}


def make_code_at(addr, size=0):
    """Force bytes at address to be analyzed as code."""
    _mcp_log(f"MAKE CODE 0x{addr:08X} size={size} ...")
    if size:
        ida_bytes.del_items(addr, 0, size)
        count = 0
        ea = addr
        end = addr + size
        while ea < end:
            length = idc.create_insn(ea)
            if length == 0:
                ea += 2
            else:
                ea += length
                count += 1
        _mcp_log(f"MAKE CODE 0x{addr:08X}: {count} instructions created", addr)
        return {"success": True, "address": f"0x{addr:08X}",
                "instructions": count}
    else:
        length = idc.create_insn(addr)
        _mcp_log(f"MAKE CODE 0x{addr:08X}: {'OK' if length else 'FAILED'} ({length} bytes)", addr if length else None)
        return {"success": length > 0, "address": f"0x{addr:08X}",
                "length": length}


def delete_function_at(addr):
    """Delete a function at an address."""
    name = ida_name.get_name(addr) or f"0x{addr:08X}"
    ok = ida_funcs.del_func(addr)
    if ok:
        _mcp_log(f"DELETE FUNC 0x{addr:08X} ({name})", addr)
    else:
        _mcp_log(f"DELETE FUNC 0x{addr:08X}: FAILED")
    return {"success": ok, "address": f"0x{addr:08X}"}


def find_micromips_prologues():
    """Scan for microMIPS 'save' instructions in data regions.

    The 'save' instruction starts with byte 0x64 in microMIPS16e
    or specific patterns. We look for the common prologue patterns
    that IDA missed.

    Returns addresses where unrecognized functions likely start.
    """
    results = []
    # Iterate all segments
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        # Only check executable segments
        if not (seg.perm & 1):  # X bit
            continue

        ea = seg.start_ea
        end = seg.end_ea

        while ea < end - 4:
            # Check if this is already code
            flags = ida_bytes.get_flags(ea)
            if ida_bytes.is_code(flags):
                ea += 2
                continue

            # Read 2 bytes
            b0 = ida_bytes.get_byte(ea)
            b1 = ida_bytes.get_byte(ea + 1)

            # microMIPS save16 encoding: first byte has specific patterns
            # save = 0x6464 pattern (SAVE16) or extended SAVE32
            # Common patterns seen:
            #   XX 64 = save16 (16-bit save instruction)
            #   XX 2C YY F1 = save32 (32-bit extended save)
            is_save = False

            # Check for save16: second byte = 0x64
            if b1 == 0x64:
                is_save = True

            # Check for save32: bytes [0] has low bits 0x05/0x25/etc,
            # byte[1] = 0x2C, and next halfword has F1 pattern
            if b1 == 0x2C and ea + 3 < end:
                b3 = ida_bytes.get_byte(ea + 3)
                if b3 == 0xF1:
                    is_save = True

            if is_save:
                # Verify this isn't already inside a function
                func = ida_funcs.get_func(ea)
                if not func:
                    results.append({
                        "address": f"0x{ea:08X}",
                        "bytes": ida_bytes.get_bytes(ea, 8).hex() if ida_bytes.get_bytes(ea, 8) else "",
                    })

            ea += 2

            if len(results) >= 500:
                break

    return results


def get_idb_info():
    """Get basic info about the loaded IDB."""
    func_count = sum(1 for _ in idautils.Functions())
    seg_count = sum(1 for _ in idautils.Segments())
    return {
        "file": _idb_name(),
        "path": _idb_path(),
        "functions": func_count,
        "segments": seg_count,
        "processor": ida_ida.inf_get_procname() if hasattr(ida_ida, 'inf_get_procname') else "unknown",
        "bits": 64 if ida_ida.inf_is_64bit() else 32,
    }


# ---------------------------------------------------------------------------
# Types / structs / function prototypes
# ---------------------------------------------------------------------------

def define_type(decl):
    """Parse one or more C declarations into the IDB type library.

    Accepts struct/union/typedef/function declarations. ``decl`` is a
    self-contained chunk of C source (multiple declarations allowed).
    Returns the count of parse errors (0 == full success).
    """
    if not decl:
        return {"success": False, "error": "Empty declaration"}

    flags = ida_typeinf.PT_FILE | ida_typeinf.PT_SIL
    errors = ida_typeinf.parse_decls(None, decl, None, flags)
    if errors:
        _mcp_log(f"DEFINE TYPE: {errors} parse error(s)")
        return {"success": False, "parse_errors": errors,
                "error": f"{errors} parsing error(s); check IDA Output window"}
    _mcp_log(f"DEFINE TYPE: parsed ({len(decl)} bytes)")
    return {"success": True, "size": len(decl)}


def apply_type_at(addr, type_decl):
    """Apply a type (struct, var, or function prototype) at an address.

    `type_decl` can be:
      - A named type:        ``"MyStruct"``         (wrapped into ``MyStruct x;``)
      - An inline var decl:  ``"unsigned int v;"``
      - A function proto:    ``"void __fastcall foo(int a, char *b);"``
    """
    decl = type_decl.strip()
    # If user passed a bare type name, wrap into a variable decl.
    if ';' not in decl and '(' not in decl:
        decl = f"{decl} x;"
    elif not decl.endswith(';'):
        decl += ';'

    ok = idc.SetType(addr, decl)
    if ok:
        _mcp_log(f"APPLY TYPE 0x{addr:08X}: {type_decl}", addr)
    else:
        _mcp_log(f"APPLY TYPE 0x{addr:08X}: FAILED for: {type_decl}")
    return {"success": bool(ok), "address": f"0x{addr:08X}", "type": type_decl}


def set_function_prototype_at(addr, proto):
    """Set a function's prototype (calling convention + return + args)."""
    decl = proto.strip()
    if not decl.endswith(';'):
        decl += ';'
    ok = idc.SetType(addr, decl)
    if ok:
        _mcp_log(f"SET PROTO 0x{addr:08X}: {proto}", addr)
    else:
        _mcp_log(f"SET PROTO 0x{addr:08X}: FAILED")
    return {"success": bool(ok), "address": f"0x{addr:08X}", "prototype": proto}


# ---------------------------------------------------------------------------
# Memory segments
# ---------------------------------------------------------------------------

def _perms_string_to_bits(s):
    """Map 'rwx' subset to IDA's segment.perm bitmask. R=4, W=2, X=1."""
    p = 0
    if 'r' in s.lower(): p |= 4
    if 'w' in s.lower(): p |= 2
    if 'x' in s.lower(): p |= 1
    return p


def add_segment_at(start, end, name, perms_str="rwx", sclass="DATA"):
    """Create a new memory segment.

    perms_str: 'r', 'w', 'x' subset (e.g. 'rw', 'rx', 'rwx').
    sclass:    'CODE' | 'DATA' | 'BSS' | 'XTRN' | 'CONST' | 'STACK'.
    """
    # add_segm_ex(start, end, base, use32, align, comb, flags)
    # use32=1 means 32-bit addressing IFF 64-bit base is irrelevant for x64;
    # ADDSEG_OR_DIE makes it fail loudly on overlap.
    ok = idc.add_segm_ex(start, end, 0, 1,
                         idc.saAbs, idc.scPub, idc.ADDSEG_OR_DIE)
    if not ok:
        _mcp_log(f"ADD SEGMENT 0x{start:08X}-0x{end:08X}: FAILED (overlap?)")
        return {"success": False,
                "error": "add_segm_ex failed (likely overlaps existing segment)"}

    seg = ida_segment.getseg(start)
    if not seg:
        return {"success": False, "error": "Segment created but not findable"}

    ida_segment.set_segm_name(seg, name)
    ida_segment.set_segm_class(seg, sclass)
    seg.perm = _perms_string_to_bits(perms_str)
    seg.update()

    _mcp_log(f"ADD SEGMENT 0x{start:08X}-0x{end:08X} ({name}, {perms_str}, {sclass})", start)
    return {"success": True, "start": f"0x{start:08X}", "end": f"0x{end:08X}",
            "name": name, "perms": perms_str, "class": sclass}


def set_segment_attrs_at(addr, name=None, perms_str=None, sclass=None):
    """Modify attributes of the segment containing addr."""
    seg = ida_segment.getseg(addr)
    if not seg:
        return {"success": False, "error": f"No segment at 0x{addr:08X}"}

    changes = []
    if name is not None and name != "":
        ida_segment.set_segm_name(seg, name)
        changes.append(f"name={name}")
    if perms_str is not None and perms_str != "":
        seg.perm = _perms_string_to_bits(perms_str)
        seg.update()
        changes.append(f"perms={perms_str}")
    if sclass is not None and sclass != "":
        ida_segment.set_segm_class(seg, sclass)
        changes.append(f"class={sclass}")

    if not changes:
        return {"success": False, "error": "Nothing to change (provide name/perms/class)"}

    _mcp_log(f"SET SEGMENT 0x{addr:08X}: {', '.join(changes)}", addr)
    return {"success": True, "address": f"0x{addr:08X}", "changes": changes}


# ---------------------------------------------------------------------------
# Debugger control
#
# IDA has a full in-tool debugger. Endpoints below cover process attach
# /detach/launch, run-state control (run/pause/continue/step), breakpoint
# management, memory + register R/W on the debuggee, and event polling.
#
# State machine: ida_dbg.get_process_state() returns one of
#   ida_dbg.DSTATE_NOTASK   — no debuggee
#   ida_dbg.DSTATE_RUN      — debuggee running
#   ida_dbg.DSTATE_SUSP     — debuggee suspended (paused)
#
# Read operations (memory, regs, callstack) auto-suspend a running
# debuggee, read, and resume. Write operations require explicit pause.
# ---------------------------------------------------------------------------

def _dbg_state_string():
    """Translate IDA's debugger state enum into a human-readable string."""
    try:
        s = ida_dbg.get_process_state()
    except Exception:
        return "unknown"
    if s == ida_dbg.DSTATE_NOTASK:
        return "detached"
    if s == ida_dbg.DSTATE_RUN:
        return "running"
    if s == ida_dbg.DSTATE_SUSP:
        return "paused"
    return f"state_{s}"


def dbg_state():
    """Return the current debugger state + active PID/thread if any."""
    state = _dbg_state_string()
    out = {"state": state}
    if state in ("running", "paused"):
        try:
            out["pid"] = idc.get_process_pid()
        except Exception:
            pass
        try:
            out["tid"] = idc.get_current_thread()
        except Exception:
            pass
        try:
            out["pc"] = f"0x{idc.get_reg_value('rip' if ida_ida.inf_is_64bit() else 'eip'):X}"
        except Exception:
            pass
    return out


def _require_paused():
    """For ops that need the debuggee paused; return None if OK else error dict."""
    s = _dbg_state_string()
    if s == "paused":
        return None
    if s == "detached":
        return {"error": "no active debuggee — call dbg_attach or dbg_launch first"}
    return {"error": f"debuggee is {s}; call dbg_pause first"}


def _refuse_if_debugging(endpoint_name):
    """Block mutating IDB ops while a debugger is attached.

    Mutating IDA's type library / function index / segment table while the
    debugger is paused at a BP can crash IDA — observed 2026-05-16 during
    a Saleae live-test (ida64.exe died, lost ~3 captured payloads). The
    main thread is in wait_for_next_event AND our timer is trying to
    drain mutation handlers AND those handlers want to re-enter Hex-Rays/
    typeinf machinery. Refuse cleanly instead.

    Detach first (dbg_detach), apply the annotations, then re-attach if
    you still need to continue debugging.
    """
    if _dbg_state_string() in ("paused", "running"):
        return {"error": f"{endpoint_name} blocked: debugger is "
                         f"{_dbg_state_string()}. Call dbg_detach first, "
                         f"apply the change, then re-attach if needed."}
    return None


def _auto_suspend_and_run(fn):
    """Auto-suspend the debuggee if running, call fn, resume if we suspended.

    Used for read-only operations (memory, regs, callstack, modules, threads)
    so callers don't have to pause manually for cheap reads.
    """
    s = _dbg_state_string()
    if s == "detached":
        return {"error": "no active debuggee"}
    resumed = False
    if s == "running":
        ida_dbg.suspend_process()
        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
        resumed = True
    try:
        return fn()
    finally:
        if resumed:
            ida_dbg.continue_process()


# ---- attach / launch / detach ----

def dbg_attach(pid):
    """Attach to a running process by PID."""
    if _dbg_state_string() != "detached":
        return {"error": f"already attached (state={_dbg_state_string()})"}
    _mcp_log(f"DBG ATTACH pid={pid}")
    ok = ida_dbg.attach_process(int(pid), -1)
    return {"success": int(ok) >= 0, "pid": int(pid), "state": _dbg_state_string()}


def dbg_launch(path, args=""):
    """Launch a new process under the debugger."""
    if _dbg_state_string() != "detached":
        return {"error": f"already attached (state={_dbg_state_string()})"}
    _mcp_log(f"DBG LAUNCH path={path} args={args}")
    ok = ida_dbg.start_process(path, args, "")
    return {"success": int(ok) >= 0, "path": path, "state": _dbg_state_string()}


def dbg_detach():
    """Detach from the current debuggee (leaves it running)."""
    if _dbg_state_string() == "detached":
        return {"error": "not attached"}
    _mcp_log("DBG DETACH")
    ok = ida_dbg.detach_process()
    return {"success": bool(ok), "state": _dbg_state_string()}


def dbg_terminate():
    """Kill the debuggee."""
    if _dbg_state_string() == "detached":
        return {"error": "not attached"}
    _mcp_log("DBG TERMINATE")
    ok = ida_dbg.exit_process()
    return {"success": bool(ok), "state": _dbg_state_string()}


# ---- run-state control ----

def dbg_run():
    """Continue execution (synonym for dbg_continue)."""
    return dbg_continue()


def dbg_pause():
    """Suspend the running debuggee."""
    if _dbg_state_string() != "running":
        return {"error": f"debuggee not running (state={_dbg_state_string()})"}
    _mcp_log("DBG PAUSE")
    ida_dbg.suspend_process()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
    return {"success": True, "state": _dbg_state_string()}


def dbg_continue():
    """Resume the paused debuggee."""
    err = _require_paused()
    if err: return err
    _mcp_log("DBG CONTINUE")
    ida_dbg.continue_process()
    return {"success": True, "state": _dbg_state_string()}


def dbg_step_into():
    """Single-step into. Returns the new PC."""
    err = _require_paused()
    if err: return err
    _mcp_log("DBG STEP INTO")
    ida_dbg.step_into()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
    return {"success": True, **dbg_state()}


def dbg_step_over():
    """Single-step over (treats call as one instruction). Returns new PC."""
    err = _require_paused()
    if err: return err
    _mcp_log("DBG STEP OVER")
    ida_dbg.step_over()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
    return {"success": True, **dbg_state()}


def dbg_step_out(timeout_s=30):
    """Step out of current function — same as 'run until return'."""
    err = _require_paused()
    if err: return err
    _mcp_log("DBG STEP OUT / RUN UNTIL RET")
    ida_dbg.step_until_ret()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, timeout_s)
    return {"success": True, **dbg_state()}


def dbg_run_to(addr, timeout_s=30):
    """Continue until the debuggee hits addr."""
    err = _require_paused()
    if err: return err
    _mcp_log(f"DBG RUN TO 0x{addr:X}")
    ida_dbg.run_to(addr)
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, timeout_s)
    return {"success": True, **dbg_state()}


# ---- breakpoints ----

_BPT_TYPES = {
    "sw":       0,  # software exec BP (int3)
    "hw_exec":  4,  # hardware exec
    "hw_write": 1,  # hardware write watch
    "hw_read":  3,  # hardware r/w watch
    "hw_rw":    3,  # alias
}


def dbg_set_breakpoint(addr, bp_type="sw", size=1):
    """Add a breakpoint. bp_type in {sw, hw_exec, hw_write, hw_read, hw_rw}."""
    t = _BPT_TYPES.get(bp_type, 0)
    # add_bpt(ea) for sw; add_bpt(ea, size, type) for hw watches
    if bp_type == "sw":
        ok = ida_dbg.add_bpt(addr)
    else:
        ok = ida_dbg.add_bpt(addr, size, t)
    if ok:
        _mcp_log(f"DBG BP+ 0x{addr:X} type={bp_type}", addr)
    else:
        _mcp_log(f"DBG BP+ 0x{addr:X} type={bp_type}: FAILED")
    return {"success": bool(ok), "address": f"0x{addr:X}", "type": bp_type}


def dbg_del_breakpoint(addr):
    """Remove the breakpoint at addr."""
    ok = ida_dbg.del_bpt(addr)
    _mcp_log(f"DBG BP- 0x{addr:X}: {'OK' if ok else 'FAILED'}")
    return {"success": bool(ok), "address": f"0x{addr:X}"}


def dbg_list_breakpoints():
    """Return all active breakpoints."""
    bpts = []
    n = ida_dbg.get_bpt_qty()
    for i in range(n):
        bpt = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, bpt):
            bpts.append({
                "address": f"0x{bpt.ea:X}",
                "size": bpt.size,
                "type": bpt.type,
                "enabled": bool(bpt.flags & ida_dbg.BPT_ENABLED),
            })
    return {"breakpoints": bpts}


# ---- memory + registers ----

def dbg_read_memory(addr, size):
    """Read live debuggee memory. Auto-pauses if running."""
    def _do():
        data = idc.read_dbg_memory(addr, min(size, 65536))
        if data is None:
            return {"error": f"read failed at 0x{addr:X}"}
        return {"address": f"0x{addr:X}", "size": len(data), "hex": data.hex()}
    return _auto_suspend_and_run(_do)


def dbg_write_memory(addr, hex_data):
    """Write live debuggee memory. Requires paused."""
    err = _require_paused()
    if err: return err
    try:
        data = bytes.fromhex(hex_data)
    except ValueError:
        return {"error": "hex must be a string of hex digits"}
    n = idc.write_dbg_memory(addr, data)
    _mcp_log(f"DBG WRITE 0x{addr:X} {len(data)} bytes -> {n} written", addr)
    return {"success": int(n) == len(data), "address": f"0x{addr:X}", "written": int(n)}


def dbg_get_reg(name):
    """Read a single register from the debuggee."""
    def _do():
        try:
            v = idc.get_reg_value(name)
            return {"name": name, "value": f"0x{v:X}"}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}"}
    return _auto_suspend_and_run(_do)


def dbg_set_reg(name, value):
    """Write a single register. Requires paused."""
    err = _require_paused()
    if err: return err
    idc.set_reg_value(value, name)
    _mcp_log(f"DBG SET REG {name} = 0x{value:X}")
    return {"success": True, "name": name, "value": f"0x{value:X}"}


def dbg_get_regs():
    """Return all GP registers of the current thread (auto-pauses)."""
    if ida_ida.inf_is_64bit():
        names = ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","rip",
                 "r8","r9","r10","r11","r12","r13","r14","r15","eflags"]
    else:
        names = ["eax","ebx","ecx","edx","esi","edi","ebp","esp","eip","eflags"]

    def _do():
        out = {}
        for n in names:
            try:
                out[n] = f"0x{idc.get_reg_value(n):X}"
            except Exception:
                out[n] = "?"
        return {"registers": out}
    return _auto_suspend_and_run(_do)


# ---- event poll ----

def dbg_wait_event(timeout_s=30):
    """Block until the next debug event (BP hit, exception, exit, ...).

    Returns {event, code, pc, message} describing what happened. Useful for
    'continue then wait for next BP'.
    """
    code = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP | ida_dbg.WFNE_NOWAIT,
                                       0) if timeout_s == 0 else \
           ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, timeout_s)
    out = {"event_code": int(code), "state": _dbg_state_string()}
    try:
        if _dbg_state_string() == "paused":
            out["pc"] = f"0x{idc.get_reg_value('rip' if ida_ida.inf_is_64bit() else 'eip'):X}"
    except Exception:
        pass
    return out


# ---- callstack / threads / modules ----

def dbg_callstack():
    """Return the current thread's call stack frames.

    Uses ida_dbg.collect_stacktrace which fills an ida_idd.call_stack_t
    container. Frames have .pc (instruction pointer) and .fp (frame pointer).
    """
    def _do():
        frames = []
        try:
            tid = idc.get_current_thread()
            trace = ida_idd.call_stack_t()
            ok = ida_dbg.collect_stacktrace(trace, tid)
            if not ok:
                return {"frames": [], "note": "collect_stacktrace returned False"}
            for i in range(trace.size()):
                frame = trace.at(i)
                frames.append({
                    "depth": i,
                    "pc": f"0x{frame.pc:X}",
                    "fp": f"0x{frame.fp:X}" if hasattr(frame, "fp") else "0",
                    "name": ida_name.get_name(frame.pc) or "",
                })
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}",
                    "frames": frames}  # whatever we collected before the error
        return {"frames": frames}
    return _auto_suspend_and_run(_do)


def dbg_threads():
    """List threads in the debuggee."""
    def _do():
        out = []
        n = idc.get_thread_qty()
        for i in range(n):
            tid = idc.getn_thread(i)
            out.append({"index": i, "tid": tid})
        return {"threads": out}
    return _auto_suspend_and_run(_do)


def dbg_modules():
    """List loaded modules of the debuggee (base, size, name).

    modinfo_t lives in ida_idd, not ida_dbg. get_first_module/get_next_module
    are on ida_dbg though.
    """
    def _do():
        out = []
        try:
            mod = ida_idd.modinfo_t()
            ok = ida_dbg.get_first_module(mod)
            while ok:
                out.append({
                    "name": mod.name,
                    "base": f"0x{mod.base:X}",
                    "size": mod.size,
                })
                ok = ida_dbg.get_next_module(mod)
        except Exception as e:
            return {"error": f"{type(e).__name__}: {e}", "modules": out}
        return {"modules": out}
    return _auto_suspend_and_run(_do)


# ---------------------------------------------------------------------------
# Hex-Rays local variable manipulation
#
# Naming + typing stack locals (v40, Buffer, etc. in pseudocode) gives the
# biggest readability win for re-decompiles in a debugging session — you can
# annotate state as you discover it.
# ---------------------------------------------------------------------------

def rename_local_var(func_addr, old_name, new_name):
    """Rename a Hex-Rays local variable in a function."""
    if not ida_hexrays.init_hexrays_plugin():
        return {"success": False, "error": "Hex-Rays not available"}
    ok = ida_hexrays.rename_lvar(func_addr, old_name, new_name)
    _mcp_log(f"LVAR RENAME 0x{func_addr:X} {old_name} -> {new_name}: "
             f"{'OK' if ok else 'FAILED'}", func_addr)
    return {"success": bool(ok), "function": f"0x{func_addr:X}",
            "old_name": old_name, "new_name": new_name}


def set_local_var_type(func_addr, var_name, type_decl):
    """Apply a C type to a Hex-Rays local variable."""
    if not ida_hexrays.init_hexrays_plugin():
        return {"success": False, "error": "Hex-Rays not available"}

    tif = ida_typeinf.tinfo_t()
    decl = type_decl.strip()
    if not decl.endswith(';'):
        decl = decl + ' x;'  # parse_decl wants a complete declaration
    parsed_name = ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL)
    if not tif.is_well_defined():
        return {"success": False, "error": f"could not parse type: {type_decl}"}

    ok = ida_hexrays.set_lvar_type(func_addr, var_name, tif)
    _mcp_log(f"LVAR TYPE 0x{func_addr:X} {var_name} = {type_decl}: "
             f"{'OK' if ok else 'FAILED'}", func_addr)
    return {"success": bool(ok), "function": f"0x{func_addr:X}",
            "name": var_name, "type": type_decl}


# ---------------------------------------------------------------------------
# Per-IDB scratch / lab notebook
#
# Persistent free-form markdown buffer stored in a named netnode inside the
# IDB ($ reversing_mcp_scratch). Auto-saved with the IDB, survives IDA
# restarts, accumulates discoveries across sessions. Use scratch_log to
# append a timestamped section — that's the most-common entry point.
# ---------------------------------------------------------------------------

_SCRATCH_NETNODE_NAME = "$ reversing_mcp_scratch"
_SCRATCH_TAG = ord('M')  # blob tag — "M" for MCP


def _scratch_node():
    """Get-or-create the netnode that stores the scratch markdown."""
    return ida_netnode.netnode(_SCRATCH_NETNODE_NAME, 0, True)


def scratch_read():
    """Return current scratch content as markdown text."""
    try:
        node = _scratch_node()
        data = node.getblob(0, _SCRATCH_TAG)
        if data is None:
            return {"content": "", "size": 0}
        if isinstance(data, bytes):
            text = data.decode("utf-8", errors="replace")
        else:
            text = str(data)
        return {"content": text, "size": len(text)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def scratch_replace(content):
    """Replace the entire scratch buffer."""
    try:
        node = _scratch_node()
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        node.setblob(data, 0, _SCRATCH_TAG)
        _mcp_log(f"SCRATCH REPLACE: {len(data)} bytes")
        return {"success": True, "size": len(data)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def scratch_append(text):
    """Append raw text to the scratch buffer."""
    current = scratch_read()
    if "error" in current:
        return current
    return scratch_replace(current["content"] + text)


def scratch_log(category, content):
    """Append a timestamped markdown section. The most-common entry point.

    Output format:

      ## [2026-05-16 14:32:08 UTC] {category}

      {content}
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    entry = f"\n\n## [{ts}] {category}\n\n{content}\n"
    return scratch_append(entry)


def scratch_clear():
    """Empty the scratch buffer entirely."""
    return scratch_replace("")


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

def _parse_addr(s):
    """Parse an address string (hex with optional 0x prefix)."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    try:
        return int(s, 16)
    except ValueError:
        return int(s)


class MCPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for IDA MCP queries."""

    def log_message(self, format, *args):
        # Suppress default logging
        pass

    def _respond(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def _error(self, msg, status=400):
        self._respond({"error": msg}, status)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/ping":
            self._respond({"status": "ok", "idb": _run_on_main_thread(_idb_name)})
            return

        try:
            if path == "/info":
                result = _run_on_main_thread(get_idb_info)
            elif path == "/segments":
                result = _run_on_main_thread(get_segments)
            else:
                self._error(f"Unknown endpoint: {path}", 404)
                return
            self._respond(result)
        except Exception as e:
            self._error(f"{type(e).__name__}: {e}", 500)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length > 0 else {}
        path = self.path.split("?")[0]

        try:
            result = _run_on_main_thread(self._dispatch, path, body)
            self._respond(result)
        except Exception as e:
            self._error(f"{type(e).__name__}: {e}", 500)

    # Endpoints that mutate the IDB. Guarded against running while
    # the debugger is engaged — those re-entries can crash IDA.
    _MUTATING = frozenset({
        "/rename", "/comment", "/create_function", "/delete_function",
        "/make_code", "/define_type", "/apply_type",
        "/set_function_prototype", "/add_segment", "/set_segment_attrs",
        "/rename_local_var", "/set_local_var_type",
        "/scratch_replace", "/scratch_append", "/scratch_log", "/scratch_clear",
    })

    def _dispatch(self, path, body):
        if path in self._MUTATING:
            blocked = _refuse_if_debugging(path)
            if blocked is not None:
                return blocked

        if path == "/function":
            addr_str = body.get("address")
            name = body.get("name")
            if addr_str:
                return get_function_at(_parse_addr(addr_str)) or {"error": "No function at address"}
            elif name:
                return get_function_by_name(name) or {"error": f"Function '{name}' not found"}
            return {"error": "Provide 'address' or 'name'"}

        elif path == "/disassemble":
            addr_str = body.get("address")
            name = body.get("name")
            start = body.get("start")
            end = body.get("end")
            if start and end:
                return {"lines": disassemble_range(_parse_addr(start), _parse_addr(end))}
            if name:
                func = get_function_by_name(name)
                if not func:
                    return {"error": f"Function '{name}' not found"}
                addr_str = f"0x{func['start']:X}"
            if addr_str:
                return disassemble_function(_parse_addr(addr_str)) or {"error": "No function at address"}
            return {"error": "Provide 'address', 'name', or 'start'+'end'"}

        elif path == "/decompile":
            addr_str = body.get("address")
            name = body.get("name")
            if name:
                func = get_function_by_name(name)
                if not func:
                    return {"error": f"Function '{name}' not found"}
                addr_str = f"0x{func['start']:X}"
            if addr_str:
                return decompile_function(_parse_addr(addr_str))
            return {"error": "Provide 'address' or 'name'"}

        elif path == "/xrefs_to":
            addr_str = body.get("address")
            name = body.get("name")
            if name:
                func = get_function_by_name(name)
                if not func:
                    return {"error": f"Function '{name}' not found"}
                addr_str = f"0x{func['start']:X}"
            if addr_str:
                return {"refs": get_xrefs_to(_parse_addr(addr_str))}
            return {"error": "Provide 'address' or 'name'"}

        elif path == "/xrefs_from":
            addr_str = body.get("address")
            if addr_str:
                return {"refs": get_xrefs_from(_parse_addr(addr_str))}
            return {"error": "Provide 'address'"}

        elif path == "/callers":
            addr_str = body.get("address")
            name = body.get("name")
            if name:
                func = get_function_by_name(name)
                if not func:
                    return {"error": f"Function '{name}' not found"}
                addr_str = f"0x{func['start']:X}"
            if addr_str:
                return {"callers": get_callers(_parse_addr(addr_str))}
            return {"error": "Provide 'address' or 'name'"}

        elif path == "/callees":
            addr_str = body.get("address")
            name = body.get("name")
            if name:
                func = get_function_by_name(name)
                if not func:
                    return {"error": f"Function '{name}' not found"}
                addr_str = f"0x{func['start']:X}"
            if addr_str:
                return {"callees": get_callees(_parse_addr(addr_str))}
            return {"error": "Provide 'address' or 'name'"}

        elif path == "/search_functions":
            pattern = body.get("pattern", "")
            if not pattern:
                return {"error": "Provide 'pattern'"}
            return {"functions": search_functions(pattern)}

        elif path == "/search_strings":
            pattern = body.get("pattern", "")
            if not pattern:
                return {"error": "Provide 'pattern'"}
            return {"strings": search_strings(pattern)}

        elif path == "/bytes":
            addr_str = body.get("address")
            size = body.get("size", 256)
            if addr_str:
                data = get_bytes_at(_parse_addr(addr_str), size)
                if data is None:
                    return {"error": "Cannot read bytes at address"}
                return {"address": addr_str, "size": size, "hex": data}
            return {"error": "Provide 'address'"}

        elif path == "/rename":
            addr_str = body.get("address")
            new_name = body.get("name")
            if addr_str and new_name:
                return rename_address(_parse_addr(addr_str), new_name)
            return {"error": "Provide 'address' and 'name'"}

        elif path == "/comment":
            addr_str = body.get("address")
            comment = body.get("comment", "")
            repeatable = body.get("repeatable", False)
            if addr_str:
                return add_comment(_parse_addr(addr_str), comment, repeatable)
            return {"error": "Provide 'address' and 'comment'"}

        elif path == "/create_function":
            addr_str = body.get("address")
            end_str = body.get("end")
            if addr_str:
                end = _parse_addr(end_str) if end_str else None
                return create_function_at(_parse_addr(addr_str), end)
            return {"error": "Provide 'address'"}

        elif path == "/delete_function":
            addr_str = body.get("address")
            if addr_str:
                return delete_function_at(_parse_addr(addr_str))
            return {"error": "Provide 'address'"}

        elif path == "/make_code":
            addr_str = body.get("address")
            size = body.get("size", 0)
            if addr_str:
                return make_code_at(_parse_addr(addr_str), size)
            return {"error": "Provide 'address'"}

        elif path == "/find_micromips_prologues":
            return {"prologues": find_micromips_prologues()}

        elif path == "/define_type":
            decl = body.get("decl", "")
            if not decl:
                return {"error": "Provide 'decl'"}
            return define_type(decl)

        elif path == "/apply_type":
            addr_str = body.get("address")
            type_decl = body.get("type")
            if addr_str and type_decl:
                return apply_type_at(_parse_addr(addr_str), type_decl)
            return {"error": "Provide 'address' and 'type'"}

        elif path == "/set_function_prototype":
            addr_str = body.get("address")
            proto = body.get("prototype")
            if addr_str and proto:
                return set_function_prototype_at(_parse_addr(addr_str), proto)
            return {"error": "Provide 'address' and 'prototype'"}

        elif path == "/add_segment":
            start_str = body.get("start")
            end_str = body.get("end")
            name = body.get("name", "")
            perms = body.get("perms", "rwx")
            sclass = body.get("class", "DATA")
            if start_str and end_str and name:
                return add_segment_at(_parse_addr(start_str),
                                      _parse_addr(end_str),
                                      name, perms, sclass)
            return {"error": "Provide 'start', 'end', and 'name'"}

        elif path == "/set_segment_attrs":
            addr_str = body.get("address")
            if addr_str:
                return set_segment_attrs_at(
                    _parse_addr(addr_str),
                    name=body.get("name"),
                    perms_str=body.get("perms"),
                    sclass=body.get("class"),
                )
            return {"error": "Provide 'address'"}

        # --------- Debugger control ---------

        elif path == "/dbg_state":
            return dbg_state()

        elif path == "/dbg_attach":
            pid = body.get("pid")
            if pid is None:
                return {"error": "Provide 'pid'"}
            return dbg_attach(int(pid))

        elif path == "/dbg_launch":
            p = body.get("path")
            if not p:
                return {"error": "Provide 'path'"}
            return dbg_launch(p, body.get("args", ""))

        elif path == "/dbg_detach":
            return dbg_detach()

        elif path == "/dbg_terminate":
            return dbg_terminate()

        elif path == "/dbg_run" or path == "/dbg_continue":
            return dbg_continue()

        elif path == "/dbg_pause":
            return dbg_pause()

        elif path == "/dbg_step_into":
            return dbg_step_into()

        elif path == "/dbg_step_over":
            return dbg_step_over()

        elif path == "/dbg_step_out" or path == "/dbg_run_until_ret":
            return dbg_step_out(int(body.get("timeout_s", 30)))

        elif path == "/dbg_run_to":
            addr_str = body.get("address")
            if not addr_str:
                return {"error": "Provide 'address'"}
            return dbg_run_to(_parse_addr(addr_str),
                              int(body.get("timeout_s", 30)))

        elif path == "/dbg_set_breakpoint":
            addr_str = body.get("address")
            if not addr_str:
                return {"error": "Provide 'address'"}
            return dbg_set_breakpoint(_parse_addr(addr_str),
                                      bp_type=body.get("type", "sw"),
                                      size=int(body.get("size", 1)))

        elif path == "/dbg_del_breakpoint":
            addr_str = body.get("address")
            if not addr_str:
                return {"error": "Provide 'address'"}
            return dbg_del_breakpoint(_parse_addr(addr_str))

        elif path == "/dbg_list_breakpoints":
            return dbg_list_breakpoints()

        elif path == "/dbg_read_memory":
            addr_str = body.get("address")
            size = int(body.get("size", 16))
            if not addr_str:
                return {"error": "Provide 'address'"}
            return dbg_read_memory(_parse_addr(addr_str), size)

        elif path == "/dbg_write_memory":
            addr_str = body.get("address")
            hex_data = body.get("hex", "")
            if not addr_str:
                return {"error": "Provide 'address' and 'hex'"}
            return dbg_write_memory(_parse_addr(addr_str), hex_data)

        elif path == "/dbg_get_reg":
            name = body.get("name")
            if not name:
                return {"error": "Provide 'name'"}
            return dbg_get_reg(name)

        elif path == "/dbg_set_reg":
            name = body.get("name")
            value = body.get("value")
            if not name or value is None:
                return {"error": "Provide 'name' and 'value'"}
            if isinstance(value, str):
                value = _parse_addr(value)
            return dbg_set_reg(name, int(value))

        elif path == "/dbg_get_regs":
            return dbg_get_regs()

        elif path == "/dbg_wait_event":
            return dbg_wait_event(int(body.get("timeout_s", 30)))

        elif path == "/dbg_callstack":
            return dbg_callstack()

        elif path == "/dbg_threads":
            return dbg_threads()

        elif path == "/dbg_modules":
            return dbg_modules()

        # --------- Hex-Rays local variables ---------

        elif path == "/rename_local_var":
            func_addr = body.get("function")
            old_name = body.get("old_name")
            new_name = body.get("new_name")
            if not (func_addr and old_name and new_name):
                return {"error": "Provide 'function', 'old_name', 'new_name'"}
            return rename_local_var(_parse_addr(func_addr), old_name, new_name)

        elif path == "/set_local_var_type":
            func_addr = body.get("function")
            var_name = body.get("name")
            type_decl = body.get("type")
            if not (func_addr and var_name and type_decl):
                return {"error": "Provide 'function', 'name', 'type'"}
            return set_local_var_type(_parse_addr(func_addr), var_name, type_decl)

        # --------- Scratch / lab-notebook ---------

        elif path == "/scratch_read":
            return scratch_read()

        elif path == "/scratch_replace":
            content = body.get("content", "")
            return scratch_replace(content)

        elif path == "/scratch_append":
            text = body.get("text", "")
            return scratch_append(text)

        elif path == "/scratch_log":
            category = body.get("category", "Note")
            content = body.get("content", "")
            return scratch_log(category, content)

        elif path == "/scratch_clear":
            return scratch_clear()

        else:
            return {"error": f"Unknown endpoint: {path}"}


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def _register(port):
    """Write registration file so the MCP server can discover us."""
    os.makedirs(REGISTRATION_DIR, exist_ok=True)
    pid = os.getpid()
    info = {
        "pid": pid,
        "port": port,
        "idb": _idb_name(),
        "idb_path": _idb_path(),
    }
    path = os.path.join(REGISTRATION_DIR, f"{pid}.json")
    with open(path, "w") as f:
        json.dump(info, f, indent=2)
    return path


def _unregister():
    """Remove registration file."""
    pid = os.getpid()
    path = os.path.join(REGISTRATION_DIR, f"{pid}.json")
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

_server = None
_thread = None
_reg_path = None


def start_server():
    """Start the HTTP server and main-thread timer."""
    global _server, _thread, _reg_path, _ui_timer

    if _server is not None:
        print(f"[MCP] Server already running on port {_server.server_port}")
        return

    # Start the UI timer that processes requests on the main thread
    _ui_timer = _MainThreadTimer(interval_ms=100)

    port = _find_free_port()
    _server = http.server.HTTPServer(("127.0.0.1", port), MCPHandler)
    _thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _thread.start()
    _reg_path = _register(port)

    print(f"[MCP] Server started on http://127.0.0.1:{port}")
    print(f"[MCP] IDB: {_idb_name()}")
    print(f"[MCP] Registration: {_reg_path}")


def stop_server():
    """Stop the HTTP server and main-thread timer."""
    global _server, _thread, _reg_path, _ui_timer

    if _ui_timer is not None:
        _ui_timer.stop()
        _ui_timer = None

    if _server is None:
        return

    _server.shutdown()
    _unregister()
    print(f"[MCP] Server stopped")
    _server = None
    _thread = None
    _reg_path = None


class IdaMcpPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "MCP server for Claude Code integration"
    help = "Starts an HTTP server for remote IDB queries"
    wanted_name = "IDA MCP Server"
    wanted_hotkey = "Ctrl-Shift-M"

    def init(self):
        # Don't auto-start in batch/headless mode — the server thread
        # prevents IDA from exiting after qexit(). Use Ctrl-Shift-M to
        # start manually in the GUI.
        if os.environ.get("IDA_HEADLESS"):
            return ida_idaapi.PLUGIN_KEEP
        start_server()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        if _server:
            stop_server()
        else:
            start_server()

    def term(self):
        stop_server()


def PLUGIN_ENTRY():
    return IdaMcpPlugin()


# If loaded via File > Script File (not as a plugin), start immediately
if __name__ == "__main__":
    start_server()
