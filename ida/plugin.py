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

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_ida
import ida_idaapi
import ida_kernwin
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
    """
    result = [None]
    error = [None]
    done = threading.Event()

    item = (func, args, kwargs, result, error, done)
    with _request_lock:
        _request_queue.append(item)

    # Wait for the main-thread timer to process our request
    done.wait()

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

        for func, args, kwargs, result, error, done in batch:
            try:
                result[0] = func(*args, **kwargs)
            except Exception as e:
                error[0] = e
            finally:
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

    def _dispatch(self, path, body):
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
