#!/usr/bin/env python3
"""
MCP server for Frida — dynamic instrumentation via the frida-python client lib.

Unlike the ida/ghidra/jadx/ilspy bridges in this repo, Frida doesn't need an
in-tool bridge: `frida-python` IS the client. The MCP server runs frida
directly and holds session/script state in-process across tool calls.

Layout per call:
    Claude Code  ←stdio→  frida/mcp_server.py  ←──→  frida-server on device
                              │                       (the actual hooks live here)
                          state: {session_id: Session,
                                  script_id: Script}

The "session" model from frida is preserved: you attach to (or spawn) a
process to get a Session, then `load_script` injects JS that lives inside
the target. The JS communicates back via `send(...)` calls which we
buffer per script and drain via `drain_messages`.

Usage:
    python frida/mcp_server.py              # stdio mode for Claude Code
    python frida/mcp_server.py --list       # print device + process inventory
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

# Allow imports from parent directory (matches the other MCP servers' style)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

try:
    import frida
except ImportError as e:
    sys.stderr.write(
        "frida-python not installed. Run `pip install frida frida-tools` "
        "(or `python install.py --tools frida`) and retry.\n"
    )
    raise


mcp = FastMCP("frida")


# ---------------------------------------------------------------------------
# In-process state — Frida Session and Script objects must outlive a single
# MCP call. Keyed by short opaque ids returned to the caller.
# ---------------------------------------------------------------------------

@dataclass
class SessionRecord:
    sid: str                          # opaque id we hand the caller
    session: "frida.core.Session"
    device_id: str
    target: str                       # name or PID we attached/spawned with
    pid: int


@dataclass
class ScriptRecord:
    rid: str                          # opaque id
    script: "frida.core.Script"
    session_id: str
    messages: deque                   # buffered (level, payload, data) tuples
    lock: threading.Lock = field(default_factory=threading.Lock)


SESSIONS: dict[str, SessionRecord] = {}
SCRIPTS: dict[str, ScriptRecord] = {}
STATE_LOCK = threading.Lock()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _get_device(device_id: str = "local"):
    """Resolve a device id to a frida.Device. 'local'/'usb'/'remote' are
    shortcuts for the built-in device kinds; any other value is treated as
    an explicit device id substring match."""
    mgr = frida.get_device_manager()
    if device_id == "local":
        return frida.get_local_device()
    if device_id == "usb":
        return frida.get_usb_device(timeout=5)
    if device_id == "remote":
        return frida.get_remote_device()
    # explicit id / id-substring
    for d in mgr.enumerate_devices():
        if device_id == d.id or device_id in (d.name or ""):
            return d
    raise ValueError(f"no device matches {device_id!r}")


def _require_session(session_id: str) -> SessionRecord:
    rec = SESSIONS.get(session_id)
    if rec is None:
        raise ValueError(f"no session {session_id!r} — call attach/spawn first")
    return rec


def _require_script(script_id: str) -> ScriptRecord:
    rec = SCRIPTS.get(script_id)
    if rec is None:
        raise ValueError(f"no script {script_id!r} — call load_script first")
    return rec


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_devices() -> list[dict]:
    """List Frida-reachable devices (local, USB-attached, remote frida-server)."""
    return [
        {"id": d.id, "name": d.name, "type": d.type}
        for d in frida.get_device_manager().enumerate_devices()
    ]


@mcp.tool()
def list_processes(device_id: str = "local", name_filter: str = "") -> list[dict]:
    """List processes on a device.

    Args:
        device_id: device shortcut ('local', 'usb', 'remote') or explicit id
        name_filter: substring filter on process name (case-insensitive)
    """
    dev = _get_device(device_id)
    procs = dev.enumerate_processes()
    flt = name_filter.lower()
    return [
        {"pid": p.pid, "name": p.name}
        for p in procs
        if not flt or flt in (p.name or "").lower()
    ]


@mcp.tool()
def list_applications(device_id: str = "usb") -> list[dict]:
    """List installed/running applications on a device (Android/iOS).

    Args:
        device_id: device shortcut or id; defaults to 'usb' since this is
                   typically used against an Android/iOS device.
    """
    dev = _get_device(device_id)
    apps = dev.enumerate_applications()
    return [
        {"identifier": a.identifier, "name": a.name, "pid": a.pid}
        for a in apps
    ]


@mcp.tool()
def attach(target: str, device_id: str = "local") -> dict:
    """Attach to an already-running process (no spawn). Returns session_id.

    Args:
        target: process name OR pid (as a string)
        device_id: device shortcut or id
    """
    dev = _get_device(device_id)
    pid: int
    try:
        pid = int(target)
    except ValueError:
        # name → resolve via enumerate_processes
        match = [p for p in dev.enumerate_processes() if p.name == target]
        if not match:
            raise ValueError(f"no process named {target!r} on {device_id}")
        pid = match[0].pid

    session = dev.attach(pid)
    sid = _new_id("sess")
    with STATE_LOCK:
        SESSIONS[sid] = SessionRecord(
            sid=sid, session=session, device_id=device_id, target=target, pid=pid,
        )
    return {"session_id": sid, "pid": pid}


@mcp.tool()
def spawn(program: str, device_id: str = "usb", argv: list[str] | None = None,
          envp: dict[str, str] | None = None) -> dict:
    """Spawn a program suspended (Android app identifier or absolute path).

    Returned session_id is ready to load_script into; the target is paused
    until you call `resume`. Useful when you need to instrument constructors
    that run before main().

    Args:
        program: app identifier (e.g. 'com.supercell.clashroyale') or path
        device_id: device shortcut or id
        argv: optional extra argv (Linux/macOS)
        envp: optional env vars as a dict (Linux/macOS)
    """
    dev = _get_device(device_id)
    spawn_kwargs: dict[str, Any] = {}
    if argv is not None:
        spawn_kwargs["argv"] = argv
    if envp is not None:
        spawn_kwargs["envp"] = envp
    pid = dev.spawn(program, **spawn_kwargs)
    session = dev.attach(pid)
    sid = _new_id("sess")
    with STATE_LOCK:
        SESSIONS[sid] = SessionRecord(
            sid=sid, session=session, device_id=device_id, target=program, pid=pid,
        )
    return {"session_id": sid, "pid": pid, "suspended": True}


@mcp.tool()
def resume(session_id: str) -> dict:
    """Resume a process that was spawn()-ed. No-op if already running."""
    rec = _require_session(session_id)
    dev = _get_device(rec.device_id)
    dev.resume(rec.pid)
    return {"resumed": rec.pid}


@mcp.tool()
def detach(session_id: str, kill: bool = False) -> dict:
    """Detach Frida from a session. Optionally kill the target.

    Args:
        session_id: which session to detach
        kill: if true, also terminate the target process
    """
    rec = _require_session(session_id)
    # Unload any scripts owned by this session
    for sid, sr in list(SCRIPTS.items()):
        if sr.session_id == session_id:
            try:
                sr.script.unload()
            except Exception:
                pass
            del SCRIPTS[sid]
    rec.session.detach()
    if kill:
        try:
            _get_device(rec.device_id).kill(rec.pid)
        except Exception:
            pass
    with STATE_LOCK:
        del SESSIONS[session_id]
    return {"detached": True, "killed": kill}


@mcp.tool()
def list_sessions() -> list[dict]:
    """List all active Frida sessions held by this MCP server."""
    return [
        {"session_id": s.sid, "device_id": s.device_id, "target": s.target, "pid": s.pid}
        for s in SESSIONS.values()
    ]


@mcp.tool()
def load_script(session_id: str, source: str, runtime: str = "qjs") -> dict:
    """Inject JavaScript into the target process.

    The script runs inside the target. Use `send(...)` from JS to push
    messages back; they're buffered server-side and read via `drain_messages`.

    Args:
        session_id: from a previous attach/spawn
        source: JavaScript source (Frida flavor — Interceptor/Module/NativePointer)
        runtime: 'qjs' (default, fast) or 'v8' (larger but more features)
    """
    rec = _require_session(session_id)
    script = rec.session.create_script(source, runtime=runtime)

    sr_id = _new_id("scr")
    sr = ScriptRecord(rid=sr_id, script=script, session_id=session_id,
                      messages=deque(maxlen=10_000))

    def _on_message(message, data):
        # message is a dict: {type: 'send'|'error', payload: ..., description?, stack?}
        with sr.lock:
            sr.messages.append({
                "type": message.get("type"),
                "payload": message.get("payload"),
                "data_hex": data.hex() if data else None,
                # If error, also surface description + stack
                **({"description": message.get("description"),
                    "stack": message.get("stack")}
                   if message.get("type") == "error" else {}),
            })

    script.on("message", _on_message)
    script.load()

    with STATE_LOCK:
        SCRIPTS[sr_id] = sr
    return {"script_id": sr_id}


@mcp.tool()
def unload_script(script_id: str) -> dict:
    """Unload a loaded Frida script (removes its hooks)."""
    sr = _require_script(script_id)
    try:
        sr.script.unload()
    finally:
        with STATE_LOCK:
            SCRIPTS.pop(script_id, None)
    return {"unloaded": True}


@mcp.tool()
def drain_messages(script_id: str, max_messages: int = 200) -> list[dict]:
    """Pop pending messages a Frida script has `send(...)`-ed back.

    Args:
        script_id: from load_script
        max_messages: cap on how many messages to return (default 200)
    """
    sr = _require_script(script_id)
    with sr.lock:
        out = []
        for _ in range(min(max_messages, len(sr.messages))):
            out.append(sr.messages.popleft())
    return out


@mcp.tool()
def call_rpc(script_id: str, method: str, args: list[Any] | None = None) -> Any:
    """Call a function exported by the script via `rpc.exports`.

    Inside the JS, declare exports like:
        rpc.exports = {
            readU32: (addr) => ptr(addr).readU32(),
            hookFoo: () => { ... },
        };
    Then from MCP: call_rpc(script_id, 'readU32', ['0x1234']).
    """
    sr = _require_script(script_id)
    fn = getattr(sr.script.exports, method, None)
    if fn is None:
        raise ValueError(f"script has no rpc.exports.{method!r}")
    return fn(*(args or []))


# ---- Convenience: canned scripts for the common cases ----------------------

_READ_MEMORY_JS = """
rpc.exports = {
  readBytes(addr, size) {
    const p = ptr(addr);
    return p.readByteArray(size);
  }
};
"""

_ENUM_MODULES_JS = """
rpc.exports = {
  enumModules() {
    return Process.enumerateModules().map(m => ({
      name: m.name, base: m.base.toString(), size: m.size, path: m.path,
    }));
  },
  enumExports(name) {
    const m = Process.findModuleByName(name);
    if (!m) return null;
    return m.enumerateExports().map(e => ({
      name: e.name, type: e.type, address: e.address.toString(),
    }));
  },
  enumImports(name) {
    const m = Process.findModuleByName(name);
    if (!m) return null;
    return m.enumerateImports().map(e => ({
      name: e.name, type: e.type, module: e.module,
      address: e.address ? e.address.toString() : null,
    }));
  },
  findExport(module, symbol) {
    const p = Module.findExportByName(module, symbol);
    return p ? p.toString() : null;
  },
};
"""


def _ensure_helper(session_id: str, key: str, src: str) -> ScriptRecord:
    """Load a canned helper script once per session, return its record."""
    # Look for an already-loaded helper with our marker
    for sr in SCRIPTS.values():
        if sr.session_id == session_id and getattr(sr, "_helper_key", None) == key:
            return sr
    rec = _require_session(session_id)
    script = rec.session.create_script(src, runtime="qjs")
    sr_id = _new_id("hlp")
    sr = ScriptRecord(rid=sr_id, script=script, session_id=session_id,
                      messages=deque(maxlen=1000))
    sr._helper_key = key  # type: ignore[attr-defined]
    script.on("message", lambda m, d: sr.messages.append({"type": m.get("type"), "payload": m.get("payload")}))
    script.load()
    with STATE_LOCK:
        SCRIPTS[sr_id] = sr
    return sr


@mcp.tool()
def enum_modules(session_id: str) -> list[dict]:
    """List loaded modules (shared libraries) in the target process."""
    sr = _ensure_helper(session_id, "enum", _ENUM_MODULES_JS)
    return sr.script.exports.enum_modules()


@mcp.tool()
def enum_exports(session_id: str, module: str) -> list[dict] | None:
    """List exported symbols from a loaded module.

    Args:
        session_id: from attach/spawn
        module: module name (e.g. 'libsupercell_clashroyale.so')
    """
    sr = _ensure_helper(session_id, "enum", _ENUM_MODULES_JS)
    return sr.script.exports.enum_exports(module)


@mcp.tool()
def enum_imports(session_id: str, module: str) -> list[dict] | None:
    """List imported symbols (with resolved addresses if available) from a module."""
    sr = _ensure_helper(session_id, "enum", _ENUM_MODULES_JS)
    return sr.script.exports.enum_imports(module)


@mcp.tool()
def find_export(session_id: str, module: str, symbol: str) -> str | None:
    """Resolve `module!symbol` → address (hex string). Returns null if not found.

    Args:
        session_id: from attach/spawn
        module: module name (or empty string to search all loaded modules)
        symbol: exported symbol name
    """
    sr = _ensure_helper(session_id, "enum", _ENUM_MODULES_JS)
    return sr.script.exports.find_export(module or None, symbol)


@mcp.tool()
def read_memory(session_id: str, address: str, size: int) -> dict:
    """Read raw bytes from the target process. Returns hex.

    Args:
        session_id: from attach/spawn
        address: hex address (e.g. '0x1234abcd')
        size: number of bytes (max 65536)
    """
    if size > 65536:
        raise ValueError("size capped at 65536")
    sr = _ensure_helper(session_id, "read_mem", _READ_MEMORY_JS)
    data = sr.script.exports.read_bytes(address, size)
    return {"address": address, "size": size, "hex": bytes(data).hex() if data else ""}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _list_inventory() -> None:
    """`--list`: print devices + key processes. For sanity-checking the host."""
    print("=== Frida devices ===")
    for d in frida.get_device_manager().enumerate_devices():
        print(f"  id={d.id!r:>15}  type={d.type!r:>10}  name={d.name!r}")

    # Best-effort: probe the most common device kinds
    for shortcut in ("local", "usb"):
        try:
            dev = _get_device(shortcut)
        except Exception as e:
            print(f"\n[{shortcut}] unreachable: {e}")
            continue
        print(f"\n[{shortcut}] ({dev.id} / {dev.name}) processes (first 30):")
        try:
            for p in dev.enumerate_processes()[:30]:
                print(f"  pid={p.pid:>6}  {p.name}")
        except Exception as e:
            print(f"  enumerate failed: {e}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print device + process inventory and exit")
    args = ap.parse_args()
    if args.list:
        _list_inventory()
        return
    mcp.run()


if __name__ == "__main__":
    main()
