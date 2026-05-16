"""
Shared instance discovery and HTTP proxy for reversing tool MCP servers.

Each tool (IDA, Ghidra, Binary Ninja, ...) registers running instances
as JSON files in a tool-specific directory under ~/.<tool>_mcp/.
This module provides common logic for discovering, resolving, and
calling those instances over HTTP.
"""

import json
import os
import sys

import httpx


def _pid_alive(pid: int) -> bool:
    """Cross-platform PID liveness check that does NOT signal the process.

    On Windows we MUST NOT use ``os.kill(pid, 0)`` — depending on the Python
    build it routes through ``TerminateProcess`` and actually kills the target
    (CPython issue tracker has multiple reports, and this bug killed a running
    IDA Pro instance during development of this repo). Use ``OpenProcess`` with
    ``PROCESS_QUERY_LIMITED_INFORMATION`` — a strictly read-only right — then
    immediately close the handle.
    """
    if pid is None or pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    else:
        try:
            os.kill(int(pid), 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def discover_instances(reg_dir: str) -> list[dict]:
    """Read registration files from reg_dir and return live instances."""
    if not os.path.isdir(reg_dir):
        return []

    instances = []
    for fname in os.listdir(reg_dir):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(reg_dir, fname)
        try:
            with open(path) as f:
                info = json.load(f)
            pid = info.get("pid")
            if pid and not _pid_alive(pid):
                os.unlink(path)
                continue
            instances.append(info)
        except (json.JSONDecodeError, IOError):
            continue
    return instances


def resolve_instance(reg_dir: str, target: str | None = None,
                     name_keys: tuple[str, ...] = ("name", "path")) -> dict | None:
    """Find an instance, optionally matching by name substring."""
    instances = discover_instances(reg_dir)
    if not instances:
        return None
    if target:
        target_lower = target.lower()
        for inst in instances:
            for key in name_keys:
                if target_lower in inst.get(key, "").lower():
                    return inst
        return None
    return instances[0]


def call_instance(reg_dir: str, endpoint: str, body: dict | None = None,
                  target: str | None = None, tool_name: str = "tool",
                  name_keys: tuple[str, ...] = ("name", "path"),
                  timeout: int = 30) -> dict:
    """HTTP call to a discovered instance. Returns JSON dict."""
    inst = resolve_instance(reg_dir, target, name_keys)
    if not inst:
        available = discover_instances(reg_dir)
        if not available:
            return {"error": f"No {tool_name} instances found."}
        names = [i.get(name_keys[0], "?") for i in available]
        return {"error": f"No {tool_name} instance matches '{target}'. Available: {names}"}

    port = inst["port"]
    url = f"http://127.0.0.1:{port}{endpoint}"
    try:
        if body is not None:
            r = httpx.post(url, json=body, timeout=timeout)
        else:
            r = httpx.get(url, timeout=timeout)
        return r.json()
    except httpx.ConnectError:
        pid = inst.get("pid")
        if pid:
            reg = os.path.join(reg_dir, f"{pid}.json")
            try:
                os.unlink(reg)
            except FileNotFoundError:
                pass
        return {"error": f"{tool_name} instance (port {port}) not responding."}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def list_instances_text(reg_dir: str, tool_name: str,
                        name_key: str = "name") -> str:
    """Format instance list as human-readable text."""
    instances = discover_instances(reg_dir)
    if not instances:
        return f"No active {tool_name} instances."
    lines = []
    for inst in instances:
        lines.append(f"  port:{inst['port']}  pid:{inst.get('pid','?')}  {name_key}:{inst.get(name_key,'?')}")
    return f"{len(instances)} active {tool_name} instance(s):\n" + "\n".join(lines)
