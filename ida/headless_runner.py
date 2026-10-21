"""
IDA headless runner — pass as -S to idat64 to keep the MCP server alive.

Usage:
    idat64.exe -A -Sheadless_runner.py target.exe
    idat64.exe -A -Sheadless_runner.py -L analysis.log target.exe

What it does:
  1. Waits for IDA's auto-analysis to finish (ida_auto.auto_wait).
  2. Pumps the MCP request queue on IDA's main thread, then briefly sleeps.
  3. Exits cleanly on Ctrl+C or when IDA is asked to quit.

The MCP plugin starts automatically via the normal plugin init path.
If IDA_MCP_BIND=0.0.0.0 is set, the server listens on all interfaces.
After this script prints "MCP server ready", use --scan or list_instances()
from the MCP server on the other machine to find the port.
"""

import importlib.util
import os
import sys
import time

import ida_auto
import idc


def _load_bridge():
    """Load the installed plugin, falling back to the sibling source file."""
    try:
        import ida_mcp_plugin

        return ida_mcp_plugin
    except ImportError:
        plugin_path = os.path.join(os.path.dirname(__file__), "plugin.py")
        spec = importlib.util.spec_from_file_location("ida_mcp_plugin", plugin_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Cannot load IDA MCP plugin from {plugin_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module


print("[MCP runner] Waiting for auto-analysis...")
ida_auto.auto_wait()

try:
    bridge = _load_bridge()
    bridge.start_server()
except Exception as exc:
    print(f"[MCP runner] Could not start bridge: {type(exc).__name__}: {exc}")
    idc.qexit(1)
    raise

print("[MCP runner] Auto-analysis complete. MCP server ready.")
print("[MCP runner] Use close_session(save=True) for a clean shutdown.")

try:
    while True:
        bridge.drain_headless_requests()
        time.sleep(0.05)
except KeyboardInterrupt:
    print("[MCP runner] Interrupted; leaving shutdown to IDA.")
