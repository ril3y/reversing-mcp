"""
IDA headless runner — pass as -S to idat64 to keep the MCP server alive.

Usage:
    idat64.exe -A -Sheadless_runner.py target.exe
    idat64.exe -A -Sheadless_runner.py -L analysis.log target.exe

What it does:
  1. Waits for IDA's auto-analysis to finish (ida_auto.auto_wait).
  2. Loops with idc.sleep(100), which yields to IDA's internal event loop
     every 100 ms.  This lets execute_sync calls from the MCP plugin's HTTP
     handler thread run on the main thread without blocking the server.
  3. Exits cleanly on Ctrl+C or when IDA is asked to quit.

The MCP plugin starts automatically via the normal plugin init path.
If IDA_MCP_BIND=0.0.0.0 is set, the server listens on all interfaces.
After this script prints "MCP server ready", use --scan or list_instances()
from the MCP server on the other machine to find the port.
"""

import ida_auto
import idc

print("[MCP runner] Waiting for auto-analysis...")
ida_auto.auto_wait()
print("[MCP runner] Auto-analysis complete. MCP server ready.")
print("[MCP runner] Press Ctrl+C or close this window to stop.")

try:
    while True:
        # idc.sleep yields to IDA's internal event loop for N milliseconds,
        # allowing execute_sync calls queued by the MCP plugin to fire on the
        # main thread.  Do NOT use time.sleep here — that blocks the event loop
        # and freezes MCP request handling.
        idc.sleep(100)
except KeyboardInterrupt:
    print("[MCP runner] Stopped.")
