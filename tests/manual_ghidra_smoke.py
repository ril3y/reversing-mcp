#!/usr/bin/env python3
"""
Manual smoke test for the Ghidra MCP HTTP bridge.

Reproduces the exec_script body-cache bug end-to-end by talking DIRECTLY to
the running plugin via httpx (no MCP / no python wrapper). Run this against
a live Ghidra instance with a program loaded after rebuilding/reinstalling
the plugin to verify the fix landed.

NOT a pytest test — exits non-zero on failure so it's CI-friendly if you
ever wire it up. Usage:

    # Start Ghidra, open any program (any platform), then:
    python tests/manual_ghidra_smoke.py
    python tests/manual_ghidra_smoke.py --port 13438  # if BASE_PORT taken

The plugin discovers a free port in [13437, 13500); the default here matches
the BASE_PORT constant in GhidraMcpPlugin.java. If your plugin landed on a
different port, pass --port. You can find the live port with:

    cat ~/.ghidra_mcp/*.json
"""

from __future__ import annotations

import argparse
import json
import sys

try:
    import httpx
except ImportError:
    print("ERROR: httpx not installed. `pip install httpx` and retry.",
          file=sys.stderr)
    sys.exit(2)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=13437,
                    help="Plugin port (default: 13437, the plugin's BASE_PORT)")
    ap.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()

    base = f"http://{args.host}:{args.port}"
    print(f"Targeting {base}")

    # Sanity ping
    try:
        r = httpx.get(f"{base}/ping", timeout=5)
    except httpx.ConnectError as e:
        print(f"FAIL: cannot reach {base}/ping — is Ghidra running with the "
              f"MCP plugin enabled and a program open? ({e})")
        return 2
    print(f"  /ping  -> {r.status_code} {r.text[:120]}")
    if r.status_code != 200:
        print("FAIL: /ping did not return 200")
        return 2

    # The actual regression test: two exec_scripts with different code
    # must return different stdout. Pre-fix, both returned the FIRST call's
    # stdout because parseJsonBody cached the body on the shared HttpContext.
    payload_a = {"code": 'print("FIRST_CALL_TOKEN_AAA")'}
    payload_b = {"code": 'print("SECOND_CALL_TOKEN_BBB")'}

    r1 = httpx.post(f"{base}/exec_script", json=payload_a, timeout=args.timeout)
    r2 = httpx.post(f"{base}/exec_script", json=payload_b, timeout=args.timeout)
    j1, j2 = r1.json(), r2.json()
    print(f"  /exec_script #1 -> {json.dumps(j1)[:200]}")
    print(f"  /exec_script #2 -> {json.dumps(j2)[:200]}")

    ok = True
    if not j1.get("success") or not j2.get("success"):
        print("FAIL: at least one exec_script returned success=false")
        ok = False
    if j1.get("stdout") == j2.get("stdout"):
        print("FAIL: both exec_script calls returned IDENTICAL stdout "
              "(parseJsonBody body-cache bug is still live)")
        ok = False
    else:
        assert "AAA" in (j1.get("stdout") or ""), \
            f"call 1 missing AAA token: {j1!r}"
        assert "BBB" in (j2.get("stdout") or ""), \
            f"call 2 missing BBB token: {j2!r}"
        print("  PASS: distinct stdout for distinct code")

    # Same shape for search_strings — needs DefinedData in the loaded program
    # so we just check that two patterns produce different result sets (which
    # would be the FIRST call's set on the buggy plugin).
    rs1 = httpx.post(f"{base}/search_strings", json={"pattern": "the"},
                     timeout=args.timeout).json()
    rs2 = httpx.post(f"{base}/search_strings", json={"pattern": "qqqqzzzz"},
                     timeout=args.timeout).json()
    print(f"  /search_strings 'the'      -> {len(rs1.get('strings', []))} hits")
    print(f"  /search_strings 'qqqqzzzz' -> {len(rs2.get('strings', []))} hits")
    if rs1 == rs2 and rs1.get("strings"):
        print("FAIL: search_strings returned identical sets for distinct "
              "patterns (body-cache bug live for search_strings)")
        ok = False
    elif rs1 != rs2:
        print("  PASS: distinct search_strings results for distinct patterns")
    else:
        print("  SKIP: both patterns returned empty — inconclusive "
              "(program may have no defined strings)")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
