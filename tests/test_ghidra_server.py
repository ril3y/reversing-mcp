"""
Tests for ghidra/mcp_server.py.

Mirrors the jadx/ilspy server test pattern: a FakeBridge stands in for the
running Ghidra HTTP plugin so we can assert the Python MCP layer (a) sends
the right body to the right endpoint and (b) returns the bridge's response
unmodified.

These tests target the SYMPTOMS of the parseJsonBody attribute-cache bug
that was reported (see GhidraMcpPlugin.java's threadBody javadoc):
  - Two consecutive exec_script calls with different code returned the same
    stdout, because the Java-side body cache was on the shared HttpContext
    instead of being per-request.
  - search_strings ignored the second pattern for the same reason.
  - decompile returned the first-call address's pseudocode for every
    subsequent call.

The FakeBridge here always echoes the request body back into a unique
response, so any cross-call leakage on the PYTHON side would show up as
duplicate responses. (The Java-side leak has been fixed in the plugin;
these tests pin the Python contract.)
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from conftest import FakeBridge, bridge_registered  # noqa: E402


def _load_module(name: str, path: str):
    """Load a module from an explicit file path, bypassing sys.path."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"could not load {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def ghidra_server(monkeypatch, reg_dir):
    """Import the ghidra MCP server with REG_DIR pointed at the tmp reg_dir."""
    srv = _load_module("ghidra_mcp_server",
                       os.path.join(ROOT, "ghidra", "mcp_server.py"))
    monkeypatch.setattr(srv, "REG_DIR", reg_dir)
    yield srv


def _unwrap(tool):
    """Pull the underlying function out of a FastMCP @tool() wrapper."""
    return getattr(tool, "fn", tool)


# ---------------------------------------------------------------------------
# Body forwarding — verify the python layer sends the right JSON per call.
# ---------------------------------------------------------------------------

def test_exec_script_sends_code_and_commit(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route(
        "/exec_script",
        lambda m, b: (200, {"success": True, "committed": True, "stdout": ""}),
    )
    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        _unwrap(ghidra_server.exec_script)(code='print("hi")')
    path, method, body = fake_bridge.calls[-1]
    assert path == "/exec_script" and method == "POST"
    assert body == {"code": 'print("hi")', "commit": "true"}


def test_exec_script_commit_false_serialised_as_string(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    # The MCP layer sends commit as the literal string "false"/"true" because
    # the Java parseJsonBody only handles flat string values.
    fake_bridge.route(
        "/exec_script",
        lambda m, b: (200, {"success": True, "committed": False, "stdout": ""}),
    )
    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        _unwrap(ghidra_server.exec_script)(code="pass", commit=False)
    _, _, body = fake_bridge.calls[-1]
    assert body == {"code": "pass", "commit": "false"}


def test_search_strings_sends_pattern(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/search_strings", lambda m, b: (200, {"strings": []}))
    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        _unwrap(ghidra_server.search_strings)(pattern="HTTP/1.1")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"pattern": "HTTP/1.1"}


def test_decompile_sends_address(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/decompile", lambda m, b: (200, {"pseudocode": "", "address": ""}))
    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        _unwrap(ghidra_server.decompile)(address="0x12345")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"address": "0x12345"}


def test_xrefs_to_sends_address(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/xrefs_to", lambda m, b: (200, {"refs": []}))
    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        _unwrap(ghidra_server.xrefs_to)(address="0xdeadbeef")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"address": "0xdeadbeef"}


def test_get_function_sends_name(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/function", lambda m, b: (200, {"name": "foo"}))
    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        _unwrap(ghidra_server.get_function)(name="memcpy")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"name": "memcpy"}


def test_get_bytes_sends_address_and_size(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/bytes", lambda m, b: (200, {"hex": "00"}))
    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        _unwrap(ghidra_server.get_bytes)(address="0x100", size=32)
    _, _, body = fake_bridge.calls[-1]
    assert body == {"address": "0x100", "size": 32}


# ---------------------------------------------------------------------------
# Distinct-response tests — these are the regression tests for the bug.
#
# The FakeBridge handler distinguishes responses by inspecting the request
# body. If the Python layer ever cached a request or response (or if a future
# refactor regresses), these tests catch it because two consecutive calls
# with different bodies would produce identical responses.
# ---------------------------------------------------------------------------

def test_exec_script_distinct_responses(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    """REGRESSION: two consecutive exec_script calls with different code
    must produce different stdout. On the broken Java plugin, both calls
    got the FIRST call's stdout — because parseJsonBody cached the body
    on the (shared) HttpContext attribute map. This test pins the contract
    that distinct bodies in → distinct responses out, end-to-end."""

    def handler(method, body):
        # Echo the code back into stdout — so distinct inputs give
        # provably-distinct outputs.
        code = body.get("code", "")
        return (200, {
            "success": True,
            "committed": True,
            "stdout": f"ECHO:{code}\n",
        })

    fake_bridge.route("/exec_script", handler)

    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        r1 = _unwrap(ghidra_server.exec_script)(code='print("FIRST_CALL_TOKEN_AAA")')
        r2 = _unwrap(ghidra_server.exec_script)(code='print("SECOND_CALL_TOKEN_BBB")')

    assert r1["stdout"] == 'ECHO:print("FIRST_CALL_TOKEN_AAA")\n'
    assert r2["stdout"] == 'ECHO:print("SECOND_CALL_TOKEN_BBB")\n'
    assert r1["stdout"] != r2["stdout"], \
        "exec_script must not echo the first call's stdout on the second call"

    # Both requests should have been received with distinct bodies.
    exec_calls = [(p, b) for (p, _, b) in fake_bridge.calls if p == "/exec_script"]
    assert len(exec_calls) == 2
    assert exec_calls[0][1]["code"] != exec_calls[1][1]["code"]


def test_search_strings_distinct_patterns(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    """REGRESSION: search_strings with different patterns must produce
    different results. The broken plugin returned the first pattern's
    hits for every subsequent call."""

    def handler(method, body):
        pattern = body.get("pattern", "")
        return (200, {"strings": [
            {"address": "0x1000", "value": f"matched:{pattern}", "length": 10}
        ]})

    fake_bridge.route("/search_strings", handler)

    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        r1 = _unwrap(ghidra_server.search_strings)(pattern="HTTP/1.1")
        r2 = _unwrap(ghidra_server.search_strings)(pattern="POST /api")

    assert r1["strings"][0]["value"] == "matched:HTTP/1.1"
    assert r2["strings"][0]["value"] == "matched:POST /api"
    assert r1 != r2


def test_decompile_distinct_addresses(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    """REGRESSION: decompile of two different addresses must return two
    different pseudocode payloads. The broken plugin returned the first
    address's function for every subsequent call."""

    def handler(method, body):
        addr = body.get("address", "")
        return (200, {
            "pseudocode": f"void func_{addr}() {{ /* ... */ }}",
            "address": addr,
        })

    fake_bridge.route("/decompile", handler)

    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        r1 = _unwrap(ghidra_server.decompile)(address="0x11111111")
        r2 = _unwrap(ghidra_server.decompile)(address="0x22222222")

    assert r1["address"] == "0x11111111"
    assert r2["address"] == "0x22222222"
    assert r1["pseudocode"] != r2["pseudocode"]


def test_xrefs_to_distinct_addresses(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    """REGRESSION: xrefs_to with different addresses must produce
    distinct ref sets."""

    def handler(method, body):
        addr = body.get("address", "")
        return (200, {"refs": [{"from": f"0xcaller_for_{addr}"}]})

    fake_bridge.route("/xrefs_to", handler)

    with bridge_registered(fake_bridge, reg_dir, name_key="program", name="x"):
        r1 = _unwrap(ghidra_server.xrefs_to)(address="0xdead0000")
        r2 = _unwrap(ghidra_server.xrefs_to)(address="0xbeef1111")

    assert r1["refs"][0]["from"] == "0xcaller_for_0xdead0000"
    assert r2["refs"][0]["from"] == "0xcaller_for_0xbeef1111"
    assert r1 != r2


# ---------------------------------------------------------------------------
# Instance resolution — same as ilspy/jadx test pattern.
# ---------------------------------------------------------------------------

def test_program_substring_resolves_correct_bridge(ghidra_server, fake_bridge: FakeBridge, reg_dir):
    """When ``program=...`` is passed, common.resolve_instance picks the
    matching registration by substring across ('program', 'program_path')."""
    import json as _json
    dead = os.path.join(reg_dir, "1.json")
    _json.dump({"pid": os.getpid(), "port": 1, "program": "dead.so",
                "program_path": "/tmp/dead.so"}, open(dead, "w"))
    live_path = os.path.join(reg_dir, f"{os.getpid()}.json")
    _json.dump({"pid": os.getpid(), "port": fake_bridge.port,
                "program": "live.so", "program_path": "/tmp/live.so"},
               open(live_path, "w"))

    fake_bridge.route("/info", lambda m, b: (200, {"program": "live.so"}))
    try:
        result = _unwrap(ghidra_server.idb_info)(program="live")
        assert result == {"program": "live.so"}
    finally:
        for p in (dead, live_path):
            try: os.unlink(p)
            except FileNotFoundError: pass


def test_no_instance_returns_error_dict(ghidra_server, reg_dir):
    # No registration files — every tool should return a structured error.
    result = _unwrap(ghidra_server.idb_info)()
    assert "error" in result
    assert "Ghidra" in result["error"]
