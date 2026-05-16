"""
Tests for unicorn/mcp_server.py.

Mirrors test_jadx_server.py: load the MCP server from its file path, point
REG_DIR at a tmp dir, register a FakeBridge, and assert the wire bodies.
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
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"could not load {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def unicorn_server(monkeypatch, reg_dir):
    srv = _load_module("unicorn_mcp_server",
                       os.path.join(ROOT, "unicorn", "mcp_server.py"))
    monkeypatch.setattr(srv, "REG_DIR", reg_dir)
    yield srv


def _unwrap(tool):
    return getattr(tool, "fn", tool)


def test_info_sends_get_to_info(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/info", lambda m, b: (200, {"arch": "thumb", "pc": "0x0"}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        result = _unwrap(unicorn_server.info)()
    assert result == {"arch": "thumb", "pc": "0x0"}
    paths = [p for (p, _, _) in fake_bridge.calls]
    assert paths == ["/info"]


def test_list_regions_sends_get(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/list_regions",
                      lambda m, b: (200, [{"start": "0x0", "size": "0x1000",
                                           "perms": "rwx"}]))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        result = _unwrap(unicorn_server.list_regions)()
    assert isinstance(result, list)
    path, method, _ = fake_bridge.calls[-1]
    assert path == "/list_regions" and method == "GET"


def test_map_region_passes_perms(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/map_region", lambda m, b: (200, {"ok": True}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.map_region)(start="0x10000000", size="0x400000",
                                           perms="rx")
    path, method, body = fake_bridge.calls[-1]
    assert path == "/map_region" and method == "POST"
    assert body == {"start": "0x10000000", "size": "0x400000", "perms": "rx"}


def test_step_default_count(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/step", lambda m, b: (200, {"pc": "0x4",
                                                   "instructions_run": 1}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.step)()
    _, _, body = fake_bridge.calls[-1]
    assert body == {"count": 1}


def test_step_explicit_count(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/step", lambda m, b: (200, {"pc": "0x8",
                                                   "instructions_run": 3}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.step)(count=3)
    _, _, body = fake_bridge.calls[-1]
    assert body == {"count": 3}


def test_run_until_includes_pc_when_given(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/run_until",
                      lambda m, b: (200, {"stopped_reason": "reached_pc",
                                          "pc": "0x100"}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.run_until)(pc="0x100", timeout_ms=500)
    _, _, body = fake_bridge.calls[-1]
    assert body == {"pc": "0x100", "max_instructions": 0, "timeout_ms": 500}


def test_run_until_omits_pc_when_blank(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/run_until",
                      lambda m, b: (200, {"stopped_reason": "timeout"}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.run_until)(max_instructions=100)
    _, _, body = fake_bridge.calls[-1]
    assert body == {"max_instructions": 100, "timeout_ms": 0}
    assert "pc" not in body


def test_add_hook_mem_read_stub(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/add_hook", lambda m, b: (200, {"id": 1}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.add_hook)(type="mem_read",
                                         range="0x40000000-0x80000000",
                                         action="stub",
                                         value="0xFFFFFFFF")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"type": "mem_read", "range": "0x40000000-0x80000000",
                    "action": "stub", "value": "0xFFFFFFFF"}


def test_add_hook_mem_write_trace(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/add_hook", lambda m, b: (200, {"id": 2}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.add_hook)(type="mem_write",
                                         range="0x20000000-0x20100000",
                                         action="trace")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"type": "mem_write", "range": "0x20000000-0x20100000",
                    "action": "trace"}
    assert "value" not in body
    assert "return_value" not in body


def test_add_hook_code_stub_with_return(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/add_hook", lambda m, b: (200, {"id": 3}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.add_hook)(type="code", range="0x1000",
                                         action="stub", return_value="0x0")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"type": "code", "range": "0x1000",
                    "action": "stub", "return_value": "0x0"}


def test_add_hook_code_break(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/add_hook", lambda m, b: (200, {"id": 4}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.add_hook)(type="code", range="0x2000",
                                         action="break")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"type": "code", "range": "0x2000", "action": "break"}


def test_add_hook_block_trace(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/add_hook", lambda m, b: (200, {"id": 5}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.add_hook)(type="block",
                                         range="0x0-0xFFFFFFFF",
                                         action="trace")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"type": "block", "range": "0x0-0xFFFFFFFF",
                    "action": "trace"}


def test_read_reg_passes_name_verbatim(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/read_reg",
                      lambda m, b: (200, {"name": b.get("name", "?"),
                                          "value": "0x7"}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        result = _unwrap(unicorn_server.read_reg)(name="r0")
    assert result == {"name": "r0", "value": "0x7"}
    _, _, body = fake_bridge.calls[-1]
    assert body == {"name": "r0"}


def test_write_reg_passes_name_and_value(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/write_reg", lambda m, b: (200, {"ok": True}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.write_reg)(name="pc", value="0x10000000")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"name": "pc", "value": "0x10000000"}


def test_snapshot_restore_pass_name(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/snapshot",
                      lambda m, b: (200, {"ok": True, "captured_bytes": 1024}))
    fake_bridge.route("/restore", lambda m, b: (200, {"ok": True}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.snapshot)(name="pre_boot")
        _unwrap(unicorn_server.restore)(name="pre_boot")
    snap_body = fake_bridge.calls[-2][2]
    rest_body = fake_bridge.calls[-1][2]
    assert snap_body == {"name": "pre_boot"}
    assert rest_body == {"name": "pre_boot"}


def test_disasm_passes_addr_and_size(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/disasm", lambda m, b: (200, {"insns": []}))
    with bridge_registered(fake_bridge, reg_dir, name_key="arch", name="thumb"):
        _unwrap(unicorn_server.disasm)(addr="0x100", size="0x20")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"addr": "0x100", "size": "0x20"}


def test_arch_substring_resolves_correct_bridge(unicorn_server, fake_bridge: FakeBridge, reg_dir):
    """Two registrations -- thumb (dead port) + x86_64 (live). Asking for arch='x86'
    must pick the live x86_64 one via substring match."""
    import json as _json
    # Use distinct PIDs that are still valid (our own).  The dead one has a
    # port nothing answers on; the live one points at fake_bridge.
    my_pid = os.getpid()
    dead = os.path.join(reg_dir, f"{my_pid - 1}.json")
    # We can't easily fake "live" pids that aren't our own without risking
    # collision; instead, mark the "dead" entry's PID == ours but port=1
    # (refused).  Discovery treats us as live.  resolve_instance prefers
    # the substring match regardless of order.
    _json.dump({"pid": my_pid, "port": 1, "arch": "thumb"},
               open(dead, "w"))
    live_path = os.path.join(reg_dir, f"{my_pid}.json")
    _json.dump({"pid": my_pid, "port": fake_bridge.port, "arch": "x86_64"},
               open(live_path, "w"))

    fake_bridge.route("/info", lambda m, b: (200, {"arch": "x86_64"}))
    try:
        result = _unwrap(unicorn_server.info)(arch="x86")
        assert result == {"arch": "x86_64"}
    finally:
        for p in (dead, live_path):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass
