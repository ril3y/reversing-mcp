"""
Tests for jadx/mcp_server.py.

The FastMCP @mcp.tool() decorator wraps each function, but the original
remains callable.  We monkeypatch the module's REG_DIR to a tmp dir and
override ``_call`` to send requests at a per-test FakeBridge, then assert
the bridge saw the right endpoint and body.
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
def jadx_server(monkeypatch, reg_dir):
    """Import the jadx MCP server with REG_DIR pointed at the tmp reg_dir."""
    srv = _load_module("jadx_mcp_server",
                       os.path.join(ROOT, "jadx", "mcp_server.py"))
    monkeypatch.setattr(srv, "REG_DIR", reg_dir)
    yield srv


def _unwrap(tool):
    """Pull the underlying function out of a FastMCP @tool() wrapper."""
    # FastMCP wraps with a Tool object that exposes .fn for the original
    # callable.  Fall back to the wrapper itself if the attribute is absent.
    return getattr(tool, "fn", tool)


def test_info_sends_get_to_info(jadx_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/info", lambda m, b: (200, {"classes": 7, "methods": 42}))
    with bridge_registered(fake_bridge, reg_dir, name_key="jar", name="x.apk"):
        result = _unwrap(jadx_server.info)()
    assert result == {"classes": 7, "methods": 42}
    paths = [p for (p, _, _) in fake_bridge.calls]
    assert paths == ["/info"]


def test_list_classes_passes_prefix_and_limit(jadx_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/list_classes", lambda m, b: (200, {"classes": []}))
    with bridge_registered(fake_bridge, reg_dir, name_key="jar", name="x.apk"):
        _unwrap(jadx_server.list_classes)(prefix="com.foo", limit=50)
    path, method, body = fake_bridge.calls[-1]
    assert path == "/list_classes" and method == "POST"
    assert body == {"prefix": "com.foo", "limit": 50}


def test_decompile_class_sends_name(jadx_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/decompile_class", lambda m, b: (200, {"source": "// ..."}))
    with bridge_registered(fake_bridge, reg_dir, name_key="jar", name="x.apk"):
        result = _unwrap(jadx_server.decompile_class)(name="com.foo.Bar")
    assert result == {"source": "// ..."}
    _, _, body = fake_bridge.calls[-1]
    assert body == {"name": "com.foo.Bar"}


def test_decompile_method_sends_both_args(jadx_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/decompile_method", lambda m, b: (200, {"source": ""}))
    with bridge_registered(fake_bridge, reg_dir, name_key="jar", name="x.apk"):
        _unwrap(jadx_server.decompile_method)(class_name="com.foo.Bar", method="baz")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"class": "com.foo.Bar", "method": "baz"}


def test_xrefs_to_omits_method_when_blank(jadx_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/xrefs_to", lambda m, b: (200, {"refs": []}))
    with bridge_registered(fake_bridge, reg_dir, name_key="jar", name="x.apk"):
        _unwrap(jadx_server.xrefs_to)(class_name="com.foo.Bar")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"class": "com.foo.Bar"}
    assert "method" not in body


def test_xrefs_to_includes_method_when_given(jadx_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/xrefs_to", lambda m, b: (200, {"refs": []}))
    with bridge_registered(fake_bridge, reg_dir, name_key="jar", name="x.apk"):
        _unwrap(jadx_server.xrefs_to)(class_name="com.foo.Bar", method="baz")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"class": "com.foo.Bar", "method": "baz"}


def test_jar_substring_resolves_correct_bridge(jadx_server, fake_bridge: FakeBridge, reg_dir):
    """When ``jar=...`` is passed, common.resolve_instance picks the matching
    registration by substring across ('jar', 'jar_path')."""
    # Stand up two registrations.  Only the second points at our live bridge;
    # the first has a port that nothing answers on.  Targeting by jar name
    # must select the live one, not just "the first one we find".
    import json as _json
    dead = os.path.join(reg_dir, "1.json")
    _json.dump({"pid": os.getpid(), "port": 1, "jar": "dead.apk",
                "jar_path": "/tmp/dead.apk"}, open(dead, "w"))
    live_path = os.path.join(reg_dir, f"{os.getpid()}.json")
    _json.dump({"pid": os.getpid(), "port": fake_bridge.port,
                "jar": "live.apk", "jar_path": "/tmp/live.apk"},
               open(live_path, "w"))

    fake_bridge.route("/info", lambda m, b: (200, {"jar": "live.apk"}))
    try:
        result = _unwrap(jadx_server.info)(jar="live")
        assert result == {"jar": "live.apk"}
    finally:
        for p in (dead, live_path):
            try: os.unlink(p)
            except FileNotFoundError: pass
