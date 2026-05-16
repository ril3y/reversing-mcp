"""
Tests for ilspy/mcp_server.py — same shape as the jadx tests.
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
def ilspy_server(monkeypatch, reg_dir):
    srv = _load_module("ilspy_mcp_server",
                       os.path.join(ROOT, "ilspy", "mcp_server.py"))
    monkeypatch.setattr(srv, "REG_DIR", reg_dir)
    yield srv


def _unwrap(tool):
    return getattr(tool, "fn", tool)


def test_info_returns_bridge_payload(ilspy_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/info", lambda m, b: (200, {"types": 7, "methods": 42}))
    with bridge_registered(fake_bridge, reg_dir, name_key="assembly", name="x.dll"):
        assert _unwrap(ilspy_server.info)() == {"types": 7, "methods": 42}


def test_list_types_passes_prefix_and_limit(ilspy_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/list_types", lambda m, b: (200, {"types": []}))
    with bridge_registered(fake_bridge, reg_dir, name_key="assembly", name="x.dll"):
        _unwrap(ilspy_server.list_types)(prefix="System.Collections", limit=10)
    path, method, body = fake_bridge.calls[-1]
    assert path == "/list_types" and method == "POST"
    assert body == {"prefix": "System.Collections", "limit": 10}


def test_decompile_type_sends_name(ilspy_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/decompile_type", lambda m, b: (200, {"source": ""}))
    with bridge_registered(fake_bridge, reg_dir, name_key="assembly", name="x.dll"):
        _unwrap(ilspy_server.decompile_type)(name="System.String")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"name": "System.String"}


def test_decompile_method_sends_type_and_method(ilspy_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/decompile_method", lambda m, b: (200, {"source": ""}))
    with bridge_registered(fake_bridge, reg_dir, name_key="assembly", name="x.dll"):
        _unwrap(ilspy_server.decompile_method)(type_name="System.String", method="Concat")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"type": "System.String", "method": "Concat"}


def test_get_il_sends_type_and_method(ilspy_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/get_il", lambda m, b: (200, {"il": ""}))
    with bridge_registered(fake_bridge, reg_dir, name_key="assembly", name="x.dll"):
        _unwrap(ilspy_server.get_il)(type_name="System.String", method="Concat")
    _, _, body = fake_bridge.calls[-1]
    assert body == {"type": "System.String", "method": "Concat"}


def test_search_strings_passes_limit(ilspy_server, fake_bridge: FakeBridge, reg_dir):
    fake_bridge.route("/search_strings", lambda m, b: (200, {"hits": []}))
    with bridge_registered(fake_bridge, reg_dir, name_key="assembly", name="x.dll"):
        _unwrap(ilspy_server.search_strings)(pattern="GET /", limit=25)
    _, _, body = fake_bridge.calls[-1]
    assert body == {"pattern": "GET /", "limit": 25}


def test_assembly_substring_resolves_correct_bridge(ilspy_server, fake_bridge: FakeBridge, reg_dir):
    import json as _json
    dead = os.path.join(reg_dir, "1.json")
    _json.dump({"pid": os.getpid(), "port": 1, "assembly": "dead.dll",
                "assembly_path": "/tmp/dead.dll"}, open(dead, "w"))
    live_path = os.path.join(reg_dir, f"{os.getpid()}.json")
    _json.dump({"pid": os.getpid(), "port": fake_bridge.port,
                "assembly": "live.dll", "assembly_path": "/tmp/live.dll"},
               open(live_path, "w"))

    fake_bridge.route("/info", lambda m, b: (200, {"assembly": "live.dll"}))
    try:
        result = _unwrap(ilspy_server.info)(assembly="live")
        assert result == {"assembly": "live.dll"}
    finally:
        for p in (dead, live_path):
            try: os.unlink(p)
            except FileNotFoundError: pass
