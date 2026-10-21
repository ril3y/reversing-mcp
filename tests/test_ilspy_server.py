"""Focused tests for the unified, read-only ILSpy provider."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from reversing_mcp.errors import ReversingMcpError
from reversing_mcp.models import LifecycleAction, SessionRequest
from reversing_mcp.providers import ilspy


def run(coroutine):
    return asyncio.run(coroutine)


def test_ilspy_session_translates_canonical_operations_to_bridge_shapes(monkeypatch):
    calls = []

    def fake_call(remote, endpoint, body=None, timeout=30):
        calls.append((remote, endpoint, body, timeout))
        return {"success": True, "body": body}

    monkeypatch.setattr(ilspy, "call_remote", fake_call)
    session = ilspy.IlspySession(
        {"port": 13637, "assembly_path": "sample.dll"},
        process=SimpleNamespace(pid=42),
        owned=True,
    )

    run(session.invoke("target.info", {}))
    run(session.invoke("managed.types.list", {"prefix": "System", "limit": 10}))
    run(
        session.invoke(
            "managed.methods.decompile",
            {"type_name": "System.String", "method": "Concat"},
        )
    )
    run(session.invoke("search.strings", {"query": "GET /", "limit": 25}))

    assert calls[0][1:3] == ("/info", None)
    assert calls[1][1:3] == (
        "/list_types",
        {"prefix": "System", "limit": 10},
    )
    assert calls[2][1:3] == (
        "/decompile_method",
        {"type": "System.String", "method": "Concat"},
    )
    assert calls[3][1:3] == (
        "/search_strings",
        {"pattern": "GET /", "limit": 25},
    )


def test_ilspy_backend_opens_owned_bridge(monkeypatch, tmp_path):
    assembly = tmp_path / "sample.dll"
    assembly.write_bytes(b"MZ")
    process = SimpleNamespace(pid=99)

    def fake_launch(path, *, options):
        assert path == str(assembly)
        assert options["timeout"] == 7
        return process, {
            "pid": 99,
            "port": 13637,
            "assembly": assembly.name,
            "assembly_path": str(assembly),
        }

    monkeypatch.setattr(ilspy, "_launch_bridge", fake_launch)
    session = run(
        ilspy.IlspyBackend().open(
            SessionRequest(
                lifecycle=LifecycleAction.OPEN,
                target_path=str(assembly),
                options={"timeout": 7},
            )
        )
    )

    assert session.target_path == str(assembly)
    assert session.mode == "headless"
    assert "lifecycle.save" not in session.capabilities
    assert "lifecycle.close" in session.capabilities


def test_ilspy_owned_close_terminates_only_its_bridge(monkeypatch, tmp_path):
    class Process:
        pid = 77

        def __init__(self):
            self.terminated = False

        def poll(self):
            return None if not self.terminated else 0

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            assert timeout == 5
            return 0

    monkeypatch.setattr(ilspy, "REGISTRATION_DIR", str(tmp_path))
    registration = tmp_path / "77.json"
    registration.write_text("{}", encoding="utf-8")
    process = Process()
    session = ilspy.IlspySession(
        {"port": 13637, "assembly_path": "sample.dll"},
        process=process,
        owned=True,
    )

    result = run(session.close())

    assert process.terminated
    assert not registration.exists()
    assert result == {"closed": True, "pid": 77, "saved": False}


def test_ilspy_save_remains_explicitly_unsupported():
    session = ilspy.IlspySession(
        {"port": 13637, "assembly_path": "sample.dll"},
        process=SimpleNamespace(pid=1),
        owned=True,
    )

    with pytest.raises(ReversingMcpError) as raised:
        run(session.save())

    assert raised.value.code == "unsupported_capability"
