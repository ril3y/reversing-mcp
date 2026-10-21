"""IDA headless lifecycle tests that do not require an IDA license."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def spawn_server():
    return _load_module("ida_spawn_server", ROOT / "ida" / "spawn_server.py")


def test_build_headless_create_command(spawn_server, tmp_path):
    source = tmp_path / "sample.exe"
    source.write_bytes(b"MZ")
    database = tmp_path / "analysis" / "sample.i64"

    command, operation, actual_database = spawn_server._build_ida_command(
        "idat64.exe",
        source_path=str(source),
        database_path=str(database),
        headless=True,
    )

    assert operation == "create"
    assert command[0:2] == ["idat64.exe", "-A"]
    assert any(arg.startswith("-S") for arg in command)
    assert f"-o{database.resolve()}" in command
    assert command[-1] == str(source.resolve())
    assert actual_database == str(database.resolve())


def test_build_headless_reopens_existing_database(spawn_server, tmp_path):
    database = tmp_path / "saved.i64"
    database.write_bytes(b"IDA")

    command, operation, actual_database = spawn_server._build_ida_command(
        "idat64.exe",
        database_path=str(database),
        headless=True,
    )

    assert operation == "reopen"
    assert command[-1] == str(database.resolve())
    assert not any(arg.startswith("-o") for arg in command)
    assert actual_database == str(database.resolve())


def test_default_database_is_reopened_instead_of_overwritten(spawn_server, tmp_path):
    source = tmp_path / "saved.exe"
    source.write_bytes(b"MZ")
    database = tmp_path / "saved.i64"
    database.write_bytes(b"IDA")

    command, operation, _actual_database = spawn_server._build_ida_command(
        "idat64.exe", source_path=str(source), headless=True
    )

    assert operation == "reopen"
    assert command[-1] == str(database.resolve())
    assert not any(arg.startswith("-o") for arg in command)


def test_headless_discovery_never_falls_back_to_gui(
    spawn_server, monkeypatch, tmp_path
):
    gui = tmp_path / "ida64.exe"
    gui.write_bytes(b"")
    missing_text = tmp_path / "idat64.exe"
    monkeypatch.delenv("IDA_PATH", raising=False)
    monkeypatch.setattr(
        spawn_server,
        "_CANDIDATE_PAIRS",
        [(str(gui), str(missing_text))],
    )

    assert spawn_server._find_ida(headless=True) is None
    assert spawn_server._find_ida(headless=False) == str(gui)


def test_spawn_passes_persistent_session_metadata(spawn_server, monkeypatch, tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"\x00")
    database = tmp_path / "sample.i64"
    captured = {}

    class Process:
        pid = 4242

    def fake_popen(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return Process()

    monkeypatch.setattr(spawn_server.subprocess, "Popen", fake_popen)
    result = spawn_server._spawn(
        "idat64.exe",
        source_path=str(source),
        database_path=str(database),
        headless=True,
        allow_python=True,
    )

    env = captured["kwargs"]["env"]
    assert env["IDA_MCP_MODE"] == "headless"
    assert env["IDA_MCP_BIND"] == "127.0.0.1"
    assert env["IDA_MCP_ALLOW_PYTHON"] == "1"
    assert env["IDA_HEADLESS"] == "1"
    assert env["IDA_MCP_DATABASE_PATH"] == str(database.resolve())
    assert result["session_id"] == "ida-4242"
    assert result["operation"] == "create"


def test_python_cannot_be_enabled_on_network_bind(spawn_server, tmp_path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"\x00")

    with pytest.raises(ValueError, match="loopback"):
        spawn_server._spawn(
            "idat64.exe",
            source_path=str(source),
            headless=True,
            bind_host="0.0.0.0",
            allow_python=True,
        )


def test_headless_runner_uses_supported_main_thread_request_pump():
    source = (ROOT / "ida" / "headless_runner.py").read_text(encoding="utf-8")

    assert "bridge.drain_headless_requests()" in source
    assert "idc.sleep(" not in source
