from __future__ import annotations

import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from reversing_mcp.errors import ReversingMcpError
from reversing_mcp.models import LifecycleAction, SessionRequest
from reversing_mcp.providers import (
    binary_ninja,
    builtin_backends,
    local_bridges,
    radare2,
)


def run(coroutine):
    return asyncio.run(coroutine)


class FakeBinaryView:
    def __init__(self, filename: str) -> None:
        self.file = SimpleNamespace(filename=filename, close=self._close)
        self.platform = "windows-x86_64"
        self.arch = "x86_64"
        self.entry_point = 0x1000
        self.functions = []
        self.strings = []
        self.closed = False
        self.database = ""
        self.snapshots = 0

    def __len__(self) -> int:
        return 4

    def _close(self) -> None:
        self.closed = True

    def update_analysis_and_wait(self) -> None:
        pass

    def create_database(self, path: str) -> bool:
        self.database = path
        return True

    def save_auto_snapshot(self) -> bool:
        self.snapshots += 1
        return True

    def read(self, address: int, size: int) -> bytes:
        del address
        return b"\x7fELF"[:size]


def test_binary_ninja_create_invoke_save_and_close(tmp_path, monkeypatch):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"\x7fELF")
    database = tmp_path / "sample.bndb"
    view = FakeBinaryView(str(target))
    sdk = SimpleNamespace(load=lambda path: view)
    monkeypatch.setattr(binary_ninja.importlib, "import_module", lambda name: sdk)

    session = run(
        binary_ninja.BinaryNinjaBackend().open(
            SessionRequest(
                lifecycle=LifecycleAction.CREATE,
                target_path=str(target),
                database_path=str(database),
            )
        )
    )
    info = run(session.invoke("target.info", {}))
    memory = run(session.invoke("memory.read", {"address": "0x1000", "size": 4}))
    saved = run(session.save())
    closed = run(session.close(save=False))

    assert info["architecture"] == "x86_64"
    assert memory["bytes"] == "7f454c46"
    assert saved == {"saved": True, "database_path": str(database.resolve())}
    assert view.snapshots == 1
    assert closed == {"closed": True, "saved": False}
    assert view.closed


def test_binary_ninja_reports_missing_sdk(monkeypatch):
    def missing(name: str):
        raise ImportError(name)

    monkeypatch.setattr(binary_ninja.importlib, "import_module", missing)
    with pytest.raises(ReversingMcpError) as raised:
        run(
            binary_ninja.BinaryNinjaBackend().open(
                SessionRequest(lifecycle=LifecycleAction.OPEN, target_path="missing")
            )
        )
    assert raised.value.code == "dependency_missing"


class FakeR2Pipe:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.closed = False

    def cmd(self, command: str) -> str:
        self.commands.append(command)
        return ""

    def cmdj(self, command: str):
        self.commands.append(command)
        if command == "ij":
            return {"bin": {"arch": "x86"}}
        if command == "aflj":
            return [{"offset": 0x1000, "name": "entry0"}]
        if command.startswith("pxj"):
            return [0x41, 0x42]
        return []

    def quit(self) -> None:
        self.closed = True


def test_radare2_create_mutate_save_script_and_close(tmp_path, monkeypatch):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"AB")
    pipe = FakeR2Pipe()
    sdk = SimpleNamespace(open=lambda target, flags: pipe)
    monkeypatch.setattr(radare2.importlib, "import_module", lambda name: sdk)

    session = run(
        radare2.Radare2Backend().open(
            SessionRequest(
                lifecycle=LifecycleAction.CREATE,
                target_path=str(target),
                database_path="sample-project",
            )
        )
    )
    assert run(session.invoke("target.info", {}))["bin"]["arch"] == "x86"
    assert (
        run(session.invoke("memory.read", {"address": 0, "size": 2}))["bytes"] == "4142"
    )
    renamed = run(
        session.invoke("symbols.rename", {"function": 0x1000, "name": "main"})
    )
    script = run(
        session.run_script(
            language="python",
            source='result = r2.cmdj("ij")["bin"]["arch"]',
            arguments={},
        )
    )
    run(session.save())
    run(session.close(save=False))

    assert renamed == {"address": 0x1000, "name": "main"}
    assert script == {"result": "x86"}
    assert "aaa" in pipe.commands
    assert pipe.commands.count("Ps sample-project") == 2
    assert "afn main @ 4096" in pipe.commands
    assert pipe.closed


def test_radare2_rejects_unsafe_project_name():
    with pytest.raises(ReversingMcpError) as raised:
        radare2._project_name("project;rm")
    assert raised.value.code == "invalid_project_name"


def test_all_provider_families_are_registered_without_native_sdks():
    assert {backend.provider_id for backend in builtin_backends()} == {
        "binary_ninja",
        "bluetooth_le",
        "capstone",
        "frida",
        "ghidra",
        "ida",
        "ilspy",
        "jadx",
        "protocol",
        "radare2",
    }


def test_ida_bridge_uses_canonical_translation_and_lifecycle(monkeypatch):
    calls = []

    def fake_call(remote, endpoint, body=None, timeout=10):
        calls.append((remote, endpoint, body, timeout))
        return {"success": True, "endpoint": endpoint, "body": body}

    monkeypatch.setattr(local_bridges, "call_remote", fake_call)
    session = local_bridges.IdaSession(
        provider_id="ida",
        registration={"port": 13337, "mode": "headless"},
        target_path="sample.exe",
        database_path="sample.i64",
        capabilities=local_bridges.IDA_CAPABILITIES,
        operations=local_bridges.IDA_OPERATIONS,
        endpoint_map=local_bridges._IDA_ENDPOINTS,
        owned=True,
    )

    run(
        session.invoke(
            "target.info",
            {},
        )
    )
    run(
        session.invoke(
            "comments.write",
            {"address": "0x401000", "comment": "entry point"},
        )
    )
    run(
        session.run_script(
            language="python", source="_result = 42", arguments={"answer": 42}
        )
    )
    run(session.save())
    run(session.close(save=False))

    assert calls[0][1:3] == ("/info", None)
    assert calls[1][1:3] == (
        "/comment",
        {"address": "0x401000", "comment": "entry point", "repeatable": False},
    )
    assert calls[2][1] == "/execute_python"
    assert "arguments" not in calls[2][2]
    assert "args = __ida_mcp_json.loads('{\"answer\":42}')" in calls[2][2]["code"]
    assert calls[3][1] == "/save_database"
    assert calls[4][1:3] == ("/close_session", {"save": False})


def test_ida_local_variable_and_notebook_translation_preserve_bridge_shapes(
    monkeypatch,
):
    calls = []

    def fake_call(remote, endpoint, body=None, timeout=10):
        calls.append((remote, endpoint, body, timeout))
        return {"success": True}

    monkeypatch.setattr(local_bridges, "call_remote", fake_call)
    session = local_bridges.IdaSession(
        provider_id="ida",
        registration={"port": 13337, "mode": "headless"},
        target_path="sample.exe",
        database_path="sample.i64",
        capabilities=local_bridges.IDA_CAPABILITIES,
        operations=local_bridges.IDA_OPERATIONS,
        endpoint_map=local_bridges._IDA_ENDPOINTS,
        owned=True,
    )

    run(
        session.invoke(
            "locals.rename",
            {"function": "0x401000", "old_name": "v1", "new_name": "buffer"},
        )
    )
    run(session.invoke("notebook.append", {"content": "finding"}))

    assert calls[0][1:3] == (
        "/rename_local_var",
        {"function": "0x401000", "old_name": "v1", "new_name": "buffer"},
    )
    assert calls[1][1:3] == ("/scratch_append", {"text": "finding"})


def test_ida_extended_operations_use_canonical_names_and_bridge_shapes(
    tmp_path, monkeypatch
):
    calls = []

    def fake_call(remote, endpoint, body=None, timeout=10):
        calls.append((remote, endpoint, body, timeout))
        return {"success": True}

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    monkeypatch.setattr(local_bridges, "call_remote", fake_call)
    session = local_bridges.IdaSession(
        provider_id="ida",
        registration={"port": 13337, "mode": "headless"},
        target_path=str(sample),
        database_path="sample.i64",
        capabilities=local_bridges.IDA_CAPABILITIES,
        operations=local_bridges.IDA_OPERATIONS,
        endpoint_map=local_bridges._IDA_ENDPOINTS,
        owned=True,
    )

    run(session.invoke("debugger.breakpoints.set", {"address": "0x401000"}))
    run(
        session.invoke(
            "segments.create",
            {
                "start": "0x500000",
                "end": "0x501000",
                "name": "MMIO",
                "sclass": "DATA",
            },
        )
    )
    run(session.invoke("target.upload", {"local_path": str(sample)}))
    run(session.invoke("firmware.arm.setup", {"base": "0x8000000"}))

    assert calls[0][1:3] == ("/dbg_set_breakpoint", {"address": "0x401000"})
    assert calls[1][1:3] == (
        "/add_segment",
        {
            "start": "0x500000",
            "end": "0x501000",
            "name": "MMIO",
            "class": "DATA",
        },
    )
    assert calls[2][1] == "/upload"
    assert calls[2][2]["filename"] == "sample.bin"
    assert calls[2][2]["data"] == "TVo="
    assert calls[3][1] == "/execute_python"
    assert "BASE=134217728" in calls[3][2]["code"]


def test_ida_endpoint_map_covers_every_declared_operation():
    assert {operation.name for operation in local_bridges.IDA_OPERATIONS} == set(
        local_bridges._IDA_ENDPOINTS
    )

    plugin = (Path(__file__).parents[1] / "ida" / "plugin.py").read_text(
        encoding="utf-8"
    )
    missing = {
        endpoint
        for endpoint in local_bridges._IDA_ENDPOINTS.values()
        if f'"{endpoint}"' not in plugin
    }
    assert not missing


def test_ida_backend_waits_for_ready_registration(tmp_path, monkeypatch):
    import ida.spawn_server as ida_spawn

    source = tmp_path / "sample.exe"
    source.write_bytes(b"MZ")
    database = tmp_path / "sample.i64"
    received = {}

    def fake_spawn(executable, **kwargs):
        received["executable"] = executable
        received.update(kwargs)
        return {
            "pid": 4242,
            "port": 13337,
            "ready": True,
            "mode": "headless",
            "source_path": str(source),
            "database_path": str(database),
            "capabilities": ["script.python"],
        }

    monkeypatch.setattr(ida_spawn, "_find_ida", lambda headless: "idat64.exe")
    monkeypatch.setattr(ida_spawn, "_spawn", fake_spawn)

    session = run(
        local_bridges.IdaBackend().open(
            SessionRequest(
                lifecycle=LifecycleAction.CREATE,
                target_path=str(source),
                database_path=str(database),
                options={"allow_python": True, "timeout": 17},
            )
        )
    )

    assert session.database_path == str(database)
    assert received["headless"] is True
    assert received["wait_timeout"] == 17
    assert received["allow_python"] is True


def test_ida_create_refuses_existing_database(tmp_path):
    source = tmp_path / "sample.exe"
    source.write_bytes(b"MZ")
    database = tmp_path / "sample.i64"
    database.write_bytes(b"IDA")

    with pytest.raises(ReversingMcpError) as raised:
        run(
            local_bridges.IdaBackend().open(
                SessionRequest(
                    lifecycle=LifecycleAction.CREATE,
                    target_path=str(source),
                    database_path=str(database),
                )
            )
        )

    assert raised.value.code == "database_exists"


def test_ida_reopen_accepts_database_as_target_path(tmp_path, monkeypatch):
    import ida.spawn_server as ida_spawn

    database = tmp_path / "sample.i64"
    database.write_bytes(b"IDA")
    received = {}

    def fake_spawn(executable, **kwargs):
        received.update(kwargs)
        return {
            "pid": 4242,
            "port": 13337,
            "ready": True,
            "mode": "headless",
            "database_path": str(database),
            "capabilities": [],
        }

    monkeypatch.setattr(ida_spawn, "_find_ida", lambda headless: "idat64.exe")
    monkeypatch.setattr(ida_spawn, "_spawn", fake_spawn)

    run(
        local_bridges.IdaBackend().open(
            SessionRequest(
                lifecycle=LifecycleAction.REOPEN,
                target_path=str(database),
            )
        )
    )

    assert received["source_path"] == ""
    assert received["database_path"] == str(database)


def test_jadx_read_only_close_never_requests_save(monkeypatch):
    calls = []

    def fake_call(remote, endpoint, body=None, timeout=10):
        calls.append((remote, endpoint, body, timeout))
        return {"success": True}

    monkeypatch.setattr(local_bridges, "call_remote", fake_call)
    session = local_bridges.JadxSession(
        provider_id="jadx",
        registration={
            "port": 13537,
            "mode": "headless",
            "owned": True,
            "protocol_version": "1.0",
        },
        target_path="sample.apk",
        database_path="",
        capabilities=local_bridges.JADX_CAPABILITIES,
        operations=local_bridges.JADX_OPERATIONS,
        endpoint_map=local_bridges._JADX_ENDPOINTS,
        owned=True,
        read_only=True,
    )

    run(session.close(save=True))

    assert calls == [("127.0.0.1:13537", "/close", {"save": False}, 30)]


def test_ghidra_endpoint_map_covers_every_declared_operation():
    declared = {operation.name for operation in local_bridges.GHIDRA_OPERATIONS}
    assert declared == set(local_bridges._GHIDRA_ENDPOINTS)
    assert local_bridges._NATIVE_ENDPOINTS["references.to"] == "/xrefs_to"
    assert local_bridges._NATIVE_ENDPOINTS["functions.create"] == "/create_function"
    assert local_bridges._GHIDRA_ENDPOINTS["analysis.range"] == "/analyze_range"
    assert local_bridges._GHIDRA_ENDPOINTS["segments.update"] == "/set_segment_perms"


def test_headless_ghidra_script_registers_every_unified_endpoint():
    script_path = (
        Path(__file__).parents[1] / "ghidra" / "scripts" / "ghidra_mcp_bridge.java"
    )
    source = script_path.read_text(encoding="utf-8")
    registered = set(re.findall(r'createContext\("(/[^"]+)"', source))

    assert set(local_bridges._GHIDRA_ENDPOINTS.values()) <= registered
    assert '"analysis.range"' in source
    assert '"segments.update"' in source
    assert "ExecutorService serverExecutor" in source
    assert "serverExecutor.shutdownNow()" in source


def test_ghidra_unified_session_forwards_common_operations_and_save(monkeypatch):
    calls = []

    def fake_call(remote, endpoint, body=None, timeout=10):
        calls.append((remote, endpoint, body, timeout))
        return {"success": True}

    monkeypatch.setattr(local_bridges, "call_remote", fake_call)
    session = local_bridges.GhidraSession(
        provider_id="ghidra",
        registration={"port": 13437, "mode": "headless", "owned": True},
        target_path="sample.exe",
        database_path="sample.gpr",
        capabilities=local_bridges.NATIVE_CAPABILITIES
        | {"analysis.range", "segments.update"},
        operations=local_bridges.GHIDRA_OPERATIONS,
        endpoint_map=local_bridges._GHIDRA_ENDPOINTS,
        owned=True,
    )

    run(session.invoke("target.info", {}))
    run(
        session.invoke(
            "comments.write",
            {"function": "0x401000", "comment": "entry point"},
        )
    )
    run(session.invoke("analysis.range", {"start": "0x401000", "end": "0x401010"}))
    run(session.invoke("segments.update", {"address": "0x401000", "perms": "RX"}))
    run(session.save())

    assert calls == [
        ("127.0.0.1:13437", "/info", None, 60),
        (
            "127.0.0.1:13437",
            "/comment",
            {
                "address": "0x401000",
                "comment": "entry point",
                "repeatable": False,
            },
            60,
        ),
        (
            "127.0.0.1:13437",
            "/analyze_range",
            {"start": "0x401000", "end": "0x401010"},
            60,
        ),
        (
            "127.0.0.1:13437",
            "/set_segment_perms",
            {"address": "0x401000", "perms": "RX"},
            60,
        ),
        ("127.0.0.1:13437", "/save", {}, 120),
    ]


def test_jadx_unified_session_preserves_managed_operation_shapes(monkeypatch):
    calls = []

    def fake_call(remote, endpoint, body=None, timeout=10):
        calls.append((remote, endpoint, body, timeout))
        return {"success": True}

    monkeypatch.setattr(local_bridges, "call_remote", fake_call)
    session = local_bridges.JadxSession(
        provider_id="jadx",
        registration={"port": 13537, "mode": "headless", "owned": True},
        target_path="sample.apk",
        database_path="",
        capabilities=local_bridges.JADX_CAPABILITIES,
        operations=local_bridges.JADX_OPERATIONS,
        endpoint_map=local_bridges._JADX_ENDPOINTS,
        owned=True,
        read_only=True,
    )

    run(session.invoke("search.classes", {"query": "com.foo", "limit": 50}))
    run(
        session.invoke(
            "analysis.decompile",
            {"class_name": "com.foo.Bar", "method": "baz"},
        )
    )
    run(session.invoke("references.to", {"class_name": "com.foo.Bar"}))
    run(
        session.invoke(
            "android.resources.list",
            {"prefix": "res/", "limit": 25},
        )
    )

    assert [call[1:3] for call in calls] == [
        ("/search_classes", {"limit": 50, "pattern": "com.foo"}),
        ("/decompile_method", {"method": "baz", "class": "com.foo.Bar"}),
        ("/xrefs_to", {"class": "com.foo.Bar"}),
        ("/list_resources", {"prefix": "res/", "limit": 25}),
    ]


def test_local_bridge_attach_selects_target_by_registration_metadata(monkeypatch):
    monkeypatch.setattr(
        local_bridges,
        "discover_instances",
        lambda reg_dir: [
            {"pid": 1, "program": "first.bin", "port": 13437},
            {"pid": 2, "jar": "target.apk", "port": 13537},
        ],
    )

    registration = local_bridges._attach_registration("unused", "target.apk")

    assert registration["pid"] == 2
    assert registration["jar"] == "target.apk"


def test_ghidra_gui_session_runs_guarded_jython(monkeypatch):
    calls = []

    def fake_call(remote, endpoint, body=None, timeout=10):
        calls.append((remote, endpoint, body, timeout))
        return {"success": True, "stdout": "42\n"}

    monkeypatch.setattr(local_bridges, "call_remote", fake_call)
    session = local_bridges.GhidraSession(
        provider_id="ghidra",
        registration={"port": 13437, "mode": "gui"},
        target_path="sample.exe",
        database_path="sample.gpr",
        capabilities=local_bridges.GHIDRA_CAPABILITIES,
        operations=local_bridges.NATIVE_OPERATIONS,
        endpoint_map=local_bridges._NATIVE_ENDPOINTS,
        owned=False,
    )

    result = run(
        session.run_script(
            language="python",
            source='print(arguments["answer"])',
            arguments={"answer": 42},
        )
    )

    assert result["stdout"] == "42\n"
    assert calls[0][1] == "/exec_script"
    assert '"answer": 42' in calls[0][2]["code"]
    assert calls[0][2]["commit"] == "true"
    assert calls[0][3] == 600
