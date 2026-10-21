"""Frida provider tests using a small in-memory SDK double."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from reversing_mcp.manager import ServerPolicy, SessionManager
from reversing_mcp.models import LifecycleAction, SessionRequest
from reversing_mcp.providers import frida
from reversing_mcp.registry import ProviderRegistry


def run(coroutine):
    return asyncio.run(coroutine)


class FakeScript:
    def __init__(self, source: str) -> None:
        self.source = source
        self.callback = None
        self.loaded = False
        self.unloaded = False
        self.exports = SimpleNamespace(
            echo=lambda value: value,
            enum_modules=lambda: [{"name": "main.exe"}],
            enum_exports=lambda module: [{"name": f"{module}!export"}],
            enum_imports=lambda module: [{"name": f"{module}!import"}],
            find_export=lambda module, symbol: f"{module}:{symbol}",
            read_bytes=lambda address, size: bytes(range(size)),
        )

    def on(self, event, callback):
        assert event == "message"
        self.callback = callback

    def load(self):
        self.loaded = True

    def unload(self):
        self.unloaded = True


class FakeNativeSession:
    def __init__(self) -> None:
        self.scripts = []
        self.detached = False

    def create_script(self, source, runtime="qjs"):
        assert runtime in {"qjs", "v8"}
        script = FakeScript(source)
        self.scripts.append(script)
        return script

    def detach(self):
        self.detached = True


class FakeDevice:
    id = "local"
    name = "Local System"
    type = "local"

    def __init__(self) -> None:
        self.native = FakeNativeSession()
        self.spawned = []
        self.resumed = []
        self.killed = []

    def enumerate_processes(self):
        return [SimpleNamespace(pid=10, name="target.exe")]

    def enumerate_applications(self):
        return [SimpleNamespace(identifier="app.id", name="App", pid=10)]

    def spawn(self, program, **options):
        self.spawned.append((program, options))
        return 10

    def attach(self, pid):
        assert pid == 10
        return self.native

    def resume(self, pid):
        self.resumed.append(pid)

    def kill(self, pid):
        self.killed.append(pid)


class FakeFrida:
    def __init__(self) -> None:
        self.device = FakeDevice()
        self.manager = SimpleNamespace(enumerate_devices=lambda: [self.device])

    def get_local_device(self):
        return self.device

    def get_usb_device(self, timeout=5):
        assert timeout == 5
        return self.device

    def get_remote_device(self):
        return self.device

    def get_device_manager(self):
        return self.manager


def test_frida_attach_script_messages_rpc_and_close(monkeypatch):
    sdk = FakeFrida()
    monkeypatch.setattr(frida.importlib, "import_module", lambda name: sdk)
    session = run(
        frida.FridaBackend().open(
            SessionRequest(
                lifecycle=LifecycleAction.ATTACH,
                target_path="target.exe",
                options={"device_id": "local"},
            )
        )
    )

    loaded = run(
        session.run_script(
            language="javascript",
            source="send(__mcpArguments.value);",
            arguments={"value": 7},
        )
    )
    script_id = loaded["script_id"]
    script = sdk.device.native.scripts[-1]
    assert 'globalThis.__mcpArguments = {"value":7}' in script.source
    script.callback({"type": "send", "payload": "hello"}, b"\x01\x02")

    messages = run(
        session.invoke(
            "frida.messages.drain",
            {"script_id": script_id, "max_messages": 10},
        )
    )
    rpc = run(
        session.invoke(
            "frida.rpc.call",
            {"script_id": script_id, "method": "echo", "args": [42]},
        )
    )
    closed = run(session.close(save=True))

    assert messages == [{"type": "send", "payload": "hello", "data_hex": "0102"}]
    assert rpc == 42
    assert closed["detached"] is True
    assert sdk.device.native.detached
    assert script.unloaded


def test_frida_open_spawns_suspended_then_resumes(monkeypatch):
    sdk = FakeFrida()
    monkeypatch.setattr(frida.importlib, "import_module", lambda name: sdk)
    session = run(
        frida.FridaBackend().open(
            SessionRequest(
                lifecycle=LifecycleAction.OPEN,
                target_path="app.id",
                options={"argv": ["--flag"], "envp": {"A": "B"}},
            )
        )
    )

    result = run(session.invoke("frida.process.resume", {}))

    assert sdk.device.spawned == [("app.id", {"argv": ["--flag"], "envp": {"A": "B"}})]
    assert result == {"resumed": 10}
    assert sdk.device.resumed == [10]


def test_frida_inventory_session_needs_no_target(monkeypatch):
    sdk = FakeFrida()
    monkeypatch.setattr(frida.importlib, "import_module", lambda name: sdk)
    session = run(
        frida.FridaBackend().open(
            SessionRequest(lifecycle=LifecycleAction.OPEN, target_path="")
        )
    )

    devices = run(session.invoke("frida.devices.list", {}))
    processes = run(session.invoke("frida.processes.list", {"name_filter": "target"}))

    assert session.mode == "inventory"
    assert "script.javascript" not in session.capabilities
    assert devices == [{"id": "local", "name": "Local System", "type": "local"}]
    assert processes == [{"pid": 10, "name": "target.exe"}]


def test_frida_javascript_uses_guarded_manager_route_and_read_only_close(
    monkeypatch,
):
    sdk = FakeFrida()
    monkeypatch.setattr(frida.importlib, "import_module", lambda name: sdk)
    manager = SessionManager(
        ProviderRegistry([frida.FridaBackend()]),
        policy=ServerPolicy(
            allow_script_execution=True,
            script_providers=frozenset({"frida"}),
        ),
    )
    descriptor = run(
        manager.open_session(
            "frida",
            lifecycle=LifecycleAction.ATTACH,
            target_path="10",
            options={"device_id": "local"},
        )
    )

    loaded = run(
        manager.run_script(
            descriptor.session_id,
            language="javascript",
            source="send('loaded');",
            save_after=False,
        )
    )
    closed = run(manager.close_session(descriptor.session_id))

    assert loaded["script_id"].startswith("script_")
    assert closed.state == "closed"
    assert sdk.device.native.detached
