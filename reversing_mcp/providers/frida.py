"""Dynamic Frida provider with per-session script and message ownership."""

from __future__ import annotations

import asyncio
import importlib
import json
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..backends import AnalysisBackend, AnalysisSession
from ..errors import ReversingMcpError
from ..models import Capability, LifecycleAction, OperationSpec, SessionRequest

SCRIPT_JAVASCRIPT = "script.javascript"

FRIDA_OPERATIONS = (
    OperationSpec("frida.devices.list", "frida.inventory"),
    OperationSpec("frida.processes.list", "frida.inventory"),
    OperationSpec("frida.applications.list", "frida.inventory"),
    OperationSpec("frida.process.resume", "frida.process.control", mutating=True),
    OperationSpec("frida.scripts.unload", SCRIPT_JAVASCRIPT, mutating=True),
    OperationSpec("frida.messages.drain", SCRIPT_JAVASCRIPT),
    OperationSpec("frida.rpc.call", SCRIPT_JAVASCRIPT, mutating=True),
    OperationSpec("modules.list", "modules.list"),
    OperationSpec("symbols.exports.list", "symbols.exports.list"),
    OperationSpec("symbols.imports.list", "symbols.imports.list"),
    OperationSpec("symbols.export.find", "symbols.export.find"),
    OperationSpec("memory.read", "memory.read"),
)

FRIDA_CAPABILITIES = frozenset(
    {
        Capability.LIFECYCLE_OPEN,
        Capability.LIFECYCLE_ATTACH,
        Capability.LIFECYCLE_CLOSE,
        SCRIPT_JAVASCRIPT,
        "frida.inventory",
        "frida.process.control",
        "modules.list",
        "symbols.exports.list",
        "symbols.imports.list",
        "symbols.export.find",
        "memory.read",
    }
)

_ENUM_MODULES_JS = """
rpc.exports = {
  enumModules() {
    return Process.enumerateModules().map(m => ({
      name: m.name, base: m.base.toString(), size: m.size, path: m.path,
    }));
  },
  enumExports(name) {
    const m = Process.findModuleByName(name);
    return m ? m.enumerateExports().map(e => ({
      name: e.name, type: e.type, address: e.address.toString(),
    })) : null;
  },
  enumImports(name) {
    const m = Process.findModuleByName(name);
    return m ? m.enumerateImports().map(e => ({
      name: e.name, type: e.type, module: e.module,
      address: e.address ? e.address.toString() : null,
    })) : null;
  },
  findExport(moduleName, symbol) {
    const p = Module.findExportByName(moduleName, symbol);
    return p ? p.toString() : null;
  },
};
"""

_READ_MEMORY_JS = """
rpc.exports = {
  readBytes(address, size) { return ptr(address).readByteArray(size); },
};
"""


@dataclass
class _ScriptRecord:
    script_id: str
    script: Any
    messages: deque[dict[str, Any]]
    helper_key: str = ""
    lock: threading.Lock = field(default_factory=threading.Lock)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _load_frida():
    try:
        return importlib.import_module("frida")
    except ImportError as error:
        raise ReversingMcpError(
            "dependency_missing",
            "frida-python is not installed",
            details={"remediation": "Install the 'frida' Python package"},
        ) from error


def _get_device(frida_module, device_id: str):
    if device_id == "local":
        return frida_module.get_local_device()
    if device_id == "usb":
        return frida_module.get_usb_device(timeout=5)
    if device_id == "remote":
        return frida_module.get_remote_device()
    devices = frida_module.get_device_manager().enumerate_devices()
    for device in devices:
        if device_id == device.id or device_id in (device.name or ""):
            return device
    raise ReversingMcpError(
        "device_not_found", f"No Frida device matches {device_id!r}"
    )


def _resolve_pid(device, target: str) -> int:
    try:
        return int(target)
    except ValueError:
        matches = [
            process
            for process in device.enumerate_processes()
            if process.name == target
        ]
        if not matches:
            raise ReversingMcpError("target_not_found", f"No process named {target!r}")
        return int(matches[0].pid)


class FridaSession(AnalysisSession):
    def __init__(
        self,
        *,
        frida_module,
        device,
        device_id: str,
        target: str,
        pid: int,
        native_session,
        suspended: bool,
        kill_on_close: bool,
    ) -> None:
        capabilities = set(FRIDA_CAPABILITIES)
        if native_session is None:
            capabilities -= {
                SCRIPT_JAVASCRIPT,
                "frida.process.control",
                "modules.list",
                "symbols.exports.list",
                "symbols.imports.list",
                "symbols.export.find",
                "memory.read",
            }
        super().__init__(
            provider_id="frida",
            target_path=target,
            mode="dynamic" if native_session is not None else "inventory",
            capabilities=frozenset(capabilities),
            operations=FRIDA_OPERATIONS,
        )
        self._frida = frida_module
        self._device = device
        self._device_id = device_id
        self._pid = pid
        self._native_session = native_session
        self._suspended = suspended
        self._kill_on_close = kill_on_close
        self._scripts: dict[str, _ScriptRecord] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        async with self._lock:
            return await asyncio.to_thread(
                self._invoke_sync, operation, dict(arguments)
            )

    def _invoke_sync(self, operation: str, arguments: dict[str, Any]) -> Any:
        self._ensure_open()
        if operation == "frida.devices.list":
            return [
                {"id": item.id, "name": item.name, "type": item.type}
                for item in self._frida.get_device_manager().enumerate_devices()
            ]
        if operation == "frida.processes.list":
            pattern = str(arguments.get("name_filter", "")).casefold()
            return [
                {"pid": item.pid, "name": item.name}
                for item in self._device.enumerate_processes()
                if not pattern or pattern in (item.name or "").casefold()
            ]
        if operation == "frida.applications.list":
            return [
                {"identifier": item.identifier, "name": item.name, "pid": item.pid}
                for item in self._device.enumerate_applications()
            ]

        self._require_target()
        if operation == "frida.process.resume":
            if not self._suspended:
                return {"resumed": self._pid, "already_running": True}
            self._device.resume(self._pid)
            self._suspended = False
            return {"resumed": self._pid}
        if operation == "frida.scripts.unload":
            script_id = str(arguments.get("script_id", ""))
            record = self._require_script(script_id)
            try:
                record.script.unload()
            finally:
                self._scripts.pop(script_id, None)
            return {"unloaded": True, "script_id": script_id}
        if operation == "frida.messages.drain":
            record = self._require_script(str(arguments.get("script_id", "")))
            limit = max(0, int(arguments.get("max_messages", 200)))
            with record.lock:
                return [
                    record.messages.popleft()
                    for _ in range(min(limit, len(record.messages)))
                ]
        if operation == "frida.rpc.call":
            record = self._require_script(str(arguments.get("script_id", "")))
            method = str(arguments.get("method", ""))
            function = getattr(record.script.exports, method, None)
            if function is None:
                raise ReversingMcpError(
                    "rpc_method_not_found", f"Script has no rpc.exports.{method}"
                )
            return function(*list(arguments.get("args") or ()))
        if operation == "modules.list":
            return self._helper(
                "modules", _ENUM_MODULES_JS
            ).script.exports.enum_modules()
        if operation == "symbols.exports.list":
            return self._helper(
                "modules", _ENUM_MODULES_JS
            ).script.exports.enum_exports(str(arguments.get("module", "")))
        if operation == "symbols.imports.list":
            return self._helper(
                "modules", _ENUM_MODULES_JS
            ).script.exports.enum_imports(str(arguments.get("module", "")))
        if operation == "symbols.export.find":
            module = str(arguments.get("module", "")) or None
            return self._helper("modules", _ENUM_MODULES_JS).script.exports.find_export(
                module, str(arguments.get("symbol", ""))
            )
        if operation == "memory.read":
            size = int(arguments.get("size", 0))
            if not 0 <= size <= 65536:
                raise ReversingMcpError(
                    "invalid_request", "Frida memory reads are capped at 65536 bytes"
                )
            address = str(arguments.get("address", ""))
            data = self._helper("memory", _READ_MEMORY_JS).script.exports.read_bytes(
                address, size
            )
            return {
                "address": address,
                "size": size,
                "bytes": bytes(data).hex() if data else "",
            }
        raise ReversingMcpError(
            "unsupported_operation", f"Unsupported Frida operation: {operation}"
        )

    async def run_script(
        self, *, language: str, source: str, arguments: Mapping[str, Any]
    ) -> Any:
        if language not in {"javascript", "js"}:
            return await super().run_script(
                language=language, source=source, arguments=arguments
            )
        argument_json = json.dumps(dict(arguments), separators=(",", ":"))
        wrapped = f"globalThis.__mcpArguments = {argument_json};\n{source}"
        runtime = str(arguments.get("runtime", "qjs"))
        async with self._lock:
            self._ensure_open()
            self._require_target()
            record = await asyncio.to_thread(self._create_script, wrapped, runtime, "")
            return {"script_id": record.script_id, "runtime": runtime}

    async def save(self) -> Any:
        raise ReversingMcpError(
            "unsupported_capability", "Frida sessions have no persistent database"
        )

    async def close(self, *, save: bool = True) -> Any:
        del save
        async with self._lock:
            if self._closed:
                return {"closed": True, "already_closed": True}
            for record in list(self._scripts.values()):
                try:
                    record.script.unload()
                except Exception:
                    pass
            self._scripts.clear()
            if self._native_session is not None:
                await asyncio.to_thread(self._native_session.detach)
                killed = False
                if self._kill_on_close:
                    try:
                        await asyncio.to_thread(self._device.kill, self._pid)
                        killed = True
                    except Exception:
                        pass
            else:
                killed = False
            self._closed = True
            return {
                "closed": True,
                "detached": self._native_session is not None,
                "killed": killed,
            }

    def _create_script(
        self, source: str, runtime: str, helper_key: str
    ) -> _ScriptRecord:
        script = self._native_session.create_script(source, runtime=runtime)
        record = _ScriptRecord(
            script_id=_new_id("script"),
            script=script,
            messages=deque(maxlen=10_000),
            helper_key=helper_key,
        )

        def on_message(message, data):
            entry = {
                "type": message.get("type"),
                "payload": message.get("payload"),
                "data_hex": data.hex() if data else None,
            }
            if message.get("type") == "error":
                entry.update(
                    {
                        "description": message.get("description"),
                        "stack": message.get("stack"),
                    }
                )
            with record.lock:
                record.messages.append(entry)

        script.on("message", on_message)
        script.load()
        self._scripts[record.script_id] = record
        return record

    def _helper(self, key: str, source: str) -> _ScriptRecord:
        for record in self._scripts.values():
            if record.helper_key == key:
                return record
        return self._create_script(source, "qjs", key)

    def _require_script(self, script_id: str) -> _ScriptRecord:
        try:
            return self._scripts[script_id]
        except KeyError as error:
            raise ReversingMcpError(
                "script_not_found", f"No Frida script {script_id!r}"
            ) from error

    def _require_target(self) -> None:
        if self._native_session is None:
            raise ReversingMcpError(
                "unsupported_capability",
                "This is an inventory-only Frida session; attach or spawn a target",
            )

    def _ensure_open(self) -> None:
        if self._closed:
            raise ReversingMcpError("session_closed", "Frida session is closed")


class FridaBackend(AnalysisBackend):
    def __init__(self) -> None:
        super().__init__(
            provider_id="frida",
            display_name="Frida",
            capabilities=FRIDA_CAPABILITIES,
            operations=FRIDA_OPERATIONS,
        )

    async def open(self, request: SessionRequest) -> AnalysisSession:
        if request.lifecycle not in {LifecycleAction.OPEN, LifecycleAction.ATTACH}:
            raise ReversingMcpError(
                "unsupported_lifecycle", "Frida supports open/spawn and attach"
            )
        frida_module = _load_frida()
        default_device = (
            "local"
            if request.lifecycle == LifecycleAction.ATTACH or not request.target_path
            else "usb"
        )
        device_id = str(request.options.get("device_id", default_device))
        device = await asyncio.to_thread(_get_device, frida_module, device_id)
        target = request.target_path
        native_session = None
        pid = 0
        suspended = False
        if request.lifecycle == LifecycleAction.ATTACH:
            if not target:
                raise ReversingMcpError(
                    "invalid_request", "Frida attach requires a process name or PID"
                )
            pid = await asyncio.to_thread(_resolve_pid, device, target)
            native_session = await asyncio.to_thread(device.attach, pid)
        elif target:
            spawn_options: dict[str, Any] = {}
            if request.options.get("argv") is not None:
                spawn_options["argv"] = list(request.options["argv"])
            if request.options.get("envp") is not None:
                spawn_options["envp"] = dict(request.options["envp"])
            pid = await asyncio.to_thread(device.spawn, target, **spawn_options)
            native_session = await asyncio.to_thread(device.attach, pid)
            suspended = True
        return FridaSession(
            frida_module=frida_module,
            device=device,
            device_id=device_id,
            target=target,
            pid=pid,
            native_session=native_session,
            suspended=suspended,
            kill_on_close=bool(request.options.get("kill_on_close", False)),
        )
