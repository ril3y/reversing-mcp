"""Read-only ILSpy provider backed by the repository's .NET bridge."""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping

from common import call_remote, discover_instances

from ..backends import AnalysisBackend, AnalysisSession
from ..errors import ReversingMcpError
from ..models import Capability, LifecycleAction, OperationSpec, SessionRequest

REGISTRATION_DIR = os.path.expanduser("~/.ilspy_mcp")

ILSPY_OPERATIONS = (
    OperationSpec("target.info", "target.info"),
    OperationSpec("managed.assemblies.list", "managed.assemblies.list"),
    OperationSpec("managed.types.list", "managed.types.list"),
    OperationSpec("managed.types.search", "managed.types.search"),
    OperationSpec("managed.types.decompile", Capability.ANALYSIS_DECOMPILE),
    OperationSpec("managed.methods.list", "managed.methods.list"),
    OperationSpec("managed.methods.decompile", Capability.ANALYSIS_DECOMPILE),
    OperationSpec("managed.methods.il", "managed.methods.il"),
    OperationSpec("search.strings", "search.strings"),
)

ILSPY_CAPABILITIES = frozenset(
    {
        Capability.LIFECYCLE_OPEN,
        Capability.LIFECYCLE_ATTACH,
        Capability.LIFECYCLE_CLOSE,
        Capability.ANALYSIS_DECOMPILE,
        "target.info",
        "managed.assemblies.list",
        "managed.types.list",
        "managed.types.search",
        "managed.methods.list",
        "managed.methods.il",
        "search.strings",
    }
)

_ENDPOINTS = {
    "target.info": "/info",
    "managed.assemblies.list": "/list_assemblies",
    "managed.types.list": "/list_types",
    "managed.types.search": "/search_types",
    "managed.types.decompile": "/decompile_type",
    "managed.methods.list": "/list_methods",
    "managed.methods.decompile": "/decompile_method",
    "managed.methods.il": "/get_il",
    "search.strings": "/search_strings",
}

_GET_OPERATIONS = {"target.info", "managed.assemblies.list"}


def _provider_error(response: Any) -> Any:
    if isinstance(response, dict) and response.get("error"):
        raise ReversingMcpError(
            "provider_operation_failed",
            str(response["error"]),
            details={"provider": "ilspy", "response": response},
        )
    return response


def _select_registration(target: str) -> dict[str, Any]:
    registrations = discover_instances(REGISTRATION_DIR)
    if target:
        folded = target.casefold()
        registrations = [
            item
            for item in registrations
            if folded in str(item.get("assembly", "")).casefold()
            or folded in str(item.get("assembly_path", "")).casefold()
        ]
    if not registrations:
        raise ReversingMcpError(
            "session_not_found", "No matching ILSpy bridge is running"
        )
    if len(registrations) > 1 and not target:
        raise ReversingMcpError(
            "ambiguous_session",
            "Multiple ILSpy bridges are running; provide an assembly selector",
            details={"sessions": registrations},
        )
    return registrations[0]


def _default_bridge_candidates() -> list[Path]:
    root = Path(__file__).resolve().parents[2]
    project = root / "ilspy" / "IlspyMcpBridge" / "bin" / "Release" / "net8.0"
    executable = "ilspy-mcp-bridge.exe" if os.name == "nt" else "ilspy-mcp-bridge"
    publish = project / "publish"
    return [
        publish / executable,
        publish / "ilspy-mcp-bridge.dll",
        publish / "IlspyMcpBridge.dll",
        project / executable,
        project / "ilspy-mcp-bridge.dll",
    ]


def _bridge_command(
    assembly: Path, options: Mapping[str, Any]
) -> tuple[list[str], Path | None]:
    configured = str(
        options.get("bridge_path", "") or os.environ.get("ILSPY_MCP_BRIDGE", "")
    )
    candidates = (
        [Path(configured).expanduser()] if configured else _default_bridge_candidates()
    )
    bridge = next(
        (candidate.resolve() for candidate in candidates if candidate.is_file()), None
    )
    if bridge is None:
        raise ReversingMcpError(
            "dependency_missing",
            "The built ILSpy MCP bridge was not found",
            details={
                "remediation": (
                    "Build ilspy/IlspyMcpBridge in Release mode or set "
                    "ILSPY_MCP_BRIDGE / options.bridge_path"
                )
            },
        )
    if bridge.suffix.casefold() == ".dll":
        command = [str(options.get("dotnet_command", "dotnet")), str(bridge)]
    else:
        command = [str(bridge)]
    command.extend(str(item) for item in options.get("bridge_args", ()))
    command.append(str(assembly))
    return command, bridge


def _launch_bridge(
    assembly_path: str,
    *,
    options: Mapping[str, Any],
) -> tuple[subprocess.Popen, dict[str, Any]]:
    assembly = Path(assembly_path).expanduser().resolve()
    if not assembly.is_file():
        raise ReversingMcpError(
            "target_not_found", f"Assembly does not exist: {assembly}"
        )
    command, _bridge = _bridge_command(assembly, options)
    process = subprocess.Popen(  # noqa: S603 - explicit local bridge executable
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    timeout = float(options.get("timeout", 120))
    deadline = time.monotonic() + max(timeout, 0.1)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ReversingMcpError(
                "provider_start_failed",
                "ILSpy bridge exited before registering",
                details={"exit_code": process.returncode},
            )
        registration = next(
            (
                item
                for item in discover_instances(REGISTRATION_DIR)
                if item.get("pid") == process.pid
            ),
            None,
        )
        if registration is not None:
            return process, registration
        time.sleep(0.1)
    process.terminate()
    process.wait(timeout=5)
    raise ReversingMcpError(
        "session_start_timeout",
        f"ILSpy bridge did not register within {timeout:g} seconds",
    )


class IlspySession(AnalysisSession):
    def __init__(
        self,
        registration: Mapping[str, Any],
        *,
        process: subprocess.Popen | None,
        owned: bool,
    ) -> None:
        capabilities = set(ILSPY_CAPABILITIES)
        if not owned:
            capabilities.discard(Capability.LIFECYCLE_CLOSE)
        super().__init__(
            provider_id="ilspy",
            target_path=str(registration.get("assembly_path", "")),
            mode="headless" if owned else "attached",
            capabilities=frozenset(capabilities),
            operations=ILSPY_OPERATIONS,
        )
        self._port = int(registration["port"])
        self._process = process
        self._owned = owned
        self._registration_path = Path(REGISTRATION_DIR) / (
            f"{int(registration.get('pid', process.pid if process else 0))}.json"
        )
        self._closed = False
        self._lock = asyncio.Lock()

    def _call(self, endpoint: str, body: Mapping[str, Any] | None) -> Any:
        if self._closed:
            raise ReversingMcpError("session_closed", "ILSpy session is closed")
        return _provider_error(
            call_remote(
                f"127.0.0.1:{self._port}",
                endpoint,
                dict(body) if body is not None else None,
                timeout=120,
            )
        )

    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        try:
            endpoint = _ENDPOINTS[operation]
        except KeyError as error:
            raise ReversingMcpError(
                "unsupported_operation", f"Unsupported ILSpy operation: {operation}"
            ) from error
        body = self._translate(operation, arguments)
        if operation in _GET_OPERATIONS:
            body = None
        async with self._lock:
            return await asyncio.to_thread(self._call, endpoint, body)

    async def save(self) -> Any:
        raise ReversingMcpError(
            "unsupported_capability", "ILSpy sessions are read-only"
        )

    async def close(self, *, save: bool = True) -> Any:
        del save
        if not self._owned or self._process is None:
            raise ReversingMcpError(
                "unsupported_capability",
                "Attached ILSpy bridges remain externally owned",
            )
        async with self._lock:
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    await asyncio.to_thread(self._process.wait, 5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    await asyncio.to_thread(self._process.wait, 5)
            self._registration_path.unlink(missing_ok=True)
            self._closed = True
            return {"closed": True, "pid": self._process.pid, "saved": False}

    @staticmethod
    def _translate(operation: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        body = dict(arguments)
        if operation == "managed.types.search":
            body["pattern"] = body.pop("query", body.get("pattern", ""))
        elif operation == "managed.types.decompile":
            body["name"] = body.pop("type_name", body.get("name", ""))
        elif operation in {
            "managed.methods.list",
            "managed.methods.decompile",
            "managed.methods.il",
        }:
            body["type"] = body.pop("type_name", body.get("type", ""))
        elif operation == "search.strings":
            body["pattern"] = body.pop("query", body.get("pattern", ""))
        return body


class IlspyBackend(AnalysisBackend):
    def __init__(self) -> None:
        super().__init__(
            provider_id="ilspy",
            display_name="ILSpy",
            capabilities=ILSPY_CAPABILITIES,
            operations=ILSPY_OPERATIONS,
        )

    async def open(self, request: SessionRequest) -> AnalysisSession:
        if request.lifecycle == LifecycleAction.ATTACH:
            registration = await asyncio.to_thread(
                _select_registration, request.target_path
            )
            return IlspySession(registration, process=None, owned=False)
        if request.lifecycle != LifecycleAction.OPEN:
            raise ReversingMcpError(
                "unsupported_lifecycle",
                "ILSpy supports open and attach; it does not create databases",
            )
        if request.mode not in {"headless", ""}:
            raise ReversingMcpError(
                "unsupported_mode", "Owned ILSpy sessions are headless"
            )
        process, registration = await asyncio.to_thread(
            _launch_bridge,
            request.target_path,
            options=request.options,
        )
        return IlspySession(registration, process=process, owned=True)
