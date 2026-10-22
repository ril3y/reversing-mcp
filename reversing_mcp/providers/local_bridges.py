"""Adapters for the repository's loopback IDA, Ghidra, and JADX bridges."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from pathlib import Path
from typing import Any, Mapping

from common import call_remote, discover_instances

from ..android_artifacts import AndroidArtifact
from ..backends import AnalysisBackend, AnalysisSession
from ..errors import ReversingMcpError
from ..models import (
    Capability,
    CommonOperation,
    LifecycleAction,
    OperationSpec,
    SessionRequest,
)
from .ida_firmware import build_arm_setup_script


NATIVE_OPERATIONS = (
    OperationSpec(CommonOperation.TARGET_INFO, "target.info"),
    OperationSpec(CommonOperation.FUNCTIONS_GET, "functions.get"),
    OperationSpec(CommonOperation.FUNCTIONS_LIST, "functions.list"),
    OperationSpec(CommonOperation.ANALYSIS_DECOMPILE, Capability.ANALYSIS_DECOMPILE),
    OperationSpec(
        CommonOperation.ANALYSIS_DISASSEMBLE, Capability.ANALYSIS_DISASSEMBLE
    ),
    OperationSpec(CommonOperation.REFERENCES_TO, Capability.ANALYSIS_XREFS),
    OperationSpec(CommonOperation.REFERENCES_FROM, Capability.ANALYSIS_XREFS),
    OperationSpec(CommonOperation.CALLGRAPH_CALLERS, "callgraph.callers"),
    OperationSpec(CommonOperation.CALLGRAPH_CALLEES, "callgraph.callees"),
    OperationSpec(CommonOperation.SEARCH_FUNCTIONS, "search.functions"),
    OperationSpec(CommonOperation.SEARCH_STRINGS, "search.strings"),
    OperationSpec(CommonOperation.MEMORY_READ, "memory.read"),
    OperationSpec(CommonOperation.SEGMENTS_LIST, "segments.list"),
    OperationSpec(
        CommonOperation.SYMBOLS_RENAME, Capability.SYMBOLS_RENAME, mutating=True
    ),
    OperationSpec(
        CommonOperation.COMMENTS_WRITE, Capability.COMMENTS_WRITE, mutating=True
    ),
    OperationSpec(
        CommonOperation.FUNCTIONS_CREATE, Capability.FUNCTIONS_CREATE, mutating=True
    ),
    OperationSpec(
        CommonOperation.FUNCTIONS_DELETE, Capability.FUNCTIONS_DELETE, mutating=True
    ),
)

IDA_OPERATIONS = NATIVE_OPERATIONS + (
    OperationSpec(CommonOperation.TYPES_DEFINE, Capability.TYPES_DEFINE, mutating=True),
    OperationSpec(CommonOperation.TYPES_APPLY, Capability.TYPES_APPLY, mutating=True),
    OperationSpec(
        CommonOperation.FUNCTIONS_SET_PROTOTYPE,
        "functions.prototype.set",
        mutating=True,
    ),
    OperationSpec(CommonOperation.LOCALS_RENAME, "locals.rename", mutating=True),
    OperationSpec(CommonOperation.LOCALS_SET_TYPE, "locals.type.set", mutating=True),
    OperationSpec(CommonOperation.NOTEBOOK_READ, "notebook.read"),
    OperationSpec(CommonOperation.NOTEBOOK_APPEND, "notebook.append", mutating=True),
    OperationSpec(CommonOperation.NOTEBOOK_REPLACE, "notebook.replace", mutating=True),
    OperationSpec(CommonOperation.NOTEBOOK_CLEAR, "notebook.clear", mutating=True),
    OperationSpec("analysis.code.create", "analysis.code.create", mutating=True),
    OperationSpec("firmware.micromips.scan", "firmware.micromips.scan", mutating=True),
    OperationSpec("firmware.arm.setup", "firmware.arm.setup", mutating=True),
    OperationSpec("segments.create", "segments.create", mutating=True),
    OperationSpec("segments.update", "segments.update", mutating=True),
    OperationSpec("target.upload", "target.upload", mutating=True),
    OperationSpec("debugger.state", "debugger.state"),
    OperationSpec("debugger.attach", "debugger.attach"),
    OperationSpec("debugger.launch", "debugger.launch"),
    OperationSpec("debugger.detach", "debugger.detach"),
    OperationSpec("debugger.silence", "debugger.silence"),
    OperationSpec("debugger.terminate", "debugger.terminate"),
    OperationSpec("debugger.continue", "debugger.continue"),
    OperationSpec("debugger.pause", "debugger.pause"),
    OperationSpec("debugger.step.into", "debugger.step.into"),
    OperationSpec("debugger.step.over", "debugger.step.over"),
    OperationSpec("debugger.step.out", "debugger.step.out"),
    OperationSpec("debugger.run.until_return", "debugger.run.until_return"),
    OperationSpec("debugger.run.to", "debugger.run.to"),
    OperationSpec("debugger.breakpoints.set", "debugger.breakpoints.set"),
    OperationSpec("debugger.breakpoints.delete", "debugger.breakpoints.delete"),
    OperationSpec("debugger.breakpoints.list", "debugger.breakpoints.list"),
    OperationSpec("debugger.trace_breakpoints.set", "debugger.trace_breakpoints.set"),
    OperationSpec(
        "debugger.trace_breakpoints.delete", "debugger.trace_breakpoints.delete"
    ),
    OperationSpec("debugger.trace_log.read", "debugger.trace_log.read"),
    OperationSpec("debugger.trace_log.clear", "debugger.trace_log.clear"),
    OperationSpec("debugger.memory.read", "debugger.memory.read"),
    OperationSpec("debugger.memory.write", "debugger.memory.write"),
    OperationSpec("debugger.registers.get", "debugger.registers.get"),
    OperationSpec("debugger.registers.set", "debugger.registers.set"),
    OperationSpec("debugger.registers.list", "debugger.registers.list"),
    OperationSpec("debugger.events.wait", "debugger.events.wait"),
    OperationSpec("debugger.callstack", "debugger.callstack"),
    OperationSpec("debugger.threads", "debugger.threads"),
    OperationSpec("debugger.modules", "debugger.modules"),
    OperationSpec("notebook.log", "notebook.log", mutating=True),
    OperationSpec("notebook.show", "notebook.show"),
    OperationSpec("notebook.refresh", "notebook.refresh"),
    OperationSpec("provider.reload", "provider.reload"),
)

GHIDRA_OPERATIONS = NATIVE_OPERATIONS + (
    OperationSpec("analysis.range", "analysis.range", mutating=True),
    OperationSpec("segments.update", "segments.update", mutating=True),
)

NATIVE_CAPABILITIES = frozenset(
    {
        Capability.LIFECYCLE_OPEN,
        Capability.LIFECYCLE_CREATE,
        Capability.LIFECYCLE_REOPEN,
        Capability.LIFECYCLE_ATTACH,
        Capability.LIFECYCLE_SAVE,
        Capability.LIFECYCLE_CLOSE,
        Capability.ANALYSIS_DECOMPILE,
        Capability.ANALYSIS_DISASSEMBLE,
        Capability.ANALYSIS_XREFS,
        Capability.SYMBOLS_RENAME,
        Capability.COMMENTS_WRITE,
        Capability.FUNCTIONS_CREATE,
        Capability.FUNCTIONS_DELETE,
        "target.info",
        "functions.get",
        "functions.list",
        "callgraph.callers",
        "callgraph.callees",
        "search.functions",
        "search.strings",
        "memory.read",
        "segments.list",
    }
)

IDA_CAPABILITIES = NATIVE_CAPABILITIES | {
    Capability.SCRIPT_PYTHON,
    Capability.TYPES_DEFINE,
    Capability.TYPES_APPLY,
    "functions.prototype.set",
    "locals.rename",
    "locals.type.set",
    "notebook.read",
    "notebook.append",
    "notebook.replace",
    "notebook.clear",
    "analysis.code.create",
    "firmware.micromips.scan",
    "firmware.arm.setup",
    "segments.create",
    "segments.update",
    "target.upload",
    "debugger.state",
    "debugger.attach",
    "debugger.launch",
    "debugger.detach",
    "debugger.silence",
    "debugger.terminate",
    "debugger.continue",
    "debugger.pause",
    "debugger.step.into",
    "debugger.step.over",
    "debugger.step.out",
    "debugger.run.until_return",
    "debugger.run.to",
    "debugger.breakpoints.set",
    "debugger.breakpoints.delete",
    "debugger.breakpoints.list",
    "debugger.trace_breakpoints.set",
    "debugger.trace_breakpoints.delete",
    "debugger.trace_log.read",
    "debugger.trace_log.clear",
    "debugger.memory.read",
    "debugger.memory.write",
    "debugger.registers.get",
    "debugger.registers.set",
    "debugger.registers.list",
    "debugger.events.wait",
    "debugger.callstack",
    "debugger.threads",
    "debugger.modules",
    "notebook.log",
    "notebook.show",
    "notebook.refresh",
    "provider.reload",
}

GHIDRA_CAPABILITIES = NATIVE_CAPABILITIES | {
    Capability.SCRIPT_PYTHON,
    "analysis.range",
    "segments.update",
}

JADX_OPERATIONS = (
    OperationSpec(CommonOperation.TARGET_INFO, "target.info"),
    OperationSpec(CommonOperation.SEARCH_CLASSES, "android.classes.search"),
    OperationSpec(CommonOperation.SEARCH_METHODS, "android.methods.list"),
    OperationSpec(CommonOperation.SEARCH_STRINGS, "search.strings"),
    OperationSpec(CommonOperation.ANALYSIS_DECOMPILE, Capability.ANALYSIS_DECOMPILE),
    OperationSpec(CommonOperation.REFERENCES_TO, Capability.ANALYSIS_XREFS),
    OperationSpec("android.classes.list", "android.classes.list"),
    OperationSpec("android.classes.get", "android.classes.get"),
    OperationSpec("android.resources.list", "android.resources.list"),
    OperationSpec(CommonOperation.ARTIFACT_ENTRIES_LIST, "artifact.entries.list"),
    OperationSpec(
        CommonOperation.ARTIFACT_FILES_EXTRACT,
        "artifact.files.extract",
        mutating=True,
    ),
    OperationSpec(CommonOperation.SOURCE_SEARCH, "source.search"),
    OperationSpec(CommonOperation.SOURCE_PRETTY, "source.pretty"),
    OperationSpec("android.framework.detect", "android.framework.detect"),
    OperationSpec("android.uniapp.inspect", "android.uniapp.inspect"),
)

JADX_CAPABILITIES = frozenset(
    {
        Capability.LIFECYCLE_OPEN,
        Capability.LIFECYCLE_CREATE,
        Capability.LIFECYCLE_ATTACH,
        Capability.LIFECYCLE_CLOSE,
        Capability.ANALYSIS_DECOMPILE,
        Capability.ANALYSIS_XREFS,
        "target.info",
        "search.strings",
        "android.classes.list",
        "android.classes.search",
        "android.classes.get",
        "android.methods.list",
        "android.resources.list",
        "artifact.entries.list",
        "artifact.files.extract",
        "source.search",
        "source.pretty",
        "android.framework.detect",
        "android.uniapp.inspect",
    }
)

JADX_ARTIFACT_CAPABILITIES = frozenset(
    {
        "artifact.entries.list",
        "artifact.files.extract",
        "source.search",
        "source.pretty",
        "android.framework.detect",
        "android.uniapp.inspect",
    }
)


def _error_response(provider: str, response: Any) -> Any:
    if isinstance(response, dict) and response.get("error"):
        value = response["error"]
        code = (
            value
            if isinstance(value, str) and " " not in value
            else "provider_operation_failed"
        )
        raise ReversingMcpError(
            code,
            str(response.get("reason") or value),
            details={"provider": provider, "response": response},
        )
    return response


def _wait_for_registration(reg_dir: str, pid: int, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for registration in discover_instances(reg_dir):
            if registration.get("pid") == pid:
                return registration
        time.sleep(0.2)
    raise ReversingMcpError(
        "session_start_timeout",
        f"Provider process {pid} did not register within {timeout:g} seconds",
        details={"pid": pid, "registration_dir": reg_dir},
    )


def _attach_registration(reg_dir: str, target: str) -> dict[str, Any]:
    registrations = discover_instances(reg_dir)
    if target:
        folded = target.casefold()
        registrations = [
            item
            for item in registrations
            if any(folded in str(value).casefold() for value in item.values())
        ]
    if not registrations:
        raise ReversingMcpError(
            "session_not_found", "No matching local provider bridge is running"
        )
    if len(registrations) > 1 and not target:
        raise ReversingMcpError(
            "ambiguous_session",
            "Multiple provider bridges are running; provide a target selector",
            details={"sessions": registrations},
        )
    return registrations[0]


class LocalBridgeSession(AnalysisSession):
    def __init__(
        self,
        *,
        provider_id: str,
        registration: Mapping[str, Any],
        target_path: str,
        database_path: str,
        capabilities: frozenset[str],
        operations: tuple[OperationSpec, ...],
        endpoint_map: Mapping[str, str],
        owned: bool,
        read_only: bool = False,
    ) -> None:
        super().__init__(
            provider_id=provider_id,
            target_path=target_path,
            database_path=database_path,
            mode=str(registration.get("mode", "attached")),
            capabilities=capabilities,
            operations=operations,
        )
        self._port = int(registration["port"])
        self._endpoint_map = dict(endpoint_map)
        self._owned = owned
        self._read_only = read_only
        self._closed = False
        self._lock = asyncio.Lock()

    def _call(
        self, endpoint: str, body: Mapping[str, Any] | None = None, timeout: float = 60
    ) -> Any:
        if self._closed:
            raise ReversingMcpError(
                "session_closed", "Provider bridge session is closed"
            )
        response = call_remote(
            f"127.0.0.1:{self._port}",
            endpoint,
            dict(body) if body is not None else None,
            timeout=timeout,
        )
        return _error_response(self.provider_id, response)

    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        endpoint = self._endpoint_map.get(operation)
        if endpoint is None:
            raise ReversingMcpError(
                "unsupported_operation", f"Unsupported operation: {operation}"
            )
        body = self._translate(operation, dict(arguments))
        request_body = None if operation in _GET_OPERATIONS else body
        async with self._lock:
            return await asyncio.to_thread(self._call, endpoint, request_body)

    async def save(self) -> Any:
        if self._read_only:
            raise ReversingMcpError(
                "unsupported_capability", "This provider is read-only"
            )
        async with self._lock:
            return await asyncio.to_thread(self._call, self._save_endpoint(), {}, 120)

    async def close(self, *, save: bool = True) -> Any:
        if not self._owned:
            raise ReversingMcpError(
                "unsupported_capability",
                "Attached GUI sessions remain user-owned and cannot be closed",
            )
        async with self._lock:
            endpoint = "/close_session" if self.provider_id == "ida" else "/close"
            result = await asyncio.to_thread(self._call, endpoint, {"save": save}, 30)
            self._closed = True
            return result

    def _save_endpoint(self) -> str:
        return "/save_database" if self.provider_id == "ida" else "/save"

    @staticmethod
    def _translate(operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        body = dict(arguments)
        function = body.get("function")
        if function is not None and operation in _FUNCTION_SELECTOR_OPERATIONS:
            body.pop("function")
            key = (
                "address"
                if isinstance(function, int) or str(function).startswith("0x")
                else "name"
            )
            body.setdefault(key, function)
        if operation == CommonOperation.FUNCTIONS_LIST:
            body.setdefault("pattern", "")
        if operation in {
            CommonOperation.SEARCH_FUNCTIONS,
            CommonOperation.SEARCH_STRINGS,
        }:
            body["pattern"] = body.pop("query", body.get("pattern", ""))
        if operation == CommonOperation.COMMENTS_WRITE:
            body.setdefault("repeatable", False)
        if operation == CommonOperation.MEMORY_READ:
            body.setdefault("size", 256)
        if operation == CommonOperation.TYPES_DEFINE and "declaration" in body:
            body["decl"] = body.pop("declaration")
        if operation == CommonOperation.NOTEBOOK_APPEND and "content" in body:
            body["text"] = body.pop("content")
        return body


_GET_OPERATIONS = {
    CommonOperation.TARGET_INFO,
    CommonOperation.SEGMENTS_LIST,
}

_FUNCTION_SELECTOR_OPERATIONS = {
    CommonOperation.FUNCTIONS_GET,
    CommonOperation.ANALYSIS_DECOMPILE,
    CommonOperation.ANALYSIS_DISASSEMBLE,
    CommonOperation.REFERENCES_TO,
    CommonOperation.REFERENCES_FROM,
    CommonOperation.CALLGRAPH_CALLERS,
    CommonOperation.CALLGRAPH_CALLEES,
    CommonOperation.SYMBOLS_RENAME,
    CommonOperation.COMMENTS_WRITE,
    CommonOperation.FUNCTIONS_CREATE,
    CommonOperation.FUNCTIONS_DELETE,
    CommonOperation.TYPES_APPLY,
    CommonOperation.FUNCTIONS_SET_PROTOTYPE,
}


_NATIVE_ENDPOINTS = {
    CommonOperation.TARGET_INFO: "/info",
    CommonOperation.FUNCTIONS_GET: "/function",
    CommonOperation.FUNCTIONS_LIST: "/search_functions",
    CommonOperation.ANALYSIS_DECOMPILE: "/decompile",
    CommonOperation.ANALYSIS_DISASSEMBLE: "/disassemble",
    CommonOperation.REFERENCES_TO: "/xrefs_to",
    CommonOperation.REFERENCES_FROM: "/xrefs_from",
    CommonOperation.CALLGRAPH_CALLERS: "/callers",
    CommonOperation.CALLGRAPH_CALLEES: "/callees",
    CommonOperation.SEARCH_FUNCTIONS: "/search_functions",
    CommonOperation.SEARCH_STRINGS: "/search_strings",
    CommonOperation.MEMORY_READ: "/bytes",
    CommonOperation.SEGMENTS_LIST: "/segments",
    CommonOperation.SYMBOLS_RENAME: "/rename",
    CommonOperation.COMMENTS_WRITE: "/comment",
    CommonOperation.FUNCTIONS_CREATE: "/create_function",
    CommonOperation.FUNCTIONS_DELETE: "/delete_function",
}

_GHIDRA_ENDPOINTS = {
    **_NATIVE_ENDPOINTS,
    "analysis.range": "/analyze_range",
    "segments.update": "/set_segment_perms",
}

_IDA_ENDPOINTS = {
    **_NATIVE_ENDPOINTS,
    CommonOperation.TYPES_DEFINE: "/define_type",
    CommonOperation.TYPES_APPLY: "/apply_type",
    CommonOperation.FUNCTIONS_SET_PROTOTYPE: "/set_function_prototype",
    CommonOperation.LOCALS_RENAME: "/rename_local_var",
    CommonOperation.LOCALS_SET_TYPE: "/set_local_var_type",
    CommonOperation.NOTEBOOK_READ: "/scratch_read",
    CommonOperation.NOTEBOOK_APPEND: "/scratch_append",
    CommonOperation.NOTEBOOK_REPLACE: "/scratch_replace",
    CommonOperation.NOTEBOOK_CLEAR: "/scratch_clear",
    "analysis.code.create": "/make_code",
    "firmware.micromips.scan": "/find_micromips_prologues",
    "firmware.arm.setup": "/execute_python",
    "segments.create": "/add_segment",
    "segments.update": "/set_segment_attrs",
    "target.upload": "/upload",
    "debugger.state": "/dbg_state",
    "debugger.attach": "/dbg_attach",
    "debugger.launch": "/dbg_launch",
    "debugger.detach": "/dbg_detach",
    "debugger.silence": "/dbg_silence",
    "debugger.terminate": "/dbg_terminate",
    "debugger.continue": "/dbg_continue",
    "debugger.pause": "/dbg_pause",
    "debugger.step.into": "/dbg_step_into",
    "debugger.step.over": "/dbg_step_over",
    "debugger.step.out": "/dbg_step_out",
    "debugger.run.until_return": "/dbg_run_until_ret",
    "debugger.run.to": "/dbg_run_to",
    "debugger.breakpoints.set": "/dbg_set_breakpoint",
    "debugger.breakpoints.delete": "/dbg_del_breakpoint",
    "debugger.breakpoints.list": "/dbg_list_breakpoints",
    "debugger.trace_breakpoints.set": "/dbg_set_trace_bp",
    "debugger.trace_breakpoints.delete": "/dbg_clear_trace_bp",
    "debugger.trace_log.read": "/dbg_get_trace_log",
    "debugger.trace_log.clear": "/dbg_clear_trace_log",
    "debugger.memory.read": "/dbg_read_memory",
    "debugger.memory.write": "/dbg_write_memory",
    "debugger.registers.get": "/dbg_get_reg",
    "debugger.registers.set": "/dbg_set_reg",
    "debugger.registers.list": "/dbg_get_regs",
    "debugger.events.wait": "/dbg_wait_event",
    "debugger.callstack": "/dbg_callstack",
    "debugger.threads": "/dbg_threads",
    "debugger.modules": "/dbg_modules",
    "notebook.log": "/scratch_log",
    "notebook.show": "/scratch_show",
    "notebook.refresh": "/scratch_refresh",
    "provider.reload": "/reload_plugin",
}


class IdaSession(LocalBridgeSession):
    @staticmethod
    def _translate(operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        body = LocalBridgeSession._translate(operation, arguments)
        if operation == "segments.create" and "sclass" in body:
            body["class"] = body.pop("sclass")
        elif operation == "segments.update" and "sclass" in body:
            body["class"] = body.pop("sclass")
        elif operation == "target.upload" and "local_path" in body:
            local_path = Path(str(body.pop("local_path"))).expanduser().resolve()
            body.setdefault("filename", body.pop("remote_filename", local_path.name))
            body["data"] = base64.b64encode(local_path.read_bytes()).decode("ascii")
        elif operation == "firmware.arm.setup":
            body = {
                "code": build_arm_setup_script(
                    base=str(body.get("base", "")),
                    thumb=bool(body.get("thumb", True)),
                    bits=int(body.get("bits", 32)),
                    seed_prologues=bool(body.get("seed_prologues", True)),
                    analyze=bool(body.get("analyze", True)),
                ),
                "save_after": False,
            }
        return body

    async def run_script(
        self, *, language: str, source: str, arguments: Mapping[str, Any]
    ) -> Any:
        if language != "python":
            return await super().run_script(
                language=language, source=source, arguments=arguments
            )
        argument_json = json.dumps(dict(arguments), separators=(",", ":"))
        wrapped_source = (
            "import json as __ida_mcp_json\n"
            f"args = __ida_mcp_json.loads({argument_json!r})\n"
            f"{source}"
        )
        async with self._lock:
            return await asyncio.to_thread(
                self._call,
                "/execute_python",
                {"code": wrapped_source, "save_after": False},
                120,
            )


class IdaBackend(AnalysisBackend):
    def __init__(self) -> None:
        super().__init__(
            provider_id="ida",
            display_name="IDA Pro",
            capabilities=IDA_CAPABILITIES,
            operations=IDA_OPERATIONS,
        )

    async def open(self, request: SessionRequest) -> AnalysisSession:
        reg_dir = os.path.expanduser("~/.ida_mcp")
        if request.lifecycle == LifecycleAction.ATTACH:
            registration = await asyncio.to_thread(
                _attach_registration, reg_dir, request.target_path
            )
            owned = False
        else:
            if request.mode not in {"headless", ""}:
                raise ReversingMcpError(
                    "unsupported_mode", "Use attach for an existing IDA GUI session"
                )
            from ida.spawn_server import _find_ida, _spawn

            executable = str(request.options.get("ida_path", "")) or _find_ida(
                headless=True
            )
            if not executable:
                raise ReversingMcpError(
                    "dependency_missing", "The idat64 executable was not found"
                )
            source = (
                request.target_path
                if request.lifecycle != LifecycleAction.REOPEN
                else ""
            )
            database = request.database_path
            if (
                request.lifecycle == LifecycleAction.REOPEN
                and not database
                and request.target_path.lower().endswith((".i64", ".idb"))
            ):
                database = request.target_path
            if request.lifecycle == LifecycleAction.CREATE:
                if not source:
                    raise ReversingMcpError(
                        "invalid_request", "IDA create requires target_path"
                    )
                create_database = (
                    Path(database) if database else Path(source).with_suffix(".i64")
                )
                if create_database.exists():
                    raise ReversingMcpError(
                        "database_exists",
                        f"IDA database already exists: {create_database}",
                    )
            if (
                request.lifecycle == LifecycleAction.REOPEN
                and not Path(database).is_file()
            ):
                raise ReversingMcpError(
                    "database_not_found",
                    f"IDA database does not exist: {database}",
                )
            timeout = float(request.options.get("timeout", 300))
            result = await asyncio.to_thread(
                _spawn,
                executable,
                source_path=source,
                database_path=database,
                headless=True,
                bind_host="127.0.0.1",
                autosave_policy=str(
                    request.options.get("autosave_policy", "after_mutation")
                ),
                allow_python=bool(request.options.get("allow_python", False)),
                wait_timeout=timeout,
            )
            registration = _error_response("ida", result)
            if not registration.get("ready", False):
                raise ReversingMcpError(
                    "session_start_timeout",
                    str(registration.get("warning", "IDA bridge did not become ready")),
                    details={
                        "pid": registration.get("pid"),
                        "database_path": registration.get("database_path"),
                        "process_left_running": True,
                    },
                )
            owned = True
        session_capabilities = set(IDA_CAPABILITIES)
        if Capability.SCRIPT_PYTHON not in registration.get("capabilities", ()):
            session_capabilities.discard(Capability.SCRIPT_PYTHON)
        if not owned and not registration.get("owned", False):
            session_capabilities.discard(Capability.LIFECYCLE_CLOSE)
        return IdaSession(
            provider_id="ida",
            registration=registration,
            target_path=str(registration.get("source_path", request.target_path)),
            database_path=str(registration.get("database_path", request.database_path)),
            capabilities=frozenset(session_capabilities),
            operations=IDA_OPERATIONS,
            endpoint_map=_IDA_ENDPOINTS,
            owned=owned or bool(registration.get("owned", False)),
        )


class GhidraSession(LocalBridgeSession):
    async def run_script(
        self, *, language: str, source: str, arguments: Mapping[str, Any]
    ) -> Any:
        if language != "python":
            return await super().run_script(
                language=language, source=source, arguments=arguments
            )
        import json

        argument_json = json.dumps(dict(arguments))
        prefix = f"import json\narguments = json.loads({argument_json!r})\n"
        async with self._lock:
            return await asyncio.to_thread(
                self._call,
                "/exec_script",
                {"code": prefix + source, "commit": "true"},
                600,
            )


class GhidraBackend(AnalysisBackend):
    def __init__(self) -> None:
        super().__init__(
            provider_id="ghidra",
            display_name="Ghidra",
            capabilities=GHIDRA_CAPABILITIES,
            operations=GHIDRA_OPERATIONS,
        )

    async def open(self, request: SessionRequest) -> AnalysisSession:
        reg_dir = os.path.expanduser("~/.ghidra_mcp")
        if request.lifecycle == LifecycleAction.ATTACH:
            registration = await asyncio.to_thread(
                _attach_registration, reg_dir, request.target_path
            )
            owned = False
        else:
            from ghidra.session import create_headless_session, open_headless_session

            def registrations() -> list[dict]:
                return discover_instances(reg_dir)

            options = dict(request.options)
            if request.lifecycle == LifecycleAction.REOPEN:
                result = await asyncio.to_thread(
                    open_headless_session,
                    str(options.get("project_dir", Path(request.database_path).parent)),
                    str(options.get("project_name", Path(request.database_path).name)),
                    str(options.get("program_name", Path(request.target_path).name)),
                    registrations=registrations,
                    analyze_headless=str(options.get("analyze_headless", "")),
                    timeout=float(options.get("timeout", 300)),
                )
            else:
                result = await asyncio.to_thread(
                    create_headless_session,
                    request.target_path,
                    registrations=registrations,
                    analyze_headless=str(options.get("analyze_headless", "")),
                    project_dir=str(options.get("project_dir", "")),
                    project_name=str(options.get("project_name", "")),
                    timeout=float(options.get("timeout", 300)),
                )
            registration = _error_response("ghidra", result)
            owned = True
        database = request.database_path or str(registration.get("project_dir", ""))
        session_capabilities = set(
            (NATIVE_CAPABILITIES | {"analysis.range", "segments.update"})
            if owned
            else GHIDRA_CAPABILITIES
        )
        if not owned and not registration.get("owned", False):
            session_capabilities.discard(Capability.LIFECYCLE_CLOSE)
        return GhidraSession(
            provider_id="ghidra",
            registration=registration,
            target_path=request.target_path
            or str(registration.get("program_path", "")),
            database_path=database,
            capabilities=frozenset(session_capabilities),
            operations=GHIDRA_OPERATIONS,
            endpoint_map=_GHIDRA_ENDPOINTS,
            owned=owned or bool(registration.get("owned", False)),
        )


_JADX_ENDPOINTS = {
    CommonOperation.TARGET_INFO: "/info",
    CommonOperation.SEARCH_CLASSES: "/search_classes",
    CommonOperation.SEARCH_METHODS: "/list_methods",
    CommonOperation.SEARCH_STRINGS: "/search_strings",
    CommonOperation.ANALYSIS_DECOMPILE: "/decompile_method",
    CommonOperation.REFERENCES_TO: "/xrefs_to",
    "android.classes.list": "/list_classes",
    "android.classes.get": "/get_class",
    "android.resources.list": "/list_resources",
}


class JadxSession(LocalBridgeSession):
    def __init__(
        self, *args, artifact: AndroidArtifact | None = None, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self._artifact = artifact

    def _require_artifact(self) -> AndroidArtifact:
        if self._artifact is None:
            raise ReversingMcpError(
                "unsupported_capability",
                "Artifact operations require an APK, XAPK, APKS, AAB, or ZIP target",
            )
        return self._artifact

    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        artifact_routes = {
            CommonOperation.ARTIFACT_ENTRIES_LIST: "list_entries",
            CommonOperation.ARTIFACT_FILES_EXTRACT: "extract",
            CommonOperation.SOURCE_SEARCH: "javascript_search",
            CommonOperation.SOURCE_PRETTY: "javascript_source",
        }
        route = artifact_routes.get(operation)
        if route:
            artifact = self._require_artifact()
            return await asyncio.to_thread(getattr(artifact, route), arguments)
        if operation == "android.framework.detect":
            artifact = self._require_artifact()
            return await asyncio.to_thread(artifact.frameworks_detect)
        if operation == "android.uniapp.inspect":
            artifact = self._require_artifact()
            result = await asyncio.to_thread(artifact.dcloud_inspect)
            try:
                classes = await super().invoke(
                    CommonOperation.SEARCH_CLASSES,
                    {"query": "io.dcloud", "limit": 25},
                )
            except ReversingMcpError as error:
                result["class_detection"] = {
                    "available": False,
                    "reason": error.message,
                }
            else:
                candidates = (
                    classes.get("classes", []) if isinstance(classes, dict) else []
                )
                result["class_detection"] = {
                    "available": True,
                    "matches": candidates,
                }
                if candidates:
                    result["detected"] = True
                    result["framework"] = "uni-app/dcloud"
            return result
        return await super().invoke(operation, arguments)

    async def close(self, *, save: bool = True) -> Any:
        """Close the owned read-only JVM without implying a save operation."""
        del save
        try:
            return await super().close(save=False)
        finally:
            if self._artifact is not None:
                await asyncio.to_thread(self._artifact.close)

    @staticmethod
    def _translate(operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        body = dict(arguments)
        if operation in {
            CommonOperation.SEARCH_CLASSES,
            CommonOperation.SEARCH_STRINGS,
        }:
            body["pattern"] = body.pop("query", body.get("pattern", ""))
        if operation == CommonOperation.SEARCH_METHODS:
            body["class"] = body.pop("class_name", body.get("class", ""))
        if operation == CommonOperation.ANALYSIS_DECOMPILE:
            body["class"] = body.pop("class_name", body.get("class", ""))
        if operation == CommonOperation.REFERENCES_TO:
            body["class"] = body.pop("class_name", body.get("class", ""))
        return body


class JadxBackend(AnalysisBackend):
    def __init__(self) -> None:
        super().__init__(
            provider_id="jadx",
            display_name="JADX",
            capabilities=JADX_CAPABILITIES,
            operations=JADX_OPERATIONS,
        )

    async def open(self, request: SessionRequest) -> AnalysisSession:
        reg_dir = os.path.expanduser("~/.jadx_mcp")
        artifact: AndroidArtifact | None = None
        if request.lifecycle == LifecycleAction.ATTACH:
            registration = await asyncio.to_thread(
                _attach_registration, reg_dir, request.target_path
            )
            owned = False
        else:
            from jadx.session import start_bridge

            options = dict(request.options)
            target = request.target_path
            artifact_suffix = Path(target).suffix.lower()
            if artifact_suffix in {".apk", ".xapk", ".apks", ".aab", ".zip"}:
                artifact = AndroidArtifact(target)
                if artifact_suffix != ".aab":
                    target = str(await asyncio.to_thread(artifact.primary_apk))
            try:
                result = await asyncio.to_thread(
                    start_bridge,
                    target,
                    bridge_jar=str(options.get("bridge_jar", "")),
                    java_command=str(options.get("java_command", "java")),
                    timeout=float(options.get("timeout", 120)),
                    registrations=lambda: discover_instances(reg_dir),
                )
                registration = _error_response("jadx", result)
            except Exception:
                if artifact is not None:
                    artifact.close()
                raise
            owned = True
        session_capabilities = set(JADX_CAPABILITIES)
        if artifact is None:
            session_capabilities -= JADX_ARTIFACT_CAPABILITIES
        if not owned and not registration.get("owned", False):
            session_capabilities.discard(Capability.LIFECYCLE_CLOSE)
        return JadxSession(
            provider_id="jadx",
            registration=registration,
            target_path=request.target_path or str(registration.get("jar_path", "")),
            database_path="",
            capabilities=frozenset(session_capabilities),
            operations=JADX_OPERATIONS,
            endpoint_map=_JADX_ENDPOINTS,
            owned=owned or bool(registration.get("owned", False)),
            read_only=True,
            artifact=artifact,
        )
