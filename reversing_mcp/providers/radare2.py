"""Optional persistent radare2 provider implemented with r2pipe."""

from __future__ import annotations

import asyncio
import importlib
import re
from pathlib import Path
from typing import Any, Mapping

from ..backends import AnalysisBackend, AnalysisSession
from ..errors import ReversingMcpError
from ..models import (
    Capability,
    CommonOperation,
    LifecycleAction,
    OperationSpec,
    SessionRequest,
)

_PROJECT_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")

OPERATIONS = (
    OperationSpec(CommonOperation.TARGET_INFO, "target.info"),
    OperationSpec(CommonOperation.FUNCTIONS_LIST, "functions.list"),
    OperationSpec(CommonOperation.FUNCTIONS_GET, "functions.get"),
    OperationSpec(
        CommonOperation.ANALYSIS_DISASSEMBLE, Capability.ANALYSIS_DISASSEMBLE
    ),
    OperationSpec(CommonOperation.REFERENCES_TO, Capability.ANALYSIS_XREFS),
    OperationSpec(CommonOperation.REFERENCES_FROM, Capability.ANALYSIS_XREFS),
    OperationSpec(CommonOperation.SEARCH_STRINGS, "search.strings"),
    OperationSpec(CommonOperation.MEMORY_READ, "memory.read"),
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

CAPABILITIES = frozenset(
    {
        Capability.LIFECYCLE_OPEN,
        Capability.LIFECYCLE_CREATE,
        Capability.LIFECYCLE_REOPEN,
        Capability.LIFECYCLE_SAVE,
        Capability.LIFECYCLE_CLOSE,
        Capability.ANALYSIS_DISASSEMBLE,
        Capability.ANALYSIS_XREFS,
        Capability.SYMBOLS_RENAME,
        Capability.COMMENTS_WRITE,
        Capability.FUNCTIONS_CREATE,
        Capability.FUNCTIONS_DELETE,
        Capability.SCRIPT_PYTHON,
        "target.info",
        "functions.list",
        "functions.get",
        "search.strings",
        "memory.read",
    }
)


def _require(arguments: Mapping[str, Any], name: str) -> Any:
    value = arguments.get(name)
    if value is None or value == "":
        raise ReversingMcpError("invalid_request", f"Missing required argument: {name}")
    return value


def _address(value: Any) -> int:
    return value if isinstance(value, int) else int(str(value), 0)


def _project_name(value: str) -> str:
    name = Path(value).name
    if not name or not _PROJECT_NAME.fullmatch(name):
        raise ReversingMcpError(
            "invalid_project_name",
            "radare2 project names may contain only letters, digits, dot, dash, "
            "and underscore",
        )
    return name


class Radare2Backend(AnalysisBackend):
    def __init__(self) -> None:
        super().__init__(
            provider_id="radare2",
            display_name="radare2",
            capabilities=CAPABILITIES,
            operations=OPERATIONS,
        )

    async def open(self, request: SessionRequest) -> AnalysisSession:
        if request.mode not in {"headless", ""}:
            raise ReversingMcpError(
                "unsupported_mode",
                "radare2's unified adapter supports headless sessions",
            )
        try:
            r2pipe = importlib.import_module("r2pipe")
        except ImportError as error:
            raise ReversingMcpError(
                "dependency_missing",
                "r2pipe is not installed in this interpreter",
                details={"provider": self.provider_id, "dependency": "r2pipe"},
            ) from error
        return await asyncio.to_thread(self._open_sync, r2pipe, request)

    @staticmethod
    def _open_sync(r2pipe: Any, request: SessionRequest) -> AnalysisSession:
        if request.lifecycle == LifecycleAction.REOPEN:
            project = _project_name(request.database_path)
            target = request.target_path or "-"
        else:
            target = request.target_path
            if not target:
                raise ReversingMcpError("invalid_request", "A target path is required")
            target_path = Path(target).expanduser().resolve()
            if not target_path.is_file():
                raise ReversingMcpError(
                    "target_not_found", f"radare2 target does not exist: {target_path}"
                )
            target = str(target_path)
            project = (
                _project_name(request.database_path) if request.database_path else ""
            )

        pipe = r2pipe.open(target, flags=["-2"])
        try:
            if request.lifecycle == LifecycleAction.REOPEN:
                response = pipe.cmd(f"Po {project}")
                if "Cannot" in response or "error" in response.lower():
                    raise ReversingMcpError(
                        "open_failed",
                        response.strip() or f"Could not open project {project}",
                    )
            else:
                analysis = str(request.options.get("analysis", "aaa"))
                if analysis not in {"aa", "aaa", "aaaa"}:
                    raise ReversingMcpError(
                        "invalid_request", "analysis must be aa, aaa, or aaaa"
                    )
                pipe.cmd(analysis)
                if request.lifecycle == LifecycleAction.CREATE:
                    project = project or _project_name(Path(target).stem)
                    pipe.cmd(f"Ps {project}")
        except Exception:
            pipe.quit()
            raise
        return Radare2Session(pipe, target_path=target, database_path=project)


class Radare2Session(AnalysisSession):
    def __init__(self, pipe: Any, *, target_path: str, database_path: str) -> None:
        super().__init__(
            provider_id="radare2",
            target_path=target_path,
            database_path=database_path,
            mode="headless",
            capabilities=CAPABILITIES,
            operations=OPERATIONS,
        )
        self._pipe = pipe
        self._lock = asyncio.Lock()
        self._closed = False

    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        async with self._lock:
            return await asyncio.to_thread(
                self._invoke_sync, operation, dict(arguments)
            )

    async def save(self) -> Any:
        async with self._lock:
            return await asyncio.to_thread(self._save_sync)

    async def close(self, *, save: bool = True) -> Any:
        async with self._lock:
            if self._closed:
                return {"closed": True, "already_closed": True}
            if save:
                self._save_sync()
            await asyncio.to_thread(self._pipe.quit)
            self._closed = True
            return {"closed": True, "saved": save}

    async def run_script(
        self, *, language: str, source: str, arguments: Mapping[str, Any]
    ) -> Any:
        if language != "python":
            return await super().run_script(
                language=language, source=source, arguments=arguments
            )
        async with self._lock:
            return await asyncio.to_thread(self._run_python, source, dict(arguments))

    def _ensure_open(self) -> None:
        if self._closed:
            raise ReversingMcpError("session_closed", "radare2 session is closed")

    def _cmdj(self, command: str) -> Any:
        result = self._pipe.cmdj(command)
        return result if result is not None else []

    def _save_sync(self) -> dict[str, Any]:
        self._ensure_open()
        if not self.database_path:
            raise ReversingMcpError(
                "database_required",
                "This session has no project; use create_session with database_path",
            )
        response = self._pipe.cmd(f"Ps {self.database_path}")
        if "error" in response.lower():
            raise ReversingMcpError("save_failed", response.strip())
        return {"saved": True, "project": self.database_path}

    def _invoke_sync(self, operation: str, arguments: dict[str, Any]) -> Any:
        self._ensure_open()
        if operation == CommonOperation.TARGET_INFO:
            return self._cmdj("ij")
        if operation == CommonOperation.FUNCTIONS_LIST:
            offset = int(arguments.get("offset", 0))
            limit = min(int(arguments.get("limit", 100)), 1000)
            return self._cmdj("aflj")[offset : offset + limit]
        if operation == CommonOperation.FUNCTIONS_GET:
            address = _address(_require(arguments, "function"))
            result = self._cmdj(f"afij @ {address}")
            if not result:
                raise ReversingMcpError(
                    "function_not_found", f"No function at {address:#x}"
                )
            return result[0]
        if operation == CommonOperation.ANALYSIS_DISASSEMBLE:
            address = _address(_require(arguments, "function"))
            return self._cmdj(f"pdfj @ {address}")
        if operation == CommonOperation.REFERENCES_TO:
            return self._cmdj(f"axtj @ {_address(_require(arguments, 'address'))}")
        if operation == CommonOperation.REFERENCES_FROM:
            return self._cmdj(f"axfj @ {_address(_require(arguments, 'address'))}")
        if operation == CommonOperation.SEARCH_STRINGS:
            query = str(arguments.get("query", "")).casefold()
            return [
                item
                for item in self._cmdj("izzj")
                if query in str(item.get("string", "")).casefold()
            ]
        if operation == CommonOperation.MEMORY_READ:
            address = _address(_require(arguments, "address"))
            size = int(_require(arguments, "size"))
            return {
                "address": address,
                "bytes": bytes(self._cmdj(f"pxj {size} @ {address}")).hex(),
            }
        if operation == CommonOperation.SYMBOLS_RENAME:
            address = _address(_require(arguments, "function"))
            name = str(_require(arguments, "name"))
            if not _PROJECT_NAME.fullmatch(name):
                raise ReversingMcpError(
                    "invalid_name", "Function name contains unsafe characters"
                )
            self._pipe.cmd(f"afn {name} @ {address}")
            return {"address": address, "name": name}
        if operation == CommonOperation.COMMENTS_WRITE:
            import base64

            address = _address(_require(arguments, "address"))
            comment = str(_require(arguments, "comment"))
            encoded = base64.b64encode(comment.encode()).decode()
            self._pipe.cmd(f"CCu base64:{encoded} @ {address}")
            return {"address": address, "comment": comment}
        if operation == CommonOperation.FUNCTIONS_CREATE:
            address = _address(_require(arguments, "address"))
            self._pipe.cmd(f"af @ {address}")
            return {"address": address, "created": True}
        if operation == CommonOperation.FUNCTIONS_DELETE:
            address = _address(_require(arguments, "function"))
            self._pipe.cmd(f"af- @ {address}")
            return {"address": address, "deleted": True}
        raise ReversingMcpError(
            "unsupported_operation", f"Unsupported operation: {operation}"
        )

    def _run_python(self, source: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self._ensure_open()
        namespace: dict[str, Any] = {
            "r2": self._pipe,
            "arguments": arguments,
            "result": None,
        }
        exec(compile(source, "<reversing-mcp-radare2>", "exec"), namespace, namespace)
        return {"result": namespace.get("result")}
