"""Optional Binary Ninja headless provider.

The SDK is imported lazily so the unified server remains usable on machines
without Binary Ninja.  All SDK interaction is serialized because a BinaryView
is stateful and its analysis APIs are synchronous.
"""

from __future__ import annotations

import asyncio
import importlib
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


OPERATIONS = (
    OperationSpec(CommonOperation.TARGET_INFO, "target.info"),
    OperationSpec(CommonOperation.FUNCTIONS_LIST, "functions.list"),
    OperationSpec(CommonOperation.FUNCTIONS_GET, "functions.get"),
    OperationSpec(CommonOperation.ANALYSIS_DECOMPILE, Capability.ANALYSIS_DECOMPILE),
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
    OperationSpec(CommonOperation.TYPES_DEFINE, Capability.TYPES_DEFINE, mutating=True),
    OperationSpec(CommonOperation.TYPES_APPLY, Capability.TYPES_APPLY, mutating=True),
)

CAPABILITIES = frozenset(
    {
        Capability.LIFECYCLE_OPEN,
        Capability.LIFECYCLE_CREATE,
        Capability.LIFECYCLE_REOPEN,
        Capability.LIFECYCLE_SAVE,
        Capability.LIFECYCLE_CLOSE,
        Capability.ANALYSIS_DECOMPILE,
        Capability.ANALYSIS_DISASSEMBLE,
        Capability.ANALYSIS_XREFS,
        Capability.SYMBOLS_RENAME,
        Capability.COMMENTS_WRITE,
        Capability.FUNCTIONS_CREATE,
        Capability.FUNCTIONS_DELETE,
        Capability.TYPES_DEFINE,
        Capability.TYPES_APPLY,
        Capability.SCRIPT_PYTHON,
        "target.info",
        "functions.list",
        "functions.get",
        "search.strings",
        "memory.read",
    }
)


def _address(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def _require(arguments: Mapping[str, Any], name: str) -> Any:
    value = arguments.get(name)
    if value is None or value == "":
        raise ReversingMcpError("invalid_request", f"Missing required argument: {name}")
    return value


class BinaryNinjaBackend(AnalysisBackend):
    """Create persistent ``.bndb`` sessions using the Binary Ninja Python API."""

    def __init__(self) -> None:
        super().__init__(
            provider_id="binary_ninja",
            display_name="Binary Ninja",
            capabilities=CAPABILITIES,
            operations=OPERATIONS,
        )

    async def open(self, request: SessionRequest) -> AnalysisSession:
        if request.mode not in {"headless", ""}:
            raise ReversingMcpError(
                "unsupported_mode",
                "Binary Ninja's unified adapter currently supports headless sessions",
                details={"mode": request.mode},
            )
        try:
            binaryninja = importlib.import_module("binaryninja")
        except ImportError as error:
            raise ReversingMcpError(
                "dependency_missing",
                "Binary Ninja's Python module is not installed in this interpreter",
                details={"provider": self.provider_id, "dependency": "binaryninja"},
            ) from error

        return await asyncio.to_thread(self._open_sync, binaryninja, request)

    @staticmethod
    def _open_sync(binaryninja: Any, request: SessionRequest) -> AnalysisSession:
        source = (
            request.database_path
            if request.lifecycle == LifecycleAction.REOPEN
            else request.target_path
        )
        if not source:
            raise ReversingMcpError(
                "invalid_request", "A target or database path is required"
            )
        source_path = Path(source).expanduser().resolve()
        if not source_path.is_file():
            raise ReversingMcpError(
                "target_not_found", f"Binary Ninja target does not exist: {source_path}"
            )

        view = binaryninja.load(str(source_path))
        if view is None:
            raise ReversingMcpError(
                "open_failed", f"Binary Ninja could not load {source_path}"
            )
        view.update_analysis_and_wait()

        database_path = request.database_path
        if request.lifecycle == LifecycleAction.CREATE:
            database_path = database_path or str(
                source_path.with_suffix(source_path.suffix + ".bndb")
            )
            database_path = str(Path(database_path).expanduser().resolve())
            if not view.create_database(database_path):
                view.file.close()
                raise ReversingMcpError(
                    "save_failed",
                    f"Binary Ninja could not create database {database_path}",
                )
        elif source_path.suffix.lower() == ".bndb":
            database_path = str(source_path)

        return BinaryNinjaSession(
            binaryninja,
            view,
            target_path=str(
                source_path if source_path.suffix.lower() != ".bndb" else ""
            ),
            database_path=database_path,
        )


class BinaryNinjaSession(AnalysisSession):
    def __init__(
        self, binaryninja: Any, view: Any, *, target_path: str, database_path: str
    ) -> None:
        super().__init__(
            provider_id="binary_ninja",
            target_path=target_path,
            database_path=database_path,
            mode="headless",
            capabilities=CAPABILITIES,
            operations=OPERATIONS,
        )
        self._bn = binaryninja
        self._view = view
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
            self._view.file.close()
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
            raise ReversingMcpError("session_closed", "Binary Ninja session is closed")

    def _save_sync(self) -> dict[str, Any]:
        self._ensure_open()
        if not self.database_path:
            raise ReversingMcpError(
                "database_required",
                "This view has no persistent database; create a session with "
                "database_path first",
            )
        saved = bool(self._view.save_auto_snapshot())
        if not saved:
            raise ReversingMcpError(
                "save_failed", "Binary Ninja failed to save an auto snapshot"
            )
        return {"saved": True, "database_path": self.database_path}

    def _function(self, value: Any) -> Any:
        if isinstance(value, str) and not value.startswith(("0x", "0X")):
            matches = self._view.get_functions_by_name(value)
            if matches:
                return matches[0]
        address = _address(value)
        function = self._view.get_function_at(address)
        if function is None:
            functions = self._view.get_functions_containing(address)
            function = functions[0] if functions else None
        if function is None:
            raise ReversingMcpError(
                "function_not_found", f"No function at {address:#x}"
            )
        return function

    @staticmethod
    def _function_dict(function: Any) -> dict[str, Any]:
        return {
            "address": function.start,
            "name": function.name,
            "size": max(0, function.highest_address - function.start),
        }

    def _invoke_sync(self, operation: str, arguments: dict[str, Any]) -> Any:
        self._ensure_open()
        if operation == CommonOperation.TARGET_INFO:
            return {
                "filename": self._view.file.filename,
                "platform": str(self._view.platform),
                "architecture": str(self._view.arch),
                "entry_point": self._view.entry_point,
                "length": len(self._view),
            }
        if operation == CommonOperation.FUNCTIONS_LIST:
            offset = int(arguments.get("offset", 0))
            limit = min(int(arguments.get("limit", 100)), 1000)
            return [
                self._function_dict(item)
                for item in self._view.functions[offset : offset + limit]
            ]
        if operation == CommonOperation.FUNCTIONS_GET:
            return self._function_dict(self._function(_require(arguments, "function")))
        if operation == CommonOperation.ANALYSIS_DECOMPILE:
            function = self._function(_require(arguments, "function"))
            lines = (
                function.hlil.root.lines if function.hlil and function.hlil.root else []
            )
            return {
                "address": function.start,
                "text": "\n".join(str(line) for line in lines),
            }
        if operation == CommonOperation.ANALYSIS_DISASSEMBLE:
            function = self._function(_require(arguments, "function"))
            return {
                "address": function.start,
                "lines": [
                    {
                        "address": address,
                        "text": "".join(str(token) for token in tokens),
                    }
                    for tokens, address in function.instructions
                ],
            }
        if operation in {
            CommonOperation.REFERENCES_TO,
            CommonOperation.REFERENCES_FROM,
        }:
            address = _address(_require(arguments, "address"))
            refs = (
                self._view.get_code_refs(address)
                if operation == CommonOperation.REFERENCES_TO
                else self._view.get_code_refs_from(address)
            )
            return [
                {
                    "address": item.address if hasattr(item, "address") else int(item),
                    "function": getattr(getattr(item, "function", None), "name", None),
                }
                for item in refs
            ]
        if operation == CommonOperation.SEARCH_STRINGS:
            query = str(arguments.get("query", "")).casefold()
            return [
                {"address": item.start, "length": item.length, "value": str(item.value)}
                for item in self._view.strings
                if query in str(item.value).casefold()
            ]
        if operation == CommonOperation.MEMORY_READ:
            address = _address(_require(arguments, "address"))
            size = int(_require(arguments, "size"))
            return {
                "address": address,
                "bytes": bytes(self._view.read(address, size)).hex(),
            }
        if operation == CommonOperation.SYMBOLS_RENAME:
            function = self._function(_require(arguments, "function"))
            name = str(_require(arguments, "name"))
            symbol = self._bn.Symbol(
                self._bn.SymbolType.FunctionSymbol, function.start, name
            )
            self._view.define_user_symbol(symbol)
            return {"address": function.start, "name": name}
        if operation == CommonOperation.COMMENTS_WRITE:
            address = _address(_require(arguments, "address"))
            comment = str(_require(arguments, "comment"))
            function = self._function(address)
            function.set_comment_at(address, comment)
            return {"address": address, "comment": comment}
        if operation == CommonOperation.FUNCTIONS_CREATE:
            address = _address(_require(arguments, "address"))
            self._view.create_user_function(address)
            return self._function_dict(self._function(address))
        if operation == CommonOperation.FUNCTIONS_DELETE:
            function = self._function(_require(arguments, "function"))
            address = function.start
            self._view.remove_user_function(function)
            return {"address": address, "deleted": True}
        if operation == CommonOperation.TYPES_DEFINE:
            declaration = str(_require(arguments, "declaration"))
            parsed = self._view.parse_types_from_string(declaration)
            for name, type_value in parsed.types.items():
                self._view.define_user_type(name, type_value)
            return {"defined": [str(name) for name in parsed.types]}
        if operation == CommonOperation.TYPES_APPLY:
            address = _address(_require(arguments, "address"))
            declaration = str(_require(arguments, "type"))
            type_value, _ = self._view.parse_type_string(declaration)
            self._view.define_user_data_var(address, type_value)
            return {"address": address, "type": str(type_value)}
        raise ReversingMcpError(
            "unsupported_operation", f"Unsupported operation: {operation}"
        )

    def _run_python(self, source: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self._ensure_open()
        namespace: dict[str, Any] = {
            "binaryninja": self._bn,
            "bv": self._view,
            "arguments": arguments,
            "result": None,
        }
        exec(
            compile(source, "<reversing-mcp-binary-ninja>", "exec"),
            namespace,
            namespace,
        )
        return {"result": namespace.get("result")}
