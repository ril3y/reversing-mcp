"""Stable wire models shared by the MCP server and provider adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping

PROTOCOL_VERSION = "1.0"


class LifecycleAction(StrEnum):
    """How a provider should acquire a session."""

    OPEN = "open"
    CREATE = "create"
    REOPEN = "reopen"
    ATTACH = "attach"


class SessionMode(StrEnum):
    """Requested execution mode.

    Providers may expose additional modes as strings. These values define the
    portable modes understood by the core.
    """

    HEADLESS = "headless"
    GUI = "gui"
    ATTACHED = "attached"


class Capability(StrEnum):
    """Portable capability identifiers.

    Provider-specific capabilities must be namespaced, for example
    ``ida.debugger.live`` or ``jadx.resources.list``.
    """

    LIFECYCLE_OPEN = "lifecycle.open"
    LIFECYCLE_CREATE = "lifecycle.create"
    LIFECYCLE_REOPEN = "lifecycle.reopen"
    LIFECYCLE_ATTACH = "lifecycle.attach"
    LIFECYCLE_SAVE = "lifecycle.save"
    LIFECYCLE_CLOSE = "lifecycle.close"
    ANALYSIS_DECOMPILE = "analysis.decompile"
    ANALYSIS_DISASSEMBLE = "analysis.disassemble"
    ANALYSIS_XREFS = "analysis.xrefs"
    SYMBOLS_RENAME = "symbols.rename"
    COMMENTS_WRITE = "comments.write"
    TYPES_DEFINE = "types.define"
    TYPES_APPLY = "types.apply"
    FUNCTIONS_CREATE = "functions.create"
    FUNCTIONS_DELETE = "functions.delete"
    SCRIPT_PYTHON = "script.python"
    SCRIPT_JAVASCRIPT = "script.javascript"


class CommonOperation(StrEnum):
    """Canonical operation names used across provider implementations."""

    TARGET_INFO = "target.info"
    FUNCTIONS_GET = "functions.get"
    FUNCTIONS_LIST = "functions.list"
    FUNCTIONS_CREATE = "functions.create"
    FUNCTIONS_DELETE = "functions.delete"
    FUNCTIONS_SET_PROTOTYPE = "functions.prototype.set"
    ANALYSIS_DECOMPILE = "analysis.decompile"
    ANALYSIS_DISASSEMBLE = "analysis.disassemble"
    REFERENCES_TO = "references.to"
    REFERENCES_FROM = "references.from"
    CALLGRAPH_CALLERS = "callgraph.callers"
    CALLGRAPH_CALLEES = "callgraph.callees"
    SEARCH_FUNCTIONS = "search.functions"
    SEARCH_STRINGS = "search.strings"
    SEARCH_CLASSES = "search.classes"
    SEARCH_METHODS = "search.methods"
    MEMORY_READ = "memory.read"
    SYMBOLS_RENAME = "symbols.rename"
    COMMENTS_WRITE = "comments.write"
    TYPES_DEFINE = "types.define"
    TYPES_APPLY = "types.apply"
    LOCALS_RENAME = "locals.rename"
    LOCALS_SET_TYPE = "locals.type.set"
    SEGMENTS_LIST = "segments.list"
    SEGMENTS_CREATE = "segments.create"
    SEGMENTS_UPDATE = "segments.update"
    NOTEBOOK_READ = "notebook.read"
    NOTEBOOK_APPEND = "notebook.append"
    NOTEBOOK_REPLACE = "notebook.replace"
    NOTEBOOK_CLEAR = "notebook.clear"


@dataclass(frozen=True, slots=True)
class OperationSpec:
    """An operation exposed by an analysis session."""

    name: str
    capability: str
    mutating: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "capability": self.capability,
            "mutating": self.mutating,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class SessionRequest:
    """Provider-neutral request to acquire an analysis session."""

    lifecycle: LifecycleAction
    target_path: str = ""
    database_path: str = ""
    mode: str = SessionMode.HEADLESS
    options: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BackendDescriptor:
    provider_id: str
    display_name: str
    capabilities: frozenset[str]
    operations: tuple[OperationSpec, ...]
    version: str = ""
    protocol_version: str = PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider_id,
            "display_name": self.display_name,
            "version": self.version,
            "protocol_version": self.protocol_version,
            "capabilities": sorted(self.capabilities),
            "operations": [operation.to_dict() for operation in self.operations],
        }


@dataclass(frozen=True, slots=True)
class SessionDescriptor:
    session_id: str
    provider_id: str
    target_path: str
    database_path: str
    mode: str
    capabilities: frozenset[str]
    operations: tuple[OperationSpec, ...]
    lifecycle: LifecycleAction
    state: str = "open"
    protocol_version: str = PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "provider": self.provider_id,
            "target_path": self.target_path,
            "database_path": self.database_path,
            "mode": self.mode,
            "state": self.state,
            "lifecycle": self.lifecycle.value,
            "protocol_version": self.protocol_version,
            "capabilities": sorted(self.capabilities),
            "operations": [operation.to_dict() for operation in self.operations],
        }


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.details:
            result["details"] = dict(self.details)
        return result


@dataclass(frozen=True, slots=True)
class OperationResult:
    """Uniform result envelope returned by every unified MCP tool."""

    ok: bool
    data: Any = None
    error: ErrorDetail | None = None
    meta: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def success(
        cls, data: Any = None, *, meta: Mapping[str, Any] | None = None
    ) -> OperationResult:
        return cls(ok=True, data=data, meta=meta or {})

    @classmethod
    def failure(
        cls,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> OperationResult:
        return cls(
            ok=False,
            error=ErrorDetail(code=code, message=message, details=details or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"ok": self.ok}
        if self.ok:
            result["data"] = self.data
        else:
            result["error"] = self.error.to_dict() if self.error else None
        if self.meta:
            result["meta"] = dict(self.meta)
        return result
