"""Session lifecycle, policy enforcement, and operation dispatch."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import Any, Mapping
from uuid import uuid4

from .backends import AnalysisSession
from .errors import (
    ReversingMcpError,
    ScriptExecutionDisabledError,
    SessionNotFoundError,
    UnsupportedCapabilityError,
)
from .models import (
    Capability,
    LifecycleAction,
    OperationSpec,
    SessionDescriptor,
    SessionRequest,
)
from .registry import ProviderRegistry

_LIFECYCLE_CAPABILITIES = {
    LifecycleAction.OPEN: Capability.LIFECYCLE_OPEN,
    LifecycleAction.CREATE: Capability.LIFECYCLE_CREATE,
    LifecycleAction.REOPEN: Capability.LIFECYCLE_REOPEN,
    LifecycleAction.ATTACH: Capability.LIFECYCLE_ATTACH,
}

# Compatibility is intentionally centralized. Providers only implement and
# advertise canonical operation names.
_OPERATION_ALIASES = {
    "add_comment": "comments.write",
    "comments.set": "comments.write",
    "decompile": "analysis.decompile",
    "disassemble": "analysis.disassemble",
    "rename": "symbols.rename",
    "xrefs.from": "references.from",
    "xrefs.to": "references.to",
}


@dataclass(frozen=True, slots=True)
class ServerPolicy:
    """Security and persistence policy for a unified server instance."""

    allow_script_execution: bool = False
    script_providers: frozenset[str] | None = None
    auto_save_mutations: bool = True

    def permits_scripts_for(self, provider_id: str) -> bool:
        return self.allow_script_execution and (
            self.script_providers is None or provider_id in self.script_providers
        )


@dataclass(slots=True)
class _ManagedSession:
    descriptor: SessionDescriptor
    provider_session: AnalysisSession
    operation_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class SessionManager:
    """Own public session IDs and mediate all provider calls."""

    def __init__(
        self,
        registry: ProviderRegistry,
        *,
        policy: ServerPolicy | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy or ServerPolicy()
        self._sessions: dict[str, _ManagedSession] = {}
        self._lock = asyncio.Lock()

    def list_backends(self) -> list[dict[str, Any]]:
        return [provider.descriptor.to_dict() for provider in self.registry.list()]

    async def list_sessions(self) -> list[SessionDescriptor]:
        async with self._lock:
            return [self._sessions[key].descriptor for key in sorted(self._sessions)]

    async def open_session(
        self,
        provider_id: str,
        *,
        lifecycle: LifecycleAction | str = LifecycleAction.OPEN,
        target_path: str = "",
        database_path: str = "",
        mode: str = "headless",
        options: Mapping[str, Any] | None = None,
    ) -> SessionDescriptor:
        provider = self.registry.get(provider_id)
        try:
            action = LifecycleAction(lifecycle)
        except ValueError as error:
            raise ReversingMcpError(
                "invalid_lifecycle",
                f"Unknown lifecycle action: {lifecycle}",
                details={"lifecycle": str(lifecycle)},
            ) from error

        capability = _LIFECYCLE_CAPABILITIES[action]
        if capability not in provider.capabilities:
            raise UnsupportedCapabilityError(
                capability, provider_id=provider_id, mode=mode
            )

        request = SessionRequest(
            lifecycle=action,
            target_path=target_path,
            database_path=database_path,
            mode=mode,
            options=dict(options or {}),
        )
        provider_session = await provider.open(request)
        if provider_session.provider_id != provider_id:
            await provider_session.close(save=False)
            raise ReversingMcpError(
                "provider_contract_error",
                "Provider returned a session with a different provider ID",
                details={
                    "expected": provider_id,
                    "actual": provider_session.provider_id,
                },
            )

        self._validate_operation_specs(provider_id, provider_session.operations)
        session_id = uuid4().hex
        descriptor = SessionDescriptor(
            session_id=session_id,
            provider_id=provider_id,
            target_path=provider_session.target_path,
            database_path=provider_session.database_path,
            mode=provider_session.mode,
            capabilities=provider_session.capabilities,
            operations=provider_session.operations,
            lifecycle=action,
        )
        async with self._lock:
            self._sessions[session_id] = _ManagedSession(
                descriptor=descriptor,
                provider_session=provider_session,
            )
        return descriptor

    async def get_descriptor(self, session_id: str) -> SessionDescriptor:
        return (await self._get_session(session_id)).descriptor

    async def capabilities(
        self, *, provider_id: str = "", session_id: str = ""
    ) -> dict[str, Any]:
        if bool(provider_id) == bool(session_id):
            raise ReversingMcpError(
                "invalid_request",
                "Specify exactly one of provider_id or session_id",
            )
        if provider_id:
            return self.registry.get(provider_id).descriptor.to_dict()
        return (await self.get_descriptor(session_id)).to_dict()

    async def invoke(
        self,
        session_id: str,
        operation: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        save_after: bool | None = None,
    ) -> Any:
        managed = await self._get_open_session(session_id)
        canonical_operation = _OPERATION_ALIASES.get(operation, operation)
        if canonical_operation.startswith("script."):
            raise ReversingMcpError(
                "script_route_required",
                "Script operations must use the guarded run_script tool",
                details={"operation": canonical_operation},
            )

        operation_spec = self._find_operation(
            managed.descriptor.operations, canonical_operation
        )
        if operation_spec is None:
            raise ReversingMcpError(
                "unsupported_operation",
                f"Session does not expose operation '{canonical_operation}'",
                details={
                    "session_id": session_id,
                    "provider": managed.descriptor.provider_id,
                    "operation": canonical_operation,
                },
            )
        if operation_spec.capability not in managed.descriptor.capabilities:
            raise UnsupportedCapabilityError(
                operation_spec.capability,
                provider_id=managed.descriptor.provider_id,
                mode=managed.descriptor.mode,
            )

        async with managed.operation_lock:
            self._ensure_open(managed)
            result = await managed.provider_session.invoke(
                canonical_operation, dict(arguments or {})
            )
            should_save = save_after
            if should_save is None:
                should_save = (
                    self.policy.auto_save_mutations
                    and operation_spec.mutating
                    and Capability.LIFECYCLE_SAVE in managed.descriptor.capabilities
                )
            if should_save:
                await self._save_managed(managed)
            return result

    async def run_script(
        self,
        session_id: str,
        *,
        language: str,
        source: str,
        arguments: Mapping[str, Any] | None = None,
        save_after: bool = True,
    ) -> Any:
        managed = await self._get_open_session(session_id)
        language = language.strip().lower()
        capability = f"script.{language}"
        if not self.policy.permits_scripts_for(managed.descriptor.provider_id):
            raise ScriptExecutionDisabledError()
        if capability not in managed.descriptor.capabilities:
            raise UnsupportedCapabilityError(
                capability,
                provider_id=managed.descriptor.provider_id,
                mode=managed.descriptor.mode,
            )
        if not source.strip():
            raise ReversingMcpError("invalid_script", "Script source cannot be empty")

        async with managed.operation_lock:
            self._ensure_open(managed)
            result = await managed.provider_session.run_script(
                language=language,
                source=source,
                arguments=dict(arguments or {}),
            )
            if save_after:
                await self._save_managed(managed)
            return result

    async def save_session(self, session_id: str) -> Any:
        managed = await self._get_open_session(session_id)
        async with managed.operation_lock:
            self._ensure_open(managed)
            return await self._save_managed(managed)

    async def close_session(
        self, session_id: str, *, save: bool = True
    ) -> SessionDescriptor:
        managed = await self._get_open_session(session_id)
        if Capability.LIFECYCLE_CLOSE not in managed.descriptor.capabilities:
            raise UnsupportedCapabilityError(
                Capability.LIFECYCLE_CLOSE,
                provider_id=managed.descriptor.provider_id,
                mode=managed.descriptor.mode,
            )
        async with managed.operation_lock:
            async with self._lock:
                current = self._sessions.get(session_id)
                if current is None or current.descriptor.state != "open":
                    raise SessionNotFoundError(session_id)
                current.descriptor = replace(current.descriptor, state="closing")
            try:
                await managed.provider_session.close(save=save)
            except Exception:
                async with self._lock:
                    current = self._sessions.get(session_id)
                    if current is not None:
                        current.descriptor = replace(current.descriptor, state="open")
                raise

            closed = replace(managed.descriptor, state="closed")
            async with self._lock:
                self._sessions.pop(session_id, None)
        return closed

    async def _save_managed(self, managed: _ManagedSession) -> Any:
        if Capability.LIFECYCLE_SAVE not in managed.descriptor.capabilities:
            raise UnsupportedCapabilityError(
                Capability.LIFECYCLE_SAVE,
                provider_id=managed.descriptor.provider_id,
                mode=managed.descriptor.mode,
            )
        return await managed.provider_session.save()

    async def _get_session(self, session_id: str) -> _ManagedSession:
        async with self._lock:
            try:
                return self._sessions[session_id]
            except KeyError as error:
                raise SessionNotFoundError(session_id) from error

    async def _get_open_session(self, session_id: str) -> _ManagedSession:
        managed = await self._get_session(session_id)
        self._ensure_open(managed)
        return managed

    @staticmethod
    def _ensure_open(managed: _ManagedSession) -> None:
        if managed.descriptor.state != "open":
            raise ReversingMcpError(
                "session_not_open",
                f"Session '{managed.descriptor.session_id}' is "
                f"{managed.descriptor.state}",
                details={
                    "session_id": managed.descriptor.session_id,
                    "state": managed.descriptor.state,
                },
            )

    @staticmethod
    def _find_operation(
        operations: tuple[OperationSpec, ...], name: str
    ) -> OperationSpec | None:
        return next(
            (operation for operation in operations if operation.name == name), None
        )

    @staticmethod
    def _validate_operation_specs(
        provider_id: str, operations: tuple[OperationSpec, ...]
    ) -> None:
        names = [operation.name for operation in operations]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise ReversingMcpError(
                "provider_contract_error",
                "Provider session declared duplicate operation names",
                details={"provider": provider_id, "operations": duplicates},
            )
