"""Base interfaces implemented by IDA, Ghidra, JADX, and future providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Mapping

from .errors import UnsupportedCapabilityError
from .models import BackendDescriptor, OperationSpec, SessionRequest


class AnalysisSession(ABC):
    """A live provider session.

    A provider owns its native process/database. The core owns the public
    session ID and calls these methods to operate on that provider resource.
    """

    def __init__(
        self,
        *,
        provider_id: str,
        target_path: str,
        database_path: str = "",
        mode: str = "headless",
        capabilities: frozenset[str] | set[str] = frozenset(),
        operations: tuple[OperationSpec, ...] = (),
    ) -> None:
        self.provider_id = provider_id
        self.target_path = target_path
        self.database_path = database_path
        self.mode = mode
        self.capabilities = frozenset(capabilities)
        self.operations = tuple(operations)

    @abstractmethod
    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        """Execute a declared non-script operation."""

    @abstractmethod
    async def save(self) -> Any:
        """Persist the native database/project."""

    @abstractmethod
    async def close(self, *, save: bool = True) -> Any:
        """Close the native resource, optionally saving first."""

    async def run_script(
        self,
        *,
        language: str,
        source: str,
        arguments: Mapping[str, Any],
    ) -> Any:
        """Execute a provider-native script when explicitly supported."""
        raise UnsupportedCapabilityError(
            f"script.{language}", provider_id=self.provider_id, mode=self.mode
        )


class AnalysisBackend(ABC):
    """Factory and static metadata for one reverse-engineering provider."""

    def __init__(
        self,
        *,
        provider_id: str,
        display_name: str,
        capabilities: frozenset[str] | set[str],
        operations: tuple[OperationSpec, ...],
        version: str = "",
    ) -> None:
        if not provider_id or not provider_id.isascii():
            raise ValueError("provider_id must be a non-empty ASCII identifier")
        self.provider_id = provider_id
        self.display_name = display_name
        self.capabilities = frozenset(capabilities)
        self.operations = tuple(operations)
        self.version = version

    @property
    def descriptor(self) -> BackendDescriptor:
        return BackendDescriptor(
            provider_id=self.provider_id,
            display_name=self.display_name,
            capabilities=self.capabilities,
            operations=self.operations,
            version=self.version,
        )

    @abstractmethod
    async def open(self, request: SessionRequest) -> AnalysisSession:
        """Open/create/reopen/attach according to ``request.lifecycle``."""
