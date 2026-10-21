"""Structured exceptions raised by the core runtime."""

from __future__ import annotations

from typing import Any, Mapping


class ReversingMcpError(Exception):
    """An expected error with a stable machine-readable code."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = dict(details or {})


class ProviderNotFoundError(ReversingMcpError):
    def __init__(self, provider_id: str) -> None:
        super().__init__(
            "provider_not_found",
            f"Unknown analysis provider: {provider_id}",
            details={"provider": provider_id},
        )


class SessionNotFoundError(ReversingMcpError):
    def __init__(self, session_id: str) -> None:
        super().__init__(
            "session_not_found",
            f"Unknown analysis session: {session_id}",
            details={"session_id": session_id},
        )


class UnsupportedCapabilityError(ReversingMcpError):
    def __init__(self, capability: str, *, provider_id: str, mode: str = "") -> None:
        details = {"provider": provider_id, "capability": capability}
        if mode:
            details["mode"] = mode
        super().__init__(
            "unsupported_capability",
            f"Provider '{provider_id}' does not support '{capability}'",
            details=details,
        )


class ScriptExecutionDisabledError(ReversingMcpError):
    def __init__(self) -> None:
        super().__init__(
            "script_execution_disabled",
            "Provider script execution is disabled by server policy",
        )
