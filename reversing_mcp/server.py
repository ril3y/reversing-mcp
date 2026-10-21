"""Unified MCP server for every registered reverse-engineering backend."""

from __future__ import annotations

import os
from typing import Any, Awaitable, Callable, Mapping

from mcp.server.fastmcp import FastMCP

from .errors import ReversingMcpError
from .manager import ServerPolicy, SessionManager
from .models import LifecycleAction, OperationResult
from .registry import ProviderRegistry, register_builtin_backends


def _environment_policy() -> ServerPolicy:
    enabled = os.environ.get("REVERSING_MCP_ALLOW_SCRIPTS", "").lower()
    providers = os.environ.get("REVERSING_MCP_SCRIPT_PROVIDERS", "").strip()
    return ServerPolicy(
        allow_script_execution=enabled in {"1", "true", "yes", "on"},
        script_providers=(
            frozenset(item.strip() for item in providers.split(",") if item.strip())
            if providers
            else None
        ),
    )


def create_server(
    registry: ProviderRegistry | None = None,
    *,
    policy: ServerPolicy | None = None,
) -> FastMCP:
    """Create an isolated unified MCP server.

    Passing a registry makes tests and third-party adapters deterministic. A
    default server loads adapters returned by ``providers.builtin_backends``.
    """
    if registry is None:
        registry = register_builtin_backends(ProviderRegistry())
    manager = SessionManager(registry, policy=policy or _environment_policy())
    server = FastMCP("reversing-mcp")

    async def respond(call: Callable[[], Awaitable[Any]]) -> dict[str, Any]:
        try:
            data = await call()
            if isinstance(data, OperationResult):
                return data.to_dict()
            return OperationResult.success(data).to_dict()
        except ReversingMcpError as error:
            return OperationResult.failure(
                error.code, error.message, details=error.details
            ).to_dict()
        except Exception as error:  # provider boundaries must not kill stdio
            return OperationResult.failure(
                "provider_error",
                f"{type(error).__name__}: {error}",
            ).to_dict()

    @server.tool()
    def list_backends() -> dict[str, Any]:
        """List registered providers, capabilities, and operation conventions."""
        return OperationResult.success(manager.list_backends()).to_dict()

    @server.tool()
    async def list_sessions() -> dict[str, Any]:
        """List active sessions owned by this server process."""

        async def call() -> list[dict[str, Any]]:
            return [item.to_dict() for item in await manager.list_sessions()]

        return await respond(call)

    @server.tool()
    async def capabilities(provider: str = "", session_id: str = "") -> dict[str, Any]:
        """Describe either a provider or a live session's supported surface."""
        return await respond(
            lambda: manager.capabilities(provider_id=provider, session_id=session_id)
        )

    async def acquire(
        lifecycle: LifecycleAction,
        provider: str,
        target_path: str,
        database_path: str,
        mode: str,
        options: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        async def call() -> dict[str, Any]:
            descriptor = await manager.open_session(
                provider,
                lifecycle=lifecycle,
                target_path=target_path,
                database_path=database_path,
                mode=mode,
                options=options,
            )
            return descriptor.to_dict()

        return await respond(call)

    @server.tool()
    async def open_session(
        provider: str,
        target_path: str = "",
        database_path: str = "",
        mode: str = "headless",
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Open an analysis target using a provider's normal lifecycle."""
        return await acquire(
            LifecycleAction.OPEN,
            provider,
            target_path,
            database_path,
            mode,
            options,
        )

    @server.tool()
    async def create_session(
        provider: str,
        target_path: str,
        database_path: str = "",
        mode: str = "headless",
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a persistent analysis database from a target artifact."""
        return await acquire(
            LifecycleAction.CREATE,
            provider,
            target_path,
            database_path,
            mode,
            options,
        )

    @server.tool()
    async def reopen_session(
        provider: str,
        database_path: str,
        target_path: str = "",
        mode: str = "headless",
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Reopen an existing provider database or project."""
        return await acquire(
            LifecycleAction.REOPEN,
            provider,
            target_path,
            database_path,
            mode,
            options,
        )

    @server.tool()
    async def attach_session(
        provider: str,
        target: str = "",
        mode: str = "attached",
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Attach to an existing GUI or provider process."""
        return await acquire(
            LifecycleAction.ATTACH, provider, target, "", mode, options
        )

    @server.tool()
    async def invoke(
        session_id: str,
        operation: str,
        arguments: dict[str, Any] | None = None,
        save_after: bool | None = None,
    ) -> dict[str, Any]:
        """Invoke a declared non-script operation on a live session."""
        return await respond(
            lambda: manager.invoke(
                session_id,
                operation,
                arguments,
                save_after=save_after,
            )
        )

    @server.tool()
    async def run_script(
        session_id: str,
        language: str,
        source: str,
        arguments: dict[str, Any] | None = None,
        save_after: bool = False,
    ) -> dict[str, Any]:
        """Run a provider-native script when policy and session allow it."""
        return await respond(
            lambda: manager.run_script(
                session_id,
                language=language,
                source=source,
                arguments=arguments,
                save_after=save_after,
            )
        )

    @server.tool()
    async def run_python(
        session_id: str,
        source: str,
        arguments: dict[str, Any] | None = None,
        save_after: bool = True,
    ) -> dict[str, Any]:
        """Run provider-native Python when both policy and provider allow it."""
        return await respond(
            lambda: manager.run_script(
                session_id,
                language="python",
                source=source,
                arguments=arguments,
                save_after=save_after,
            )
        )

    @server.tool()
    async def save_session(session_id: str) -> dict[str, Any]:
        """Persist the provider database/project."""
        return await respond(lambda: manager.save_session(session_id))

    @server.tool()
    async def close_session(session_id: str, save: bool = True) -> dict[str, Any]:
        """Close a session and optionally save its database first."""

        async def call() -> dict[str, Any]:
            descriptor = await manager.close_session(session_id, save=save)
            return descriptor.to_dict()

        return await respond(call)

    return server


mcp = create_server()
