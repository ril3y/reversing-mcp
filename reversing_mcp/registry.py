"""Provider registry used by the unified MCP server."""

from __future__ import annotations

from collections.abc import Iterable

from .backends import AnalysisBackend
from .errors import ProviderNotFoundError, ReversingMcpError


class ProviderRegistry:
    def __init__(self, providers: Iterable[AnalysisBackend] = ()) -> None:
        self._providers: dict[str, AnalysisBackend] = {}
        for provider in providers:
            self.register(provider)

    def register(self, provider: AnalysisBackend, *, replace: bool = False) -> None:
        provider_id = provider.provider_id
        if provider_id in self._providers and not replace:
            raise ReversingMcpError(
                "provider_already_registered",
                f"Provider '{provider_id}' is already registered",
                details={"provider": provider_id},
            )
        self._providers[provider_id] = provider

    def unregister(self, provider_id: str) -> AnalysisBackend:
        try:
            return self._providers.pop(provider_id)
        except KeyError as error:
            raise ProviderNotFoundError(provider_id) from error

    def get(self, provider_id: str) -> AnalysisBackend:
        try:
            return self._providers[provider_id]
        except KeyError as error:
            raise ProviderNotFoundError(provider_id) from error

    def list(self) -> tuple[AnalysisBackend, ...]:
        return tuple(self._providers[key] for key in sorted(self._providers))

    def __contains__(self, provider_id: object) -> bool:
        return provider_id in self._providers


def register_builtin_backends(registry: ProviderRegistry) -> ProviderRegistry:
    """Register available built-in adapters.

    Provider modules call this stable hook as they are added. Imports are kept
    local so the protocol package remains usable when optional tool runtimes are
    absent.
    """
    from .providers import builtin_backends

    for provider in builtin_backends():
        registry.register(provider)
    return registry
