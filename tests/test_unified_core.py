from __future__ import annotations

import asyncio
from typing import Any, Mapping

import pytest

from reversing_mcp import (
    AnalysisBackend,
    AnalysisSession,
    Capability,
    LifecycleAction,
    OperationSpec,
    ProviderRegistry,
    ServerPolicy,
    SessionManager,
    SessionRequest,
)
from reversing_mcp.errors import ReversingMcpError


def run(coroutine):
    return asyncio.run(coroutine)


OPERATIONS = (
    OperationSpec(
        "analysis.decompile", Capability.ANALYSIS_DECOMPILE, description="Decompile"
    ),
    OperationSpec("symbols.rename", Capability.SYMBOLS_RENAME, mutating=True),
)
CAPABILITIES = {
    Capability.LIFECYCLE_OPEN,
    Capability.LIFECYCLE_CREATE,
    Capability.LIFECYCLE_REOPEN,
    Capability.LIFECYCLE_ATTACH,
    Capability.LIFECYCLE_SAVE,
    Capability.LIFECYCLE_CLOSE,
    Capability.ANALYSIS_DECOMPILE,
    Capability.SYMBOLS_RENAME,
    Capability.SCRIPT_PYTHON,
}


class FakeSession(AnalysisSession):
    def __init__(self, request: SessionRequest) -> None:
        super().__init__(
            provider_id="fake",
            target_path=request.target_path,
            database_path=request.database_path,
            mode=request.mode,
            capabilities=CAPABILITIES,
            operations=OPERATIONS,
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.save_count = 0
        self.closed_with: bool | None = None

    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        payload = dict(arguments)
        self.calls.append((operation, payload))
        return {"operation": operation, "arguments": payload}

    async def save(self) -> Any:
        self.save_count += 1
        return {"saved": True}

    async def close(self, *, save: bool = True) -> Any:
        self.closed_with = save
        return {"closed": True, "saved": save}

    async def run_script(
        self,
        *,
        language: str,
        source: str,
        arguments: Mapping[str, Any],
    ) -> Any:
        return {
            "language": language,
            "source": source,
            "arguments": dict(arguments),
        }


class FakeBackend(AnalysisBackend):
    def __init__(self) -> None:
        super().__init__(
            provider_id="fake",
            display_name="Fake Analyzer",
            capabilities=CAPABILITIES,
            operations=OPERATIONS,
            version="1.2.3",
        )
        self.requests: list[SessionRequest] = []
        self.sessions: list[FakeSession] = []

    async def open(self, request: SessionRequest) -> AnalysisSession:
        self.requests.append(request)
        session = FakeSession(request)
        self.sessions.append(session)
        return session


def make_manager(*, policy: ServerPolicy | None = None):
    backend = FakeBackend()
    manager = SessionManager(ProviderRegistry([backend]), policy=policy)
    return manager, backend


@pytest.mark.parametrize("lifecycle", list(LifecycleAction))
def test_all_lifecycle_actions_return_stable_session(lifecycle):
    manager, backend = make_manager()
    descriptor = run(
        manager.open_session(
            "fake",
            lifecycle=lifecycle,
            target_path="sample.bin",
            database_path="sample.db",
        )
    )

    assert len(descriptor.session_id) == 32
    assert descriptor.provider_id == "fake"
    assert descriptor.lifecycle is lifecycle
    assert backend.requests[0].lifecycle is lifecycle
    assert run(manager.get_descriptor(descriptor.session_id)) == descriptor


def test_mutation_alias_is_normalized_and_auto_saved():
    manager, backend = make_manager()
    descriptor = run(manager.open_session("fake", target_path="sample.bin"))

    result = run(manager.invoke(descriptor.session_id, "rename", {"name": "entry"}))

    assert result["operation"] == "symbols.rename"
    assert backend.sessions[0].calls == [("symbols.rename", {"name": "entry"})]
    assert backend.sessions[0].save_count == 1


def test_read_only_operation_does_not_auto_save():
    manager, backend = make_manager()
    descriptor = run(manager.open_session("fake", target_path="sample.bin"))

    run(manager.invoke(descriptor.session_id, "analysis.decompile", {"address": 16}))

    assert backend.sessions[0].save_count == 0


def test_generic_invoke_cannot_bypass_script_policy():
    manager, _ = make_manager(policy=ServerPolicy(allow_script_execution=True))
    descriptor = run(manager.open_session("fake", target_path="sample.bin"))

    with pytest.raises(ReversingMcpError, match="guarded run_script") as error:
        run(manager.invoke(descriptor.session_id, "script.python", {}))

    assert error.value.code == "script_route_required"


def test_scripts_are_disabled_by_default():
    manager, _ = make_manager()
    descriptor = run(manager.open_session("fake", target_path="sample.bin"))

    with pytest.raises(ReversingMcpError) as error:
        run(
            manager.run_script(
                descriptor.session_id, language="python", source="print('x')"
            )
        )

    assert error.value.code == "script_execution_disabled"


def test_enabled_script_runs_and_saves():
    manager, backend = make_manager(
        policy=ServerPolicy(
            allow_script_execution=True,
            script_providers=frozenset({"fake"}),
        )
    )
    descriptor = run(manager.open_session("fake", target_path="sample.bin"))

    result = run(
        manager.run_script(
            descriptor.session_id,
            language="python",
            source="result = args['value']",
            arguments={"value": 7},
        )
    )

    assert result["arguments"] == {"value": 7}
    assert backend.sessions[0].save_count == 1


def test_close_removes_session_and_preserves_save_choice():
    manager, backend = make_manager()
    descriptor = run(manager.open_session("fake", target_path="sample.bin"))

    closed = run(manager.close_session(descriptor.session_id, save=False))

    assert closed.state == "closed"
    assert backend.sessions[0].closed_with is False
    assert run(manager.list_sessions()) == []
    with pytest.raises(ReversingMcpError) as error:
        run(manager.get_descriptor(descriptor.session_id))
    assert error.value.code == "session_not_found"


def test_capabilities_requires_exactly_one_selector():
    manager, _ = make_manager()

    with pytest.raises(ReversingMcpError) as error:
        run(manager.capabilities())

    assert error.value.code == "invalid_request"
    provider = run(manager.capabilities(provider_id="fake"))
    assert provider["protocol_version"] == "1.0"
    assert provider["provider"] == "fake"


def test_registry_rejects_duplicate_provider_ids():
    registry = ProviderRegistry([FakeBackend()])

    with pytest.raises(ReversingMcpError) as error:
        registry.register(FakeBackend())

    assert error.value.code == "provider_already_registered"
