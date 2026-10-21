from __future__ import annotations

import sys

import pytest

import install


def context(**overrides) -> install.Context:
    values = {
        "scope": "user",
        "skip_builds": True,
        "dry_run": False,
        "clients": ("claude",),
    }
    values.update(overrides)
    return install.Context(**values)


def test_claude_registration_uses_only_unified_module(monkeypatch):
    commands = []
    monkeypatch.setattr(install, "client_exists", lambda _client: True)
    monkeypatch.setattr(install, "_remove_existing_mcp", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        install, "_run", lambda command, **_kwargs: commands.append(command) or 0
    )

    result = install.register_unified_mcp("claude", context())

    assert result.ok
    assert len(commands) == 1
    command = commands[0]
    assert command[:6] == [
        "claude",
        "mcp",
        "add",
        "-s",
        "user",
        "reversing-mcp",
    ]
    assert command[-3:] == [sys.executable, "-m", "reversing_mcp"]
    assert not any(part.endswith("mcp_server.py") for part in command)


def test_codex_registration_sets_script_policy_before_server_name(monkeypatch):
    commands = []
    monkeypatch.setattr(install, "client_exists", lambda _client: True)
    monkeypatch.setattr(install, "_remove_existing_mcp", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        install, "_run", lambda command, **_kwargs: commands.append(command) or 0
    )

    result = install.register_unified_mcp(
        "codex",
        context(
            clients=("codex",),
            allow_scripts=True,
            script_providers="ida,ghidra",
        ),
    )

    assert result.ok
    command = commands[0]
    server_index = command.index("reversing-mcp")
    assert command[:3] == ["codex", "mcp", "add"]
    assert "REVERSING_MCP_ALLOW_SCRIPTS=1" in command[:server_index]
    assert "REVERSING_MCP_SCRIPT_PROVIDERS=ida,ghidra" in command[:server_index]
    assert command[-3:] == [sys.executable, "-m", "reversing_mcp"]


def test_run_install_registers_unified_once_per_client(monkeypatch):
    phases = []
    registrations = []

    def build(_ctx):
        phases.append("build")
        return install.Result(True, "built")

    def deploy(_ctx):
        phases.append("deploy")
        return install.Result(True, "deployed")

    tool = install.Tool("fake", "Fake", "fixture", "fake.marker", build, deploy)
    monkeypatch.setattr(
        install,
        "register_unified_mcp",
        lambda client, _ctx: registrations.append(client)
        or install.Result(True, "registered"),
    )

    failures = install.run_install([tool], context(clients=("claude", "codex")))

    assert failures == 0
    assert phases == ["build", "deploy"]
    assert registrations == ["claude", "codex"]


def test_removed_registration_selector_is_rejected(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["install.py", "--registration", "legacy"],
    )

    with pytest.raises(SystemExit) as error:
        install.main()

    assert error.value.code == 2
