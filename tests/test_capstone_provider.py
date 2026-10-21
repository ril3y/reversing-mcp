from __future__ import annotations

import asyncio

import pytest

from reversing_mcp.errors import ReversingMcpError
from reversing_mcp.models import LifecycleAction, SessionRequest
from reversing_mcp.providers import capstone as provider


def run(coroutine):
    return asyncio.run(coroutine)


def open_capstone(*, target_path: str = "", options=None):
    pytest.importorskip("capstone")
    return run(
        provider.CapstoneBackend().open(
            SessionRequest(
                lifecycle=LifecycleAction.OPEN,
                target_path=target_path,
                options=options or {},
            )
        )
    )


def test_inline_cortex_m_thumb_disassembly():
    session = open_capstone(
        options={
            "architecture": "arm",
            "mode": ["thumb", "mclass"],
            "base_address": "0x08000000",
        }
    )

    result = run(
        session.invoke(
            "analysis.disassemble",
            {"data": "00b5012000bd"},
        )
    )

    assert result["architecture"] == "arm"
    assert result["mode_names"] == ["thumb", "mclass"]
    assert result["start_address"] == 0x08000000
    assert [item["mnemonic"] for item in result["instructions"]] == [
        "push",
        "movs",
        "pop",
    ]
    assert result["decoded_bytes"] == 6
    assert result["undecoded_bytes"] == 0
    run(session.close())


def test_file_session_maps_addresses_and_reads_bytes(tmp_path):
    target = tmp_path / "firmware.bin"
    target.write_bytes(b"\xff\xff\x00\xb5\x01\x20\x00\xbd")
    session = open_capstone(
        target_path=str(target),
        options={
            "architecture": "arm",
            "mode": "thumb,mclass",
            "base_address": "0x08000000",
            "offset": 2,
        },
    )

    memory = run(session.invoke("memory.read", {"address": "0x08000002", "size": 6}))
    decoded = run(
        session.invoke(
            "analysis.disassemble",
            {"address": "0x08000002", "size": 6},
        )
    )
    info = run(session.invoke("target.info", {}))

    assert memory["hex"] == "00b5012000bd"
    assert memory["source"]["file_offset"] == 2
    assert decoded["source"]["file_offset"] == 2
    assert decoded["instructions"][0]["address"] == 0x08000002
    assert info["size"] == 8
    assert len(info["sha256"]) == 64


def test_inline_session_exposes_only_operations_it_can_perform():
    session = open_capstone(options={"architecture": "arm", "mode": "thumb"})

    assert "memory.read" not in {item.name for item in session.operations}
    catalog = run(session.invoke("capstone.architectures.list", {}))
    assert "arm" in {item["name"] for item in catalog["architectures"]}
    x86 = next(item for item in catalog["architectures"] if item["name"] == "x86")
    assert x86["endianness"] == ["little"]


def test_invalid_architecture_is_structured():
    pytest.importorskip("capstone")
    with pytest.raises(ReversingMcpError) as raised:
        run(
            provider.CapstoneBackend().open(
                SessionRequest(
                    lifecycle=LifecycleAction.OPEN,
                    options={"architecture": "not-a-cpu"},
                )
            )
        )

    assert raised.value.code == "invalid_architecture"
    assert "arm" in raised.value.details["available"]


def test_missing_capstone_dependency_is_structured(monkeypatch):
    def missing(_name):
        raise ImportError("missing")

    monkeypatch.setattr(provider.importlib, "import_module", missing)
    with pytest.raises(ReversingMcpError) as raised:
        run(
            provider.CapstoneBackend().open(
                SessionRequest(lifecycle=LifecycleAction.OPEN)
            )
        )

    assert raised.value.code == "dependency_missing"
    assert raised.value.details["dependency"] == "capstone"
