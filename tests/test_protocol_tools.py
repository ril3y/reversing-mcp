from __future__ import annotations

import asyncio

from reversing_mcp.models import LifecycleAction, SessionRequest
from reversing_mcp.protocols import crc16_modbus
from reversing_mcp.providers.protocol import ProtocolBackend


def run(coroutine):
    return asyncio.run(coroutine)


def modbus_frame(payload: bytes) -> bytes:
    return payload + crc16_modbus(payload).to_bytes(2, "little")


def test_protocol_provider_detects_and_decodes_modbus_crc():
    session = run(
        ProtocolBackend().open(SessionRequest(lifecycle=LifecycleAction.OPEN))
    )
    frame = modbus_frame(bytes.fromhex("010304000a0014"))

    detected = run(
        session.invoke("protocol.checksum.detect", {"frames": [frame.hex()]})
    )
    verified = run(
        session.invoke(
            "protocol.checksum.verify",
            {"frame": frame.hex(), "algorithm": "modbus"},
        )
    )
    decoded = run(session.invoke("protocol.modbus.decode", {"frame": frame.hex()}))

    assert detected["matches"][0]["algorithm"] == "crc16-modbus"
    assert detected["matches"][0]["all_frames"] is True
    assert verified["valid"] is True
    assert decoded["crc"]["valid"] is True
    assert decoded["registers"] == [10, 20]


def test_register_map_supports_scaling_signed_and_word_order():
    session = run(
        ProtocolBackend().open(SessionRequest(lifecycle=LifecycleAction.OPEN))
    )
    result = run(
        session.invoke(
            "protocol.registers.decode",
            {
                "start_address": 100,
                "registers": [1234, 0xFFFF, 0x0000, 0x3F80],
                "map": [
                    {
                        "name": "voltage",
                        "address": 100,
                        "type": "u16",
                        "scale": 0.01,
                        "unit": "V",
                    },
                    {"name": "delta", "address": 101, "type": "s16"},
                    {
                        "name": "ratio",
                        "address": 102,
                        "type": "float32",
                        "word_order": "little",
                    },
                ],
            },
        )
    )

    assert result["values"][0]["value"] == 12.34
    assert result["values"][1]["value"] == -1
    assert result["values"][2]["value"] == 1


def test_modbus_request_is_not_mistaken_for_response():
    session = run(
        ProtocolBackend().open(SessionRequest(lifecycle=LifecycleAction.OPEN))
    )
    frame = modbus_frame(bytes.fromhex("010300100002"))

    decoded = run(session.invoke("protocol.modbus.decode", {"frame": frame.hex()}))

    assert decoded["kind"] == "read_request"
    assert decoded["start_register"] == 0x10
    assert decoded["register_count"] == 2


def test_modbus_multiple_register_write_decodes_payload():
    session = run(
        ProtocolBackend().open(SessionRequest(lifecycle=LifecycleAction.OPEN))
    )
    frame = modbus_frame(bytes.fromhex("01100010000204000a0014"))

    decoded = run(session.invoke("protocol.modbus.decode", {"frame": frame.hex()}))

    assert decoded["kind"] == "write_request"
    assert decoded["start_register"] == 0x10
    assert decoded["registers"] == [10, 20]
