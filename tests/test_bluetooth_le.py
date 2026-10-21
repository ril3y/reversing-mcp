from __future__ import annotations

import asyncio
from types import SimpleNamespace

from reversing_mcp.models import LifecycleAction, SessionRequest
from reversing_mcp.providers.bluetooth_le import BluetoothLeBackend


def run(coroutine):
    return asyncio.run(coroutine)


class FakeScanner:
    @staticmethod
    async def discover(**kwargs):
        del kwargs
        device = SimpleNamespace(address="AA:BB", name="Battery")
        advertisement = SimpleNamespace(
            rssi=-42,
            service_uuids=["ff00"],
            manufacturer_data={1: b"\x01\x02"},
        )
        return {"AA:BB": (device, advertisement)}


class FakeClient:
    def __init__(self, address, **kwargs):
        del kwargs
        self.address = address
        self.is_connected = False
        descriptor = SimpleNamespace(uuid="2902", handle=3)
        characteristic = SimpleNamespace(
            uuid="ff01",
            handle=2,
            description="data",
            properties=["read", "write", "notify"],
            descriptors=[descriptor],
        )
        self.services = [
            SimpleNamespace(
                uuid="ff00",
                handle=1,
                description="battery",
                characteristics=[characteristic],
            )
        ]
        self.callback = None
        self.writes = []

    async def connect(self):
        self.is_connected = True
        return True

    async def disconnect(self):
        self.is_connected = False

    async def start_notify(self, characteristic, callback):
        del characteristic
        self.callback = callback

    async def stop_notify(self, characteristic):
        del characteristic
        self.callback = None

    async def read_gatt_char(self, characteristic):
        del characteristic
        return b"\x01\x03"

    async def write_gatt_char(self, characteristic, data, response=True):
        self.writes.append((characteristic, bytes(data), response))


def test_ble_scan_connect_capture_write_and_save(tmp_path, monkeypatch):
    fake_bleak = SimpleNamespace(BleakScanner=FakeScanner, BleakClient=FakeClient)
    monkeypatch.setattr(
        "reversing_mcp.providers.bluetooth_le.importlib.import_module",
        lambda name: fake_bleak,
    )
    session = run(
        BluetoothLeBackend().open(
            SessionRequest(lifecycle=LifecycleAction.OPEN, target_path="AA:BB")
        )
    )

    scanned = run(session.invoke("ble.scan", {"timeout": 0.1}))
    connected = run(session.invoke("ble.connect", {}))
    services = run(session.invoke("ble.services.list", {}))
    run(session.invoke("ble.subscribe", {"characteristic": "ff01"}))
    session._client.callback(SimpleNamespace(uuid="ff01"), bytearray(b"\x01\x03\x02"))
    written = run(
        session.invoke(
            "ble.write",
            {"characteristic": "ff01", "data": "01030000", "response": True},
        )
    )
    read = run(session.invoke("ble.read", {"characteristic": "ff01"}))
    transcript = run(session.invoke("ble.transcript.get", {}))
    output = tmp_path / "capture.jsonl"
    saved = run(session.invoke("ble.transcript.save", {"path": str(output)}))
    closed = run(session.close())

    assert scanned["devices"][0]["name"] == "Battery"
    assert connected["connected"] is True
    assert services["services"][0]["characteristics"][0]["uuid"] == "ff01"
    assert written["data_hex"] == "01030000"
    assert read["data_hex"] == "0103"
    assert any(event["event"] == "notify" for event in transcript["events"])
    assert saved["events"] == len(transcript["events"])
    assert output.read_text(encoding="utf-8").count("\n") == saved["events"]
    assert closed["closed"] is True
