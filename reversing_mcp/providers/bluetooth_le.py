"""Bluetooth Low Energy provider backed by the optional Bleak package."""

from __future__ import annotations

import base64
import importlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from ..backends import AnalysisBackend, AnalysisSession
from ..errors import ReversingMcpError
from ..models import (
    Capability,
    CommonOperation,
    LifecycleAction,
    OperationSpec,
    SessionRequest,
)
from ..protocols import (
    checksum_detect,
    checksum_verify,
    modbus_decode,
    parse_bytes,
    register_map_decode,
)


BLE_OPERATIONS = (
    OperationSpec("ble.scan", "ble.scan"),
    OperationSpec("ble.connect", "ble.connect", mutating=True),
    OperationSpec("ble.disconnect", "ble.disconnect", mutating=True),
    OperationSpec("ble.services.list", "ble.services.list"),
    OperationSpec("ble.subscribe", "ble.subscribe", mutating=True),
    OperationSpec("ble.unsubscribe", "ble.unsubscribe", mutating=True),
    OperationSpec("ble.read", "ble.read"),
    OperationSpec("ble.write", "ble.write", mutating=True),
    OperationSpec("ble.transcript.get", "ble.transcript.get"),
    OperationSpec("ble.transcript.clear", "ble.transcript.clear", mutating=True),
    OperationSpec("ble.transcript.save", "ble.transcript.save", mutating=True),
    OperationSpec(CommonOperation.PROTOCOL_CHECKSUM_DETECT, "protocol.checksum.detect"),
    OperationSpec(CommonOperation.PROTOCOL_CHECKSUM_VERIFY, "protocol.checksum.verify"),
    OperationSpec(CommonOperation.PROTOCOL_MODBUS_DECODE, "protocol.modbus.decode"),
    OperationSpec(
        CommonOperation.PROTOCOL_REGISTERS_DECODE, "protocol.registers.decode"
    ),
)

BLE_CAPABILITIES = frozenset(
    {
        Capability.LIFECYCLE_OPEN,
        Capability.LIFECYCLE_CLOSE,
        *(operation.capability for operation in BLE_OPERATIONS),
    }
)


class BluetoothLeSession(AnalysisSession):
    def __init__(self, bleak: Any, address: str = "", *, adapter: str = "") -> None:
        super().__init__(
            provider_id="bluetooth_le",
            target_path=address,
            mode="live",
            capabilities=BLE_CAPABILITIES,
            operations=BLE_OPERATIONS,
        )
        self._bleak = bleak
        self._address = address
        self._adapter = adapter
        self._client: Any = None
        self._subscriptions: set[str] = set()
        self._transcript: list[dict[str, Any]] = []
        self._sequence = 0
        self._started_ns = time.monotonic_ns()
        self._closed = False

    def _record(
        self,
        direction: str,
        *,
        characteristic: str = "",
        data: bytes = b"",
        event: str = "data",
        details: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._sequence += 1
        record: dict[str, Any] = {
            "sequence": self._sequence,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "elapsed_ms": round(
                (time.monotonic_ns() - self._started_ns) / 1_000_000, 3
            ),
            "direction": direction,
            "event": event,
        }
        if characteristic:
            record["characteristic"] = characteristic
        if data:
            record.update(
                {
                    "data_hex": data.hex(),
                    "data_base64": base64.b64encode(data).decode("ascii"),
                    "size": len(data),
                }
            )
        if details:
            record["details"] = dict(details)
        self._transcript.append(record)
        return record

    def _ensure_open(self) -> None:
        if self._closed:
            raise ReversingMcpError("session_closed", "Bluetooth LE session is closed")

    def _ensure_connected(self) -> Any:
        self._ensure_open()
        if self._client is None or not self._client.is_connected:
            raise ReversingMcpError(
                "ble_not_connected", "Connect to a BLE peripheral first"
            )
        return self._client

    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        self._ensure_open()
        routes = {
            "ble.scan": self._scan,
            "ble.connect": self._connect,
            "ble.disconnect": self._disconnect,
            "ble.services.list": self._services,
            "ble.subscribe": self._subscribe,
            "ble.unsubscribe": self._unsubscribe,
            "ble.read": self._read,
            "ble.write": self._write,
            "ble.transcript.get": self._transcript_get,
            "ble.transcript.clear": self._transcript_clear,
            "ble.transcript.save": self._transcript_save,
        }
        protocol_routes = {
            CommonOperation.PROTOCOL_CHECKSUM_DETECT: checksum_detect,
            CommonOperation.PROTOCOL_CHECKSUM_VERIFY: checksum_verify,
            CommonOperation.PROTOCOL_MODBUS_DECODE: modbus_decode,
            CommonOperation.PROTOCOL_REGISTERS_DECODE: register_map_decode,
        }
        if operation in protocol_routes:
            return protocol_routes[operation](arguments)
        try:
            route = routes[operation]
        except KeyError as error:
            raise ReversingMcpError(
                "unsupported_operation", f"Unsupported operation: {operation}"
            ) from error
        return await route(arguments)

    async def _scan(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        timeout = max(0.1, min(float(arguments.get("timeout", 5)), 60))
        kwargs: dict[str, Any] = {"timeout": timeout, "return_adv": True}
        if self._adapter:
            kwargs["adapter"] = self._adapter
        discovered = await self._bleak.BleakScanner.discover(**kwargs)
        rows = []
        values = discovered.values() if isinstance(discovered, dict) else discovered
        for value in values:
            if isinstance(value, tuple):
                device, advertisement = value
            else:
                device, advertisement = value, None
            service_uuids = list(getattr(advertisement, "service_uuids", None) or [])
            rows.append(
                {
                    "address": str(getattr(device, "address", "")),
                    "name": getattr(device, "name", None),
                    "rssi": getattr(
                        advertisement, "rssi", getattr(device, "rssi", None)
                    ),
                    "service_uuids": service_uuids,
                    "manufacturer_data": {
                        str(key): bytes(data).hex()
                        for key, data in (
                            getattr(advertisement, "manufacturer_data", None) or {}
                        ).items()
                    },
                }
            )
        rows.sort(key=lambda item: (item["name"] or "", item["address"]))
        self._record(
            "meta", event="scan", details={"devices": len(rows), "timeout": timeout}
        )
        return {"devices": rows, "count": len(rows), "timeout": timeout}

    async def _connect(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        address = str(arguments.get("address", self._address)).strip()
        if not address:
            raise ReversingMcpError("invalid_request", "A BLE address is required")
        if self._client is not None and self._client.is_connected:
            if address == self._address:
                return {
                    "connected": True,
                    "address": address,
                    "already_connected": True,
                }
            await self._disconnect({})
        timeout = max(1.0, min(float(arguments.get("timeout", 20)), 120))
        kwargs: dict[str, Any] = {"timeout": timeout}
        if self._adapter:
            kwargs["adapter"] = self._adapter
        self._client = self._bleak.BleakClient(address, **kwargs)
        connected = await self._client.connect()
        self._address = address
        self.target_path = address
        self._record("meta", event="connect", details={"address": address})
        return {
            "connected": bool(connected or self._client.is_connected),
            "address": address,
        }

    async def _disconnect(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        del arguments
        if self._client is None:
            return {"connected": False, "disconnected": False}
        was_connected = bool(self._client.is_connected)
        if was_connected:
            await self._client.disconnect()
        self._subscriptions.clear()
        self._record("meta", event="disconnect", details={"address": self._address})
        return {"connected": False, "disconnected": was_connected}

    async def _services(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        del arguments
        client = self._ensure_connected()
        services = []
        for service in client.services:
            characteristics = []
            for characteristic in service.characteristics:
                characteristics.append(
                    {
                        "uuid": str(characteristic.uuid),
                        "handle": getattr(characteristic, "handle", None),
                        "description": getattr(characteristic, "description", None),
                        "properties": list(
                            getattr(characteristic, "properties", []) or []
                        ),
                        "descriptors": [
                            {
                                "uuid": str(descriptor.uuid),
                                "handle": getattr(descriptor, "handle", None),
                            }
                            for descriptor in getattr(characteristic, "descriptors", [])
                        ],
                    }
                )
            services.append(
                {
                    "uuid": str(service.uuid),
                    "handle": getattr(service, "handle", None),
                    "description": getattr(service, "description", None),
                    "characteristics": characteristics,
                }
            )
        return {"services": services, "count": len(services)}

    async def _subscribe(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        client = self._ensure_connected()
        characteristic = str(arguments.get("characteristic", "")).strip()
        if not characteristic:
            raise ReversingMcpError("invalid_request", "characteristic is required")

        def callback(sender: Any, data: bytearray) -> None:
            sender_id = str(getattr(sender, "uuid", sender or characteristic))
            self._record(
                "rx", characteristic=sender_id, data=bytes(data), event="notify"
            )

        await client.start_notify(characteristic, callback)
        self._subscriptions.add(characteristic.lower())
        self._record("meta", characteristic=characteristic, event="subscribe")
        return {"subscribed": True, "characteristic": characteristic}

    async def _unsubscribe(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        client = self._ensure_connected()
        characteristic = str(arguments.get("characteristic", "")).strip()
        if not characteristic:
            raise ReversingMcpError("invalid_request", "characteristic is required")
        await client.stop_notify(characteristic)
        self._subscriptions.discard(characteristic.lower())
        self._record("meta", characteristic=characteristic, event="unsubscribe")
        return {"subscribed": False, "characteristic": characteristic}

    async def _read(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        client = self._ensure_connected()
        characteristic = str(arguments.get("characteristic", "")).strip()
        if not characteristic:
            raise ReversingMcpError("invalid_request", "characteristic is required")
        data = bytes(await client.read_gatt_char(characteristic))
        event = self._record(
            "rx", characteristic=characteristic, data=data, event="read"
        )
        return event

    async def _write(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        client = self._ensure_connected()
        characteristic = str(arguments.get("characteristic", "")).strip()
        if not characteristic:
            raise ReversingMcpError("invalid_request", "characteristic is required")
        data = parse_bytes(arguments.get("data", ""))
        response = bool(arguments.get("response", True))
        await client.write_gatt_char(characteristic, data, response=response)
        event = self._record(
            "tx",
            characteristic=characteristic,
            data=data,
            event="write",
            details={"response": response},
        )
        return {"written": True, **event}

    async def _transcript_get(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        offset = max(0, int(arguments.get("offset", 0)))
        limit = max(1, min(int(arguments.get("limit", 500)), 5000))
        selected = self._transcript[offset : offset + limit]
        return {
            "events": selected,
            "total": len(self._transcript),
            "offset": offset,
            "returned": len(selected),
            "next_offset": offset + len(selected)
            if offset + len(selected) < len(self._transcript)
            else None,
        }

    async def _transcript_clear(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        del arguments
        count = len(self._transcript)
        self._transcript.clear()
        self._sequence = 0
        self._started_ns = time.monotonic_ns()
        return {"cleared": count}

    async def _transcript_save(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        path_value = str(arguments.get("path", "")).strip()
        if not path_value:
            raise ReversingMcpError("invalid_request", "path is required")
        path = Path(path_value).expanduser().resolve()
        if path.exists() and not bool(arguments.get("overwrite", False)):
            raise ReversingMcpError(
                "output_exists", f"Refusing to overwrite transcript: {path}"
            )
        if not path.parent.is_dir():
            raise ReversingMcpError(
                "output_directory_not_found", f"Directory does not exist: {path.parent}"
            )
        format_name = str(arguments.get("format", "jsonl")).lower()
        if format_name == "jsonl":
            content = "".join(
                json.dumps(event, separators=(",", ":")) + "\n"
                for event in self._transcript
            )
        elif format_name == "json":
            content = json.dumps(self._transcript, indent=2) + "\n"
        else:
            raise ReversingMcpError(
                "invalid_request", "Transcript format must be json or jsonl"
            )
        path.write_text(content, encoding="utf-8")
        return {
            "saved": True,
            "path": str(path),
            "format": format_name,
            "events": len(self._transcript),
            "bytes": len(content.encode("utf-8")),
        }

    async def save(self) -> Any:
        raise ReversingMcpError(
            "unsupported_capability", "BLE sessions do not save provider databases"
        )

    async def close(self, *, save: bool = True) -> Any:
        del save
        if self._closed:
            return {"closed": True, "already_closed": True}
        if self._client is not None and self._client.is_connected:
            await self._client.disconnect()
        self._subscriptions.clear()
        self._closed = True
        return {"closed": True, "events": len(self._transcript)}


class BluetoothLeBackend(AnalysisBackend):
    def __init__(self) -> None:
        super().__init__(
            provider_id="bluetooth_le",
            display_name="Bluetooth Low Energy",
            capabilities=BLE_CAPABILITIES,
            operations=BLE_OPERATIONS,
        )

    async def open(self, request: SessionRequest) -> AnalysisSession:
        if request.lifecycle != LifecycleAction.OPEN:
            raise ReversingMcpError(
                "unsupported_lifecycle", "Bluetooth LE sessions only support open"
            )
        try:
            bleak = importlib.import_module("bleak")
        except ImportError as error:
            raise ReversingMcpError(
                "dependency_missing",
                "Bluetooth LE support requires the optional 'bleak' package",
                details={"remediation": "python -m pip install bleak"},
            ) from error
        return BluetoothLeSession(
            bleak,
            request.target_path,
            adapter=str(request.options.get("adapter", "")),
        )
