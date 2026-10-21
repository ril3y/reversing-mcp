"""Offline checksum, Modbus RTU, and register-map provider."""

from __future__ import annotations

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
    register_map_decode,
)


PROTOCOL_OPERATIONS = (
    OperationSpec(CommonOperation.PROTOCOL_CHECKSUM_DETECT, "protocol.checksum.detect"),
    OperationSpec(CommonOperation.PROTOCOL_CHECKSUM_VERIFY, "protocol.checksum.verify"),
    OperationSpec(CommonOperation.PROTOCOL_MODBUS_DECODE, "protocol.modbus.decode"),
    OperationSpec(
        CommonOperation.PROTOCOL_REGISTERS_DECODE, "protocol.registers.decode"
    ),
)

PROTOCOL_CAPABILITIES = frozenset(
    {
        Capability.LIFECYCLE_OPEN,
        Capability.LIFECYCLE_CLOSE,
        *(operation.capability for operation in PROTOCOL_OPERATIONS),
    }
)


class ProtocolSession(AnalysisSession):
    def __init__(self, target_path: str = "") -> None:
        super().__init__(
            provider_id="protocol",
            target_path=target_path,
            mode="headless",
            capabilities=PROTOCOL_CAPABILITIES,
            operations=PROTOCOL_OPERATIONS,
        )
        self._closed = False

    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        if self._closed:
            raise ReversingMcpError("session_closed", "Protocol session is closed")
        routes = {
            CommonOperation.PROTOCOL_CHECKSUM_DETECT: checksum_detect,
            CommonOperation.PROTOCOL_CHECKSUM_VERIFY: checksum_verify,
            CommonOperation.PROTOCOL_MODBUS_DECODE: modbus_decode,
            CommonOperation.PROTOCOL_REGISTERS_DECODE: register_map_decode,
        }
        try:
            function = routes[operation]
        except KeyError as error:
            raise ReversingMcpError(
                "unsupported_operation", f"Unsupported operation: {operation}"
            ) from error
        return function(arguments)

    async def save(self) -> Any:
        raise ReversingMcpError(
            "unsupported_capability", "Protocol sessions have no persistent state"
        )

    async def close(self, *, save: bool = True) -> Any:
        del save
        self._closed = True
        return {"closed": True}


class ProtocolBackend(AnalysisBackend):
    def __init__(self) -> None:
        super().__init__(
            provider_id="protocol",
            display_name="Protocol utilities",
            capabilities=PROTOCOL_CAPABILITIES,
            operations=PROTOCOL_OPERATIONS,
        )

    async def open(self, request: SessionRequest) -> AnalysisSession:
        if request.lifecycle != LifecycleAction.OPEN:
            raise ReversingMcpError(
                "unsupported_lifecycle", "Protocol sessions only support open"
            )
        return ProtocolSession(request.target_path)
