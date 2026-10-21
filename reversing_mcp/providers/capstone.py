"""Lightweight, read-only disassembly through the optional Capstone engine."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
from importlib import metadata
from pathlib import Path
from typing import Any, Mapping

from ..backends import AnalysisBackend, AnalysisSession
from ..capstone_engine import (
    architecture_catalog,
    disassemble,
    resolve_architecture,
    resolve_configuration,
)
from ..errors import ReversingMcpError
from ..models import (
    Capability,
    CommonOperation,
    LifecycleAction,
    OperationSpec,
    SessionRequest,
)
from ..protocols import parse_bytes


_MAX_READ_BYTES = 1024 * 1024
_ARCHITECTURES_OPERATION = "capstone.architectures.list"
_BASE_OPERATIONS = (
    OperationSpec(CommonOperation.TARGET_INFO, "target.info"),
    OperationSpec(
        CommonOperation.ANALYSIS_DISASSEMBLE, Capability.ANALYSIS_DISASSEMBLE
    ),
    OperationSpec(_ARCHITECTURES_OPERATION, _ARCHITECTURES_OPERATION),
)
_MEMORY_OPERATION = OperationSpec(CommonOperation.MEMORY_READ, "memory.read")

CAPSTONE_CAPABILITIES = frozenset(
    {
        Capability.LIFECYCLE_OPEN,
        Capability.LIFECYCLE_CLOSE,
        Capability.ANALYSIS_DISASSEMBLE,
        "target.info",
        "memory.read",
        _ARCHITECTURES_OPERATION,
    }
)
CAPSTONE_OPERATIONS = (*_BASE_OPERATIONS, _MEMORY_OPERATION)


def _integer(value: Any, field: str, *, default: int | None = None) -> int:
    if value is None or value == "":
        if default is not None:
            return default
        raise ReversingMcpError("invalid_request", f"{field} is required")
    try:
        result = value if isinstance(value, int) else int(str(value), 0)
    except (TypeError, ValueError) as error:
        raise ReversingMcpError(
            "invalid_request", f"{field} must be an integer"
        ) from error
    if result < 0:
        raise ReversingMcpError("invalid_request", f"{field} must be zero or greater")
    return result


def _installed_version() -> str:
    try:
        return metadata.version("capstone")
    except metadata.PackageNotFoundError:
        return ""


class CapstoneSession(AnalysisSession):
    def __init__(
        self,
        module: Any,
        *,
        target_path: str,
        options: Mapping[str, Any],
    ) -> None:
        operations = CAPSTONE_OPERATIONS if target_path else _BASE_OPERATIONS
        capabilities = {
            Capability.LIFECYCLE_OPEN,
            Capability.LIFECYCLE_CLOSE,
            *(operation.capability for operation in operations),
        }
        super().__init__(
            provider_id="capstone",
            target_path=target_path,
            mode="headless",
            capabilities=frozenset(capabilities),
            operations=operations,
        )
        self._capstone = module
        self._architecture = options.get("architecture", options.get("arch", ""))
        self._mode = options.get("mode")
        self._endian = options.get("endian", options.get("endianness", "little"))
        self._base_address = _integer(
            options.get("base_address"), "base_address", default=0
        )
        self._default_offset = _integer(options.get("offset"), "offset", default=0)
        self._closed = False
        self._lock = asyncio.Lock()

    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        async with self._lock:
            return await asyncio.to_thread(
                self._invoke_sync, operation, dict(arguments)
            )

    async def save(self) -> Any:
        raise ReversingMcpError(
            "unsupported_capability", "Capstone sessions have no persistent state"
        )

    async def close(self, *, save: bool = True) -> Any:
        del save
        async with self._lock:
            already_closed = self._closed
            self._closed = True
            return {"closed": True, "already_closed": already_closed}

    def _ensure_open(self) -> None:
        if self._closed:
            raise ReversingMcpError("session_closed", "Capstone session is closed")

    def _file_position(self, arguments: Mapping[str, Any]) -> tuple[int, int]:
        has_offset = "file_offset" in arguments or "offset" in arguments
        has_address = "address" in arguments
        if has_offset and has_address:
            raise ReversingMcpError(
                "invalid_request", "Specify either address or file_offset, not both"
            )
        if has_address:
            address = _integer(arguments["address"], "address")
            if address < self._base_address:
                raise ReversingMcpError(
                    "invalid_address",
                    "address is below the configured base_address",
                    details={"address": address, "base_address": self._base_address},
                )
            return address - self._base_address, address
        offset = _integer(
            arguments.get("file_offset", arguments.get("offset")),
            "file_offset",
            default=self._default_offset,
        )
        return offset, self._base_address + offset

    def _read_file(
        self, arguments: Mapping[str, Any], *, default_size: int
    ) -> tuple[bytes, dict[str, Any], int]:
        if not self.target_path:
            raise ReversingMcpError(
                "target_required", "This operation requires a file-backed session"
            )
        offset, address = self._file_position(arguments)
        size = _integer(arguments.get("size"), "size", default=default_size)
        if size <= 0 or size > _MAX_READ_BYTES:
            raise ReversingMcpError(
                "invalid_size",
                f"size must be between 1 and {_MAX_READ_BYTES} bytes",
            )
        path = Path(self.target_path)
        file_size = path.stat().st_size
        if offset >= file_size:
            raise ReversingMcpError(
                "invalid_offset",
                "file_offset is outside the target",
                details={"file_offset": offset, "file_size": file_size},
            )
        with path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(size)
        return (
            data,
            {
                "kind": "file",
                "path": self.target_path,
                "file_offset": offset,
                "requested_size": size,
                "truncated_at_eof": len(data) < size,
            },
            address,
        )

    def _disassembly_input(
        self, arguments: Mapping[str, Any]
    ) -> tuple[bytes, dict[str, Any], int]:
        if "data" not in arguments:
            return self._read_file(arguments, default_size=4096)
        data = parse_bytes(arguments.get("data"), field="data")
        if not data:
            raise ReversingMcpError("invalid_request", "data cannot be empty")
        if len(data) > _MAX_READ_BYTES:
            raise ReversingMcpError(
                "invalid_size", f"data cannot exceed {_MAX_READ_BYTES} bytes"
            )
        address = _integer(
            arguments.get("address"), "address", default=self._base_address
        )
        return data, {"kind": "inline", "size": len(data)}, address

    def _target_info(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "engine": "capstone",
            "engine_version": getattr(self._capstone, "__version__", ""),
            "configured_architecture": self._architecture or None,
            "configured_mode": self._mode,
            "configured_endian": self._endian,
            "base_address": self._base_address,
            "default_offset": self._default_offset,
            "read_only": True,
        }
        if not self.target_path:
            result.update({"source": "inline", "path": None, "size": 0})
            return result
        path = Path(self.target_path)
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result.update(
            {
                "source": "file",
                "path": self.target_path,
                "size": path.stat().st_size,
                "sha256": digest.hexdigest(),
            }
        )
        return result

    def _memory_read(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        data, source, address = self._read_file(arguments, default_size=256)
        return {
            "address": address,
            "address_hex": f"0x{address:x}",
            "size": len(data),
            "hex": data.hex(),
            "base64": base64.b64encode(data).decode("ascii"),
            "sha256": hashlib.sha256(data).hexdigest(),
            "source": source,
        }

    def _disassemble(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        config = resolve_configuration(
            self._capstone,
            architecture=arguments.get(
                "architecture", arguments.get("arch", self._architecture)
            ),
            mode=arguments.get("mode", self._mode),
            endian=arguments.get("endian", arguments.get("endianness", self._endian)),
        )
        data, source, address = self._disassembly_input(arguments)
        result = disassemble(
            self._capstone,
            data,
            address,
            config,
            count=_integer(arguments.get("count"), "count", default=256),
            skipdata=bool(arguments.get("skipdata", False)),
            syntax=str(arguments.get("syntax", "")).strip().lower(),
        )
        result["source"] = {
            **source,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        return result

    def _invoke_sync(self, operation: str, arguments: dict[str, Any]) -> Any:
        self._ensure_open()
        if operation == CommonOperation.TARGET_INFO:
            return self._target_info()
        if operation == CommonOperation.ANALYSIS_DISASSEMBLE:
            return self._disassemble(arguments)
        if operation == CommonOperation.MEMORY_READ:
            return self._memory_read(arguments)
        if operation == _ARCHITECTURES_OPERATION:
            return {
                "engine_version": getattr(self._capstone, "__version__", ""),
                "architectures": architecture_catalog(self._capstone),
            }
        raise ReversingMcpError(
            "unsupported_operation", f"Unsupported operation: {operation}"
        )


class CapstoneBackend(AnalysisBackend):
    def __init__(self) -> None:
        super().__init__(
            provider_id="capstone",
            display_name="Capstone disassembler",
            capabilities=CAPSTONE_CAPABILITIES,
            operations=CAPSTONE_OPERATIONS,
            version=_installed_version(),
        )

    async def open(self, request: SessionRequest) -> AnalysisSession:
        if request.lifecycle != LifecycleAction.OPEN:
            raise ReversingMcpError(
                "unsupported_lifecycle", "Capstone sessions only support open"
            )
        if request.mode not in {"", "headless"}:
            raise ReversingMcpError(
                "unsupported_mode", "Capstone only supports headless sessions"
            )
        try:
            capstone = importlib.import_module("capstone")
        except ImportError as error:
            raise ReversingMcpError(
                "dependency_missing",
                "Capstone is not installed in this interpreter",
                details={"provider": "capstone", "dependency": "capstone"},
            ) from error

        target_path = ""
        if request.target_path:
            path = Path(request.target_path).expanduser().resolve()
            if not path.is_file():
                raise ReversingMcpError(
                    "target_not_found", f"Capstone target does not exist: {path}"
                )
            target_path = str(path)

        architecture = request.options.get(
            "architecture", request.options.get("arch", "")
        )
        if architecture:
            resolve_architecture(capstone, architecture)
        return CapstoneSession(
            capstone,
            target_path=target_path,
            options=request.options,
        )
