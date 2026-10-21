"""Provider-independent helpers for checksums and register protocols."""

from __future__ import annotations

import math
import struct
from typing import Any, Iterable, Mapping

from .errors import ReversingMcpError


def parse_bytes(value: Any, *, field: str = "data") -> bytes:
    """Decode a byte argument from hex text, an integer list, or bytes."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, (list, tuple)):
        try:
            return bytes(int(item) for item in value)
        except (TypeError, ValueError, OverflowError) as error:
            raise ReversingMcpError(
                "invalid_bytes", f"'{field}' must contain byte values"
            ) from error
    if isinstance(value, str):
        compact = value.strip().replace("0x", "").replace("0X", "")
        for separator in (" ", ":", "-", "_", "\n", "\r", "\t", ","):
            compact = compact.replace(separator, "")
        if len(compact) % 2:
            raise ReversingMcpError(
                "invalid_bytes", f"'{field}' contains an odd number of hex digits"
            )
        try:
            return bytes.fromhex(compact)
        except ValueError as error:
            raise ReversingMcpError(
                "invalid_bytes", f"'{field}' is not valid hexadecimal data"
            ) from error
    raise ReversingMcpError(
        "invalid_bytes", f"'{field}' must be hex text, bytes, or a byte list"
    )


def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def _crc16_arc(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def _crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else crc << 1
    return crc & 0xFFFF


def _crc16_x25(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return (crc ^ 0xFFFF) & 0xFFFF


def _crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def _checksum8(data: bytes) -> int:
    return sum(data) & 0xFF


def _lrc8(data: bytes) -> int:
    return (-sum(data)) & 0xFF


def _xor8(data: bytes) -> int:
    result = 0
    for byte in data:
        result ^= byte
    return result


_ALGORITHMS = {
    "crc16-modbus": (2, crc16_modbus),
    "crc16-arc": (2, _crc16_arc),
    "crc16-ccitt-false": (2, _crc16_ccitt_false),
    "crc16-x25": (2, _crc16_x25),
    "crc8": (1, _crc8),
    "sum8": (1, _checksum8),
    "lrc8": (1, _lrc8),
    "xor8": (1, _xor8),
}

_ALIASES = {
    "modbus": "crc16-modbus",
    "modbus-rtu": "crc16-modbus",
    "crc-16/modbus": "crc16-modbus",
    "arc": "crc16-arc",
    "ibm": "crc16-arc",
    "ccitt": "crc16-ccitt-false",
    "x25": "crc16-x25",
}


def _algorithm(name: str):
    normalized = name.strip().lower().replace("_", "-")
    normalized = _ALIASES.get(normalized, normalized)
    try:
        return normalized, _ALGORITHMS[normalized]
    except KeyError as error:
        raise ReversingMcpError(
            "unsupported_algorithm",
            f"Unsupported checksum algorithm: {name}",
            details={"algorithms": sorted(_ALGORITHMS)},
        ) from error


def checksum_verify(arguments: Mapping[str, Any]) -> dict[str, Any]:
    name, (width, function) = _algorithm(str(arguments.get("algorithm", "modbus")))
    frame = parse_bytes(arguments.get("frame", arguments.get("data", "")))
    byte_order = str(arguments.get("byte_order", "little")).lower()
    if byte_order not in {"little", "big"}:
        raise ReversingMcpError(
            "invalid_request", "byte_order must be 'little' or 'big'"
        )
    supplied = arguments.get("checksum")
    if supplied is None:
        if len(frame) <= width:
            raise ReversingMcpError(
                "invalid_request", "Frame is too short to contain a checksum"
            )
        data, checksum_bytes = frame[:-width], frame[-width:]
        expected = int.from_bytes(checksum_bytes, byte_order)
    else:
        data = frame
        checksum_bytes = parse_bytes(supplied, field="checksum")
        if len(checksum_bytes) != width:
            raise ReversingMcpError(
                "invalid_request", f"{name} checksums are {width} byte(s)"
            )
        expected = int.from_bytes(checksum_bytes, byte_order)
    calculated = function(data)
    return {
        "algorithm": name,
        "valid": calculated == expected,
        "data_hex": data.hex(),
        "expected": expected,
        "expected_hex": expected.to_bytes(width, byte_order).hex(),
        "calculated": calculated,
        "calculated_hex": calculated.to_bytes(width, byte_order).hex(),
        "byte_order": byte_order,
    }


def checksum_detect(arguments: Mapping[str, Any]) -> dict[str, Any]:
    values = arguments.get("frames")
    if values is None:
        values = [arguments.get("frame", "")]
    if not isinstance(values, list) or not values:
        raise ReversingMcpError("invalid_request", "Provide one or more frames")
    frames = [parse_bytes(value, field="frames") for value in values]
    matches = []
    for name, (width, function) in _ALGORITHMS.items():
        for byte_order in ("little", "big") if width > 1 else ("big",):
            results = []
            for frame in frames:
                if len(frame) <= width:
                    results.append(False)
                    continue
                expected = int.from_bytes(frame[-width:], byte_order)
                results.append(function(frame[:-width]) == expected)
            match_count = sum(results)
            if match_count:
                matches.append(
                    {
                        "algorithm": name,
                        "byte_order": byte_order,
                        "match_count": match_count,
                        "frame_count": len(frames),
                        "all_frames": match_count == len(frames),
                        "matches": results,
                    }
                )
    matches.sort(key=lambda item: (-item["match_count"], item["algorithm"]))
    return {
        "frame_count": len(frames),
        "matches": matches,
        "conclusive": bool(matches and matches[0]["all_frames"]),
    }


def modbus_decode(arguments: Mapping[str, Any]) -> dict[str, Any]:
    frame = parse_bytes(arguments.get("frame", ""), field="frame")
    include_crc = bool(arguments.get("include_crc", True))
    if len(frame) < (4 if include_crc else 2):
        raise ReversingMcpError("invalid_request", "Modbus RTU frame is too short")
    payload = frame[:-2] if include_crc else frame
    result: dict[str, Any] = {
        "frame_hex": frame.hex(),
        "address": payload[0],
        "function": payload[1],
    }
    if include_crc:
        expected = int.from_bytes(frame[-2:], "little")
        calculated = crc16_modbus(payload)
        result["crc"] = {
            "valid": expected == calculated,
            "expected": f"{expected:04x}",
            "calculated": f"{calculated:04x}",
        }
    function = payload[1]
    body = payload[2:]
    direction = str(arguments.get("direction", "auto")).lower()
    if direction not in {"auto", "request", "response"}:
        raise ReversingMcpError(
            "invalid_request", "direction must be auto, request, or response"
        )
    if function & 0x80:
        result.update(
            {
                "kind": "exception",
                "base_function": function & 0x7F,
                "exception_code": body[0] if body else None,
            }
        )
    elif (
        function in {1, 2, 3, 4}
        and body
        and (
            direction == "response"
            or (direction == "auto" and len(body) == body[0] + 1)
        )
    ):
        byte_count = body[0]
        data = body[1 : 1 + byte_count]
        result.update({"kind": "read_response", "byte_count": byte_count})
        if function in {3, 4}:
            result["registers"] = [
                int.from_bytes(data[index : index + 2], "big")
                for index in range(0, len(data) - 1, 2)
            ]
        else:
            result["bits"] = [
                bool(byte & (1 << bit)) for byte in data for bit in range(8)
            ]
        if len(data) != byte_count:
            result["truncated"] = True
    elif function in {15, 16} and len(body) > 4:
        byte_count = body[4]
        data = body[5 : 5 + byte_count]
        result.update(
            {
                "kind": "write_request",
                "start_register": int.from_bytes(body[:2], "big"),
                "register_count": int.from_bytes(body[2:4], "big"),
                "byte_count": byte_count,
                "data_hex": data.hex(),
            }
        )
        if function == 16:
            result["registers"] = [
                int.from_bytes(data[index : index + 2], "big")
                for index in range(0, len(data) - 1, 2)
            ]
        if len(data) != byte_count:
            result["truncated"] = True
    elif function in {5, 6, 15, 16} and len(body) >= 4:
        kind = (
            "write_request"
            if direction == "request"
            else "write_response"
            if direction == "response"
            else "write_request_or_response"
        )
        result.update(
            {
                "kind": kind,
                "register": int.from_bytes(body[:2], "big"),
                "value_or_count": int.from_bytes(body[2:4], "big"),
            }
        )
    elif function in {1, 2, 3, 4} and len(body) >= 4:
        result.update(
            {
                "kind": "read_request",
                "start_register": int.from_bytes(body[:2], "big"),
                "register_count": int.from_bytes(body[2:4], "big"),
            }
        )
    else:
        result.update({"kind": "raw", "payload_hex": body.hex()})
    return result


def _register_words(arguments: Mapping[str, Any]) -> list[int]:
    supplied = arguments.get("registers")
    if supplied is not None:
        if not isinstance(supplied, list):
            raise ReversingMcpError("invalid_request", "registers must be a list")
        try:
            words = [int(value) for value in supplied]
        except (TypeError, ValueError) as error:
            raise ReversingMcpError(
                "invalid_request", "registers must contain integers"
            ) from error
        if any(value < 0 or value > 0xFFFF for value in words):
            raise ReversingMcpError(
                "invalid_request", "register values must fit in 16 bits"
            )
        return words
    data = parse_bytes(arguments.get("data", ""))
    if len(data) % 2:
        raise ReversingMcpError(
            "invalid_request", "Register data must contain an even byte count"
        )
    return [
        int.from_bytes(data[index : index + 2], "big")
        for index in range(0, len(data), 2)
    ]


def _ordered_bytes(words: Iterable[int], word_order: str) -> bytes:
    parts = [int(word).to_bytes(2, "big") for word in words]
    if word_order in {"little", "swap", "low-first"}:
        parts.reverse()
    elif word_order not in {"big", "high-first"}:
        raise ReversingMcpError(
            "invalid_request", f"Unsupported word order: {word_order}"
        )
    return b"".join(parts)


def _decode_register_value(raw: bytes, type_name: str, byte_order: str) -> Any:
    if byte_order == "little":
        raw = b"".join(raw[index : index + 2][::-1] for index in range(0, len(raw), 2))
    elif byte_order != "big":
        raise ReversingMcpError(
            "invalid_request", f"Unsupported byte order: {byte_order}"
        )
    signed = type_name.startswith("s") or type_name.startswith("int")
    if type_name in {"u16", "s16", "uint16", "int16"}:
        return int.from_bytes(raw, "big", signed=signed)
    if type_name in {"u32", "s32", "uint32", "int32"}:
        return int.from_bytes(raw, "big", signed=signed)
    if type_name in {"u64", "s64", "uint64", "int64"}:
        return int.from_bytes(raw, "big", signed=signed)
    if type_name in {"float", "float32"}:
        return struct.unpack(">f", raw)[0]
    if type_name in {"double", "float64"}:
        return struct.unpack(">d", raw)[0]
    if type_name == "ascii":
        return raw.rstrip(b"\x00").decode("ascii", errors="replace")
    if type_name == "hex":
        return raw.hex()
    if type_name == "bcd":
        digits = "".join(f"{byte:02x}" for byte in raw)
        if any(character not in "0123456789" for character in digits):
            return None
        return int(digits)
    raise ReversingMcpError(
        "invalid_request", f"Unsupported register type: {type_name}"
    )


def register_map_decode(arguments: Mapping[str, Any]) -> dict[str, Any]:
    words = _register_words(arguments)
    definitions = arguments.get("map", arguments.get("register_map", []))
    if not isinstance(definitions, list):
        raise ReversingMcpError("invalid_request", "map must be a list")
    start_address = int(arguments.get("start_address", 0))
    decoded = []
    widths = {
        "u16": 1,
        "s16": 1,
        "uint16": 1,
        "int16": 1,
        "u32": 2,
        "s32": 2,
        "uint32": 2,
        "int32": 2,
        "float": 2,
        "float32": 2,
        "u64": 4,
        "s64": 4,
        "uint64": 4,
        "int64": 4,
        "double": 4,
        "float64": 4,
    }
    for definition in definitions:
        if not isinstance(definition, Mapping):
            raise ReversingMcpError(
                "invalid_request", "Every register-map entry must be an object"
            )
        address = int(definition.get("address", start_address))
        offset = address - start_address
        type_name = str(definition.get("type", "u16")).lower()
        count = int(definition.get("register_count", widths.get(type_name, 1)))
        if type_name in {"ascii", "hex", "bcd"}:
            count = int(definition.get("register_count", 1))
        if offset < 0 or offset + count > len(words):
            decoded.append(
                {
                    "name": str(definition.get("name", f"register_{address}")),
                    "address": address,
                    "available": False,
                    "reason": "register range is outside supplied data",
                }
            )
            continue
        selected = words[offset : offset + count]
        raw = _ordered_bytes(selected, str(definition.get("word_order", "big")))
        value = _decode_register_value(
            raw, type_name, str(definition.get("byte_order", "big"))
        )
        scale = float(definition.get("scale", 1))
        addend = float(definition.get("offset", 0))
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = value * scale + addend
            if isinstance(value, float) and math.isfinite(value) and value.is_integer():
                value = int(value)
        decoded.append(
            {
                "name": str(definition.get("name", f"register_{address}")),
                "address": address,
                "available": True,
                "type": type_name,
                "raw_registers": selected,
                "value": value,
                "unit": definition.get("unit"),
            }
        )
    return {
        "start_address": start_address,
        "register_count": len(words),
        "registers": words,
        "values": decoded,
    }
