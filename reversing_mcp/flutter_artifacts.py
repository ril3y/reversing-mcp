"""Static Flutter package inspection built on the Android artifact layer."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Mapping

from .errors import ReversingMcpError

if TYPE_CHECKING:
    from .android_artifacts import AndroidArtifact, ArchiveEntry

_TEXT_ASSET_SUFFIXES = {
    ".arb",
    ".css",
    ".csv",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".plist",
    ".svg",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
_STANDARD_NATIVE_LIBRARIES = {
    "libapp.so",
    "libc++_shared.so",
    "libflutter.so",
}
_CHANNEL_PATTERN = re.compile(r"[a-z][A-Za-z0-9_.-]{1,79}/[A-Za-z0-9_./:-]{2,160}")
_DEX_CLASS_PATTERN = re.compile(r"L([A-Za-z0-9_$/-]{4,240});")
_PRINTABLE_STRING_PATTERN = re.compile(rb"[\x20-\x7e]{4,512}")


@dataclass(frozen=True, slots=True)
class FlutterNativeTarget:
    path: str
    container: str
    module: str
    abi: str
    name: str
    kind: str
    loading_unit: int | None
    size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "container": self.container,
            "module": self.module,
            "abi": self.abi,
            "name": self.name,
            "kind": self.kind,
            "loading_unit": self.loading_unit,
            "size": self.size,
        }


def _inner_parts(path: str) -> tuple[str, tuple[str, ...]]:
    if "!/" in path:
        container, inner = path.split("!/", 1)
    else:
        container, inner = "", path
    return container, PurePosixPath(inner).parts


def _native_target(entry: ArchiveEntry) -> FlutterNativeTarget | None:
    container, parts = _inner_parts(entry.path)
    try:
        lib_index = parts.index("lib")
    except ValueError:
        return None
    if len(parts) != lib_index + 3:
        return None
    abi, name = parts[lib_index + 1 :]
    match = re.fullmatch(r"libapp\.so(?:-(\d+)\.part\.so)?", name)
    if match:
        kind = "aot-loading-unit" if match.group(1) else "aot"
        loading_unit = int(match.group(1)) if match.group(1) else None
    elif name == "libflutter.so":
        kind = "engine"
        loading_unit = None
    else:
        return None
    return FlutterNativeTarget(
        path=entry.path,
        container=container or entry.container,
        module="/".join(parts[:lib_index]),
        abi=abi,
        name=name,
        kind=kind,
        loading_unit=loading_unit,
        size=entry.size,
    )


def _asset_relative(path: str) -> str | None:
    _, parts = _inner_parts(path)
    for index in range(len(parts) - 1):
        if parts[index : index + 2] == ("assets", "flutter_assets"):
            return "/".join(parts[index + 2 :])
    return None


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for index in range(5):
        if offset + index >= len(data):
            raise ValueError("truncated ULEB128")
        byte = data[offset + index]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset + index + 1
        shift += 7
    raise ValueError("invalid ULEB128")


def dex_strings(data: bytes) -> list[str]:
    """Read a DEX string table, with a bounded fallback for malformed fixtures."""
    if len(data) >= 0x70 and data.startswith(b"dex\n"):
        try:
            count, table_offset = struct.unpack_from("<II", data, 0x38)
            if count > 5_000_000 or table_offset + count * 4 > len(data):
                raise ValueError("invalid string table")
            values = []
            for index in range(count):
                (string_offset,) = struct.unpack_from(
                    "<I", data, table_offset + index * 4
                )
                _, content_offset = _uleb128(data, string_offset)
                end = data.find(b"\0", content_offset)
                if end < 0:
                    raise ValueError("unterminated DEX string")
                values.append(
                    data[content_offset:end].decode("utf-8", errors="replace")
                )
            return values
        except (ValueError, struct.error):
            pass
    return [
        match.group(0).decode("ascii", errors="ignore")
        for match in _PRINTABLE_STRING_PATTERN.finditer(data)
    ]


def _channel_candidates(strings: list[str]) -> set[str]:
    candidates = set()
    for value in strings:
        if value.startswith("L") and value.endswith(";"):
            continue
        for match in _CHANNEL_PATTERN.finditer(value):
            candidate = match.group(0).strip("./:-")
            lower = candidate.lower()
            if candidate != lower or ";" in candidate:
                continue
            if any(
                marker in lower
                for marker in (
                    ".dart",
                    ".java",
                    ".json",
                    ".kt",
                    ".png",
                    ".xml",
                    "docs.flutter.",
                )
            ):
                continue
            if lower.startswith(
                ("android/", "androidx/", "java/", "kotlin/", "kotlinx/")
            ):
                continue
            reverse_domain = re.match(r"(?:com|dev|io|org)\.[a-z0-9_.-]+/", lower)
            if not reverse_domain and not any(
                token in lower for token in ("flutter", "plugin", "channel")
            ):
                continue
            candidates.add(candidate)
    return candidates


class FlutterArtifactInspector:
    """Inspect Flutter packaging without requiring JADX or an AOT analyzer."""

    def __init__(self, artifact: AndroidArtifact) -> None:
        self.artifact = artifact
        self._entries = tuple(artifact.iter_entries(include_nested=True))

    def native_targets(self) -> dict[str, Any]:
        targets = [
            target.to_dict()
            for entry in self._entries
            if (target := _native_target(entry)) is not None
        ]
        return {"artifact": str(self.artifact.path), "targets": targets}

    def variants(self) -> dict[str, Any]:
        grouped: dict[str, dict[str, Any]] = {}
        for row in self.native_targets()["targets"]:
            variant = grouped.setdefault(
                row["abi"],
                {
                    "abi": row["abi"],
                    "engine": None,
                    "aot": None,
                    "loading_units": [],
                },
            )
            if row["kind"] == "engine":
                variant["engine"] = row
            elif row["kind"] == "aot":
                variant["aot"] = row
            else:
                variant["loading_units"].append(row)
        for variant in grouped.values():
            variant["complete"] = bool(variant["aot"] and variant["engine"])
            variant["loading_units"].sort(key=lambda item: item["loading_unit"] or 0)
        return {
            "artifact": str(self.artifact.path),
            "variants": [grouped[key] for key in sorted(grouped)],
        }

    def inspect(self) -> dict[str, Any]:
        native = self.native_targets()["targets"]
        assets = [
            {"path": entry.path, "relative_path": relative, "size": entry.size}
            for entry in self._entries
            if (relative := _asset_relative(entry.path)) is not None
        ]
        paths = {entry.path.lower() for entry in self._entries}
        has_assets = bool(assets)
        has_engine = any(row["kind"] == "engine" for row in native)
        has_aot = any(row["kind"] in {"aot", "aot-loading-unit"} for row in native)
        has_kernel = any(path.endswith("/kernel_blob.bin") for path in paths)
        detected = has_assets or has_engine or has_aot
        if has_kernel:
            build_mode = "debug-or-jit"
        elif has_aot:
            build_mode = "release-or-profile-aot"
        else:
            build_mode = "unknown"
        evidence = []
        evidence.extend(row["path"] for row in native[:25])
        evidence.extend(row["path"] for row in assets[:25])
        return {
            "framework": "flutter",
            "detected": detected,
            "artifact": str(self.artifact.path),
            "build_mode": build_mode,
            "has_flutter_assets": has_assets,
            "has_flutter_engine": has_engine,
            "has_dart_aot": has_aot,
            "asset_count": len(assets),
            "native_target_count": len(native),
            "abis": sorted({row["abi"] for row in native}),
            "deferred_loading_units": sum(
                row["kind"] == "aot-loading-unit" for row in native
            ),
            "evidence": evidence,
            "evidence_truncated": len(native) + len(assets) > len(evidence),
            "limitations": [
                "Packaging markers identify Flutter but do not recover original "
                "Dart source.",
                "Build mode is inferred from packaged kernel and AOT artifacts.",
            ],
        }

    def list_assets(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        prefix = str(arguments.get("prefix", ""))
        suffix = str(arguments.get("suffix", ""))
        limit = max(1, min(int(arguments.get("limit", 500)), 5000))
        matches = []
        total = 0
        for entry in self._entries:
            relative = _asset_relative(entry.path)
            if relative is None:
                continue
            if prefix and not relative.startswith(prefix):
                continue
            if suffix and not relative.lower().endswith(suffix.lower()):
                continue
            total += 1
            if len(matches) < limit:
                matches.append(
                    {"path": entry.path, "relative_path": relative, "size": entry.size}
                )
        return {
            "artifact": str(self.artifact.path),
            "assets": matches,
            "matched": total,
            "returned": len(matches),
            "truncated": total > len(matches),
        }

    def search_assets(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        query = str(arguments.get("query", ""))
        if not query:
            raise ReversingMcpError("invalid_request", "query cannot be empty")
        case_sensitive = bool(arguments.get("case_sensitive", False))
        context = max(0, min(int(arguments.get("context_chars", 160)), 2000))
        limit = max(1, min(int(arguments.get("limit", 100)), 1000))
        needle = query if case_sensitive else query.casefold()
        results = []
        searched = 0
        skipped = []
        for row in self.list_assets({"limit": 5000})["assets"]:
            suffix = PurePosixPath(row["relative_path"]).suffix.lower()
            if suffix not in _TEXT_ASSET_SUFFIXES:
                continue
            if row["size"] > 8 * 1024 * 1024:
                skipped.append({"path": row["path"], "reason": "size limit"})
                continue
            data = self.artifact.read_member(row["path"], max_bytes=8 * 1024 * 1024)
            text = data.decode("utf-8", errors="replace")
            haystack = text if case_sensitive else text.casefold()
            searched += 1
            start = 0
            while (index := haystack.find(needle, start)) >= 0:
                results.append(
                    {
                        "path": row["path"],
                        "relative_path": row["relative_path"],
                        "line": text.count("\n", 0, index) + 1,
                        "start": index,
                        "context": text[
                            max(0, index - context) : index + len(query) + context
                        ],
                    }
                )
                if len(results) >= limit:
                    return {
                        "query": query,
                        "results": results,
                        "searched_files": searched,
                        "truncated": True,
                        "skipped": skipped,
                    }
                start = index + max(1, len(needle))
        return {
            "query": query,
            "results": results,
            "searched_files": searched,
            "truncated": False,
            "skipped": skipped,
        }

    def plugins(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        limit = max(1, min(int(arguments.get("limit", 250)), 2000))
        query = str(arguments.get("query", "")).casefold()
        candidates: dict[tuple[str, str], dict[str, Any]] = {}
        for entry in self._entries:
            lower = entry.path.lower()
            if lower.endswith(".dex") and entry.size <= 64 * 1024 * 1024:
                data = self.artifact.read_member(entry.path)
                for string in dex_strings(data):
                    for match in _DEX_CLASS_PATTERN.finditer(string):
                        name = match.group(1).lstrip("L")
                        basename = name.rsplit("/", 1)[-1].lower()
                        if not (
                            basename.endswith("plugin")
                            or "pluginregistrant" in basename
                        ):
                            continue
                        value = name.replace("/", ".")
                        candidates[("android-class", value)] = {
                            "name": value,
                            "kind": "android-class",
                            "evidence": entry.path,
                            "confidence": "candidate",
                        }
            container, parts = _inner_parts(entry.path)
            if "lib" not in parts or not entry.path.lower().endswith(".so"):
                continue
            name = parts[-1]
            if name in _STANDARD_NATIVE_LIBRARIES:
                continue
            candidates[("native-library", name)] = {
                "name": name,
                "kind": "native-library",
                "evidence": entry.path,
                "container": container or entry.container,
                "confidence": "candidate",
            }
        rows = sorted(
            candidates.values(), key=lambda item: (item["kind"], item["name"])
        )
        if query:
            rows = [row for row in rows if query in str(row["name"]).casefold()]
        return {
            "artifact": str(self.artifact.path),
            "plugins": rows[:limit],
            "matched": len(rows),
            "truncated": len(rows) > limit,
            "limitations": [
                "Results are packaging candidates, not proof that a plugin executes.",
                "Tree shaking and generated registrants can hide plugin identities.",
            ],
        }

    def channels(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        limit = max(1, min(int(arguments.get("limit", 250)), 2000))
        query = str(arguments.get("query", "")).casefold()
        values: dict[str, set[str]] = {}
        for entry in self._entries:
            target = _native_target(entry)
            if not entry.path.lower().endswith(".dex") and not (
                target and target.kind in {"aot", "aot-loading-unit"}
            ):
                continue
            if entry.size > 64 * 1024 * 1024:
                continue
            data = self.artifact.read_member(entry.path)
            strings = (
                dex_strings(data)
                if entry.path.lower().endswith(".dex")
                else [
                    match.group(0).decode("ascii", errors="ignore")
                    for match in _PRINTABLE_STRING_PATTERN.finditer(data)
                ]
            )
            for value in _channel_candidates(strings):
                values.setdefault(value, set()).add(entry.path)
        rows = [
            {
                "name": name,
                "evidence": sorted(paths),
                "confidence": "likely"
                if name.startswith(("com.", "dev.", "io.", "org."))
                and not name.startswith("docs.")
                else "candidate",
            }
            for name, paths in sorted(values.items())
            if not query or query in name.casefold()
        ]
        return {
            "artifact": str(self.artifact.path),
            "channels": rows[:limit],
            "matched": len(rows),
            "truncated": len(rows) > limit,
            "limitations": [
                "Candidates come from static printable strings; dynamic channel "
                "names are unknown.",
                "A candidate string does not prove runtime registration or use.",
            ],
        }

    def extract_native_pair(self, abi: str, output_directory: str) -> dict[str, Any]:
        variants = self.variants()["variants"]
        selected = next((row for row in variants if row["abi"] == abi), None)
        if selected is None:
            raise ReversingMcpError(
                "flutter_abi_not_found",
                f"Flutter ABI is not present: {abi}",
                details={"available_abis": [row["abi"] for row in variants]},
            )
        if not selected["aot"]:
            raise ReversingMcpError(
                "flutter_aot_not_found", f"No libapp.so is present for ABI {abi}"
            )
        paths = [selected["aot"]["path"]]
        if selected["engine"]:
            paths.append(selected["engine"]["path"])
        result = self.artifact.extract(
            {
                "paths": paths,
                "output_directory": output_directory,
                "overwrite": True,
            }
        )
        files = {PurePosixPath(row["member"]).name: row for row in result["files"]}
        return {
            "abi": abi,
            "libapp": files["libapp.so"],
            "libflutter": files.get("libflutter.so"),
            "loading_units": selected["loading_units"],
        }
