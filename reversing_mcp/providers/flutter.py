"""Headless Flutter package and Dart AOT analysis provider."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any, Callable, Mapping

from ..android_artifacts import AndroidArtifact
from ..backends import AnalysisBackend, AnalysisSession
from ..dart_aot import (
    AotAnalyzer,
    FlutterAnalysisCache,
    configured_analyzer,
    file_sha256,
    normalize_analysis,
    safe_relative_path,
    search_analysis_text,
)
from ..errors import ReversingMcpError
from ..flutter_artifacts import FlutterArtifactInspector
from ..models import (
    Capability,
    CommonOperation,
    LifecycleAction,
    OperationSpec,
    SessionRequest,
)

FLUTTER_OPERATIONS = (
    OperationSpec(CommonOperation.TARGET_INFO, "target.info"),
    OperationSpec("android.framework.detect", "android.framework.detect"),
    OperationSpec("flutter.inspect", "flutter.inspect"),
    OperationSpec("flutter.variants.list", "flutter.variants.list"),
    OperationSpec("flutter.native.targets", "flutter.native.targets"),
    OperationSpec("flutter.assets.list", "flutter.assets.list"),
    OperationSpec("flutter.assets.search", "flutter.assets.search"),
    OperationSpec("flutter.plugins.list", "flutter.plugins.list"),
    OperationSpec("flutter.channels.list", "flutter.channels.list"),
    OperationSpec(CommonOperation.ARTIFACT_ENTRIES_LIST, "artifact.entries.list"),
    OperationSpec(
        CommonOperation.ARTIFACT_FILES_EXTRACT,
        "artifact.files.extract",
        mutating=True,
    ),
    OperationSpec("flutter.aot.status", "flutter.aot.status"),
    OperationSpec("flutter.aot.analyze", "flutter.aot.analyze"),
    OperationSpec("flutter.objects.search", "flutter.objects.search"),
    OperationSpec("flutter.libraries.list", "flutter.libraries.list"),
    OperationSpec(CommonOperation.FUNCTIONS_LIST, "functions.list"),
    OperationSpec(CommonOperation.FUNCTIONS_GET, "functions.get"),
    OperationSpec(CommonOperation.SEARCH_FUNCTIONS, "search.functions"),
    OperationSpec(CommonOperation.SEARCH_STRINGS, "search.strings"),
    OperationSpec(
        CommonOperation.ANALYSIS_DISASSEMBLE, Capability.ANALYSIS_DISASSEMBLE
    ),
)

FLUTTER_CAPABILITIES = frozenset(
    {
        Capability.LIFECYCLE_OPEN,
        Capability.LIFECYCLE_CLOSE,
        Capability.ANALYSIS_DISASSEMBLE,
        *(operation.capability for operation in FLUTTER_OPERATIONS),
    }
)


class FlutterSession(AnalysisSession):
    def __init__(
        self,
        *,
        artifact: AndroidArtifact,
        options: Mapping[str, Any],
        analyzer_factory: Callable[[Mapping[str, Any]], AotAnalyzer],
        cache: FlutterAnalysisCache,
    ) -> None:
        super().__init__(
            provider_id="flutter",
            target_path=str(artifact.path),
            mode="headless",
            capabilities=FLUTTER_CAPABILITIES,
            operations=FLUTTER_OPERATIONS,
        )
        self._artifact = artifact
        self._inspector = FlutterArtifactInspector(artifact)
        self._options = dict(options)
        self._analyzer_factory = analyzer_factory
        self._cache = cache
        self._analysis: dict[str, Any] | None = None
        self._closed = False

    def _ensure_open(self) -> None:
        if self._closed:
            raise ReversingMcpError("session_closed", "Flutter session is closed")

    def _require_analysis(self) -> dict[str, Any]:
        if self._analysis is None:
            raise ReversingMcpError(
                "analysis_required",
                "Run flutter.aot.analyze before querying Dart AOT results",
            )
        return self._analysis

    async def invoke(self, operation: str, arguments: Mapping[str, Any]) -> Any:
        self._ensure_open()
        routes = {
            "android.framework.detect": self._artifact.frameworks_detect,
            "flutter.inspect": self._inspector.inspect,
            "flutter.variants.list": self._inspector.variants,
            "flutter.native.targets": self._inspector.native_targets,
        }
        if operation in routes:
            return await asyncio.to_thread(routes[operation])
        argument_routes = {
            CommonOperation.ARTIFACT_ENTRIES_LIST: self._artifact.list_entries,
            CommonOperation.ARTIFACT_FILES_EXTRACT: self._artifact.extract,
            "flutter.assets.list": self._inspector.list_assets,
            "flutter.assets.search": self._inspector.search_assets,
            "flutter.plugins.list": self._inspector.plugins,
            "flutter.channels.list": self._inspector.channels,
        }
        if operation in argument_routes:
            return await asyncio.to_thread(argument_routes[operation], arguments)
        if operation == CommonOperation.TARGET_INFO:
            return await asyncio.to_thread(self._target_info)
        if operation == "flutter.aot.status":
            return self._status()
        if operation == "flutter.aot.analyze":
            return await asyncio.to_thread(self._analyze, arguments)
        if operation == "flutter.libraries.list":
            analysis = self._require_analysis()
            return {"libraries": analysis.get("libraries", [])}
        if operation == "flutter.objects.search":
            return await asyncio.to_thread(self._search_objects, arguments)
        if operation == CommonOperation.FUNCTIONS_LIST:
            return self._list_functions(arguments)
        if operation == CommonOperation.FUNCTIONS_GET:
            return await asyncio.to_thread(self._get_function, arguments)
        if operation == CommonOperation.SEARCH_FUNCTIONS:
            return self._search_functions(arguments)
        if operation == CommonOperation.SEARCH_STRINGS:
            return await asyncio.to_thread(self._search_text, arguments)
        if operation == CommonOperation.ANALYSIS_DISASSEMBLE:
            return await asyncio.to_thread(self._get_function, arguments)
        raise ReversingMcpError(
            "unsupported_operation", f"Unsupported Flutter operation: {operation}"
        )

    def _target_info(self) -> dict[str, Any]:
        path = Path(self.target_path)
        return {
            "path": str(path),
            "format": path.suffix.lower().lstrip("."),
            "size": path.stat().st_size,
            "sha256": file_sha256(str(path)),
            "flutter": self._inspector.inspect(),
        }

    def _status(self) -> dict[str, Any]:
        if self._analysis is None:
            return {"analyzed": False, "cache_root": str(self._cache.root)}
        return {
            "analyzed": True,
            "cache_root": str(self._cache.root),
            "cache_key": self._analysis.get("cache_key"),
            "analyzer": self._analysis.get("analyzer"),
            "abi": self._analysis.get("abi"),
            "output_directory": self._analysis.get("output_directory"),
        }

    def _select_abi(self, arguments: Mapping[str, Any]) -> str:
        variants = self._inspector.variants()["variants"]
        requested = str(arguments.get("abi") or self._options.get("abi") or "")
        if requested:
            if any(row["abi"] == requested and row["aot"] for row in variants):
                return requested
            raise ReversingMcpError(
                "flutter_abi_not_found",
                f"No Dart AOT snapshot is present for ABI {requested}",
                details={
                    "available_abis": [row["abi"] for row in variants if row["aot"]]
                },
            )
        available = [row["abi"] for row in variants if row["aot"]]
        if "arm64-v8a" in available:
            return "arm64-v8a"
        if available:
            return available[0]
        raise ReversingMcpError(
            "flutter_aot_not_found", "No libapp.so Dart AOT snapshot is present"
        )

    def _analyze(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        options = {**self._options, **dict(arguments)}
        abi = self._select_abi(arguments)
        analyzer = self._analyzer_factory(options)
        if analyzer.supported_abis and abi not in analyzer.supported_abis:
            raise ReversingMcpError(
                "unsupported_flutter_abi",
                f"{analyzer.analyzer_id} does not support Flutter ABI {abi}",
                details={"supported_abis": sorted(analyzer.supported_abis)},
            )
        extraction = self._inspector.extract_native_pair(
            abi, str(self._artifact.temporary_directory / "flutter-aot")
        )
        libapp = extraction["libapp"]["path"]
        libflutter_row = extraction.get("libflutter")
        libflutter = libflutter_row["path"] if libflutter_row else None
        input_digests = {
            "libapp_sha256": extraction["libapp"]["sha256"],
            "libflutter_sha256": libflutter_row["sha256"] if libflutter_row else None,
        }
        key = self._cache.key(
            libapp_sha256=str(input_digests["libapp_sha256"]),
            libflutter_sha256=input_digests["libflutter_sha256"],
            abi=abi,
            analyzer=analyzer,
        )
        if cached := self._cache.load(key):
            cached["cache_hit"] = True
            cached["cache_key"] = key
            self._analysis = cached
            return cached

        temporary, destination = self._cache.create_directory(key)
        output = temporary / "output"
        timeout = max(1.0, min(float(options.get("timeout", 1800)), 7200.0))
        try:
            execution = analyzer.analyze(
                libapp_path=libapp,
                libflutter_path=libflutter,
                abi=abi,
                output_directory=str(output),
                timeout=timeout,
            )
            analysis = normalize_analysis(
                output,
                analyzer=analyzer,
                abi=abi,
                input_digests=input_digests,
                execution=execution,
            )
            analysis["cache_key"] = key
            analysis["cache_hit"] = False
            analysis["output_directory"] = str(destination / "output")
            (temporary / "analysis.json").write_text(
                json.dumps(analysis, indent=2, sort_keys=True), encoding="utf-8"
            )
            self._cache.commit(temporary, destination)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        self._analysis = analysis
        return analysis

    def _list_functions(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        functions = list(self._require_analysis().get("functions", []))
        offset = max(0, int(arguments.get("offset", 0)))
        limit = max(1, min(int(arguments.get("limit", 250)), 5000))
        return {
            "functions": functions[offset : offset + limit],
            "total": len(functions),
            "offset": offset,
            "returned": len(functions[offset : offset + limit]),
            "truncated": offset + limit < len(functions),
        }

    def _search_functions(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        query = str(arguments.get("query", ""))
        if not query:
            raise ReversingMcpError("invalid_request", "query cannot be empty")
        case_sensitive = bool(arguments.get("case_sensitive", False))
        needle = query if case_sensitive else query.casefold()
        functions = self._require_analysis().get("functions", [])
        matches = [
            row
            for row in functions
            if needle
            in (str(row["name"]) if case_sensitive else str(row["name"]).casefold())
        ]
        limit = max(1, min(int(arguments.get("limit", 250)), 5000))
        return {
            "query": query,
            "functions": matches[:limit],
            "matched": len(matches),
            "truncated": len(matches) > limit,
        }

    def _selected_function(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        functions = self._require_analysis().get("functions", [])
        name = arguments.get("name") or arguments.get("function")
        address = arguments.get("address")
        index = arguments.get("index")
        if index is not None:
            try:
                return functions[int(index)]
            except (IndexError, ValueError) as error:
                raise ReversingMcpError(
                    "function_not_found", f"Function index was not found: {index}"
                ) from error
        for row in functions:
            if name is not None and row.get("name") == str(name):
                return row
            if address is not None and row.get("address") is not None:
                try:
                    requested_address = (
                        int(address, 0) if isinstance(address, str) else int(address)
                    )
                    row_address = int(str(row["address"]), 0)
                except (TypeError, ValueError):
                    pass
                else:
                    if requested_address == row_address:
                        return row
        raise ReversingMcpError(
            "function_not_found", "Provide a valid function name, address, or index"
        )

    def _get_function(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        row = dict(self._selected_function(arguments))
        analysis = self._require_analysis()
        path = Path(str(analysis["output_directory"])) / safe_relative_path(
            str(row["source_file"])
        )
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as error:
            raise ReversingMcpError(
                "analysis_cache_missing", f"Cached analyzer output is missing: {path}"
            ) from error
        line_index = max(0, int(row["line"]) - 1)
        context_lines = max(5, min(int(arguments.get("context_lines", 80)), 1000))
        start = max(0, line_index - 2)
        end = min(len(lines), line_index + context_lines)
        row.update(
            {
                "assembly": "\n".join(lines[start:end]),
                "assembly_start_line": start + 1,
                "assembly_end_line": end,
                "truncated": end < len(lines),
            }
        )
        return row

    def _search_text(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        analysis = self._require_analysis()
        return search_analysis_text(
            analysis,
            query=str(arguments.get("query", "")),
            limit=max(1, min(int(arguments.get("limit", 100)), 1000)),
            context_chars=max(0, min(int(arguments.get("context_chars", 160)), 2000)),
            case_sensitive=bool(arguments.get("case_sensitive", False)),
        )

    def _search_objects(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        analysis = self._require_analysis()
        paths = {
            str(row["path"])
            for row in analysis.get("files", [])
            if Path(str(row["path"])).name.lower() in {"objs.txt", "pp.txt"}
        }
        return search_analysis_text(
            analysis,
            query=str(arguments.get("query", "")),
            paths=paths,
            limit=max(1, min(int(arguments.get("limit", 100)), 1000)),
            context_chars=max(0, min(int(arguments.get("context_chars", 160)), 2000)),
            case_sensitive=bool(arguments.get("case_sensitive", False)),
        )

    async def save(self) -> Any:
        raise ReversingMcpError(
            "unsupported_capability", "Flutter package sessions are read-only"
        )

    async def close(self, *, save: bool = True) -> Any:
        del save
        if not self._closed:
            await asyncio.to_thread(self._artifact.close)
            self._closed = True
        return {"closed": True}


class FlutterBackend(AnalysisBackend):
    def __init__(
        self,
        *,
        analyzer_factory: Callable[
            [Mapping[str, Any]], AotAnalyzer
        ] = configured_analyzer,
        cache: FlutterAnalysisCache | None = None,
    ) -> None:
        super().__init__(
            provider_id="flutter",
            display_name="Flutter / Dart AOT",
            capabilities=FLUTTER_CAPABILITIES,
            operations=FLUTTER_OPERATIONS,
        )
        self._analyzer_factory = analyzer_factory
        self._cache = cache or FlutterAnalysisCache()

    async def open(self, request: SessionRequest) -> AnalysisSession:
        if request.lifecycle != LifecycleAction.OPEN:
            raise ReversingMcpError(
                "unsupported_lifecycle", "Flutter sessions only support open"
            )
        artifact = AndroidArtifact(request.target_path)
        try:
            detected = FlutterArtifactInspector(artifact).inspect()["detected"]
        except Exception:
            artifact.close()
            raise
        if not detected:
            artifact.close()
            raise ReversingMcpError(
                "framework_not_detected",
                f"Flutter packaging markers were not found in {request.target_path}",
            )
        return FlutterSession(
            artifact=artifact,
            options=request.options,
            analyzer_factory=self._analyzer_factory,
            cache=self._cache,
        )
