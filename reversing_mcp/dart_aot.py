"""Pluggable Dart AOT analysis and persistent normalized result caching."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import ReversingMcpError

_TEXT_OUTPUT_SUFFIXES = {".s", ".asm", ".dart", ".js", ".json", ".txt"}
_ADDRESS_LABEL = re.compile(
    r"^\s*(?:0x)?([0-9a-fA-F]{6,16})\s+(?:<([^>]+)>|([^\s].*?))\s*:?\s*$"
)
_SYMBOL_LABEL = re.compile(r"^([A-Za-z_.$][\w.$<>:@/+-]{2,300}):\s*$")
_FUNCTION_COMMENT = re.compile(
    r"^\s*(?://|#)\s*(?:Function|Code for)\s+(.+?)(?:\s+at\s+(0x[0-9a-fA-F]+))?\s*$",
    re.IGNORECASE,
)
_LIBRARY = re.compile(r"(?:package:[\w./+-]+\.dart|dart:[\w./+-]+)")
_DART_CLASS = re.compile(r"^\s*class\s+([A-Za-z_$][\w$<>.,?]*)")
_DART_METHOD = re.compile(
    r"^\s{2,}(?:(?:[\w$<>,?.\[\]]+)\s+)?"
    r"([A-Za-z_$~][\w$.:<>=+*/?!\[\]-]*)\s*\([^;]*\)\s*"
    r"(?:async\*?|sync\*?)?\s*\{\s*$"
)
_DART_ADDRESS = re.compile(r"^\s*//\s*(0x[0-9a-fA-F]+):")
_DART_CONTROL_WORDS = {"catch", "for", "if", "switch", "while"}


def _default_cache_root() -> Path:
    configured = os.environ.get("REVERSING_MCP_FLUTTER_CACHE", "")
    if configured:
        return Path(configured).expanduser().resolve()
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return (base / "reversing-mcp" / "flutter").resolve()


def _command_tokens(value: Any) -> tuple[str, ...]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        tokens = tuple(str(item) for item in value if str(item))
    else:
        text = str(value or "").strip()
        if not text:
            return ()
        if text.startswith("["):
            try:
                decoded = json.loads(text)
            except json.JSONDecodeError:
                decoded = None
            if isinstance(decoded, list):
                tokens = tuple(str(item) for item in decoded if str(item))
            else:
                tokens = tuple(shlex.split(text, posix=os.name != "nt"))
        else:
            tokens = tuple(shlex.split(text, posix=os.name != "nt"))
    return tokens


class AotAnalyzer(ABC):
    """Adapter boundary for Dart snapshot analyzers."""

    analyzer_id: str
    supported_abis: frozenset[str]

    @property
    @abstractmethod
    def identity(self) -> str:
        """Stable tool identity included in cache keys."""

    @abstractmethod
    def analyze(
        self,
        *,
        libapp_path: str,
        libflutter_path: str | None,
        abi: str,
        output_directory: str,
        timeout: float,
    ) -> dict[str, Any]:
        """Populate ``output_directory`` and return execution metadata."""


class BlutterAnalyzer(AotAnalyzer):
    """Adapter for worawit/blutter without implicit downloads or builds."""

    analyzer_id = "blutter"
    supported_abis = frozenset({"arm64-v8a"})

    def __init__(
        self, command: Sequence[str], *, allow_toolchain_build: bool = False
    ) -> None:
        self.command = tuple(command)
        self.allow_toolchain_build = allow_toolchain_build

    @property
    def identity(self) -> str:
        digest = hashlib.sha256("\0".join(self.command).encode())
        digest.update(str(self.allow_toolchain_build).encode())
        for token in self.command:
            path = Path(token).expanduser()
            if not path.is_file() and (resolved := shutil.which(token)):
                path = Path(resolved)
            if not path.is_file():
                continue
            digest.update(str(path.resolve()).encode())
            digest.update(file_sha256(str(path)).encode())
        return f"blutter:{digest.hexdigest()}"

    def analyze(
        self,
        *,
        libapp_path: str,
        libflutter_path: str | None,
        abi: str,
        output_directory: str,
        timeout: float,
    ) -> dict[str, Any]:
        if abi not in self.supported_abis:
            raise ReversingMcpError(
                "unsupported_flutter_abi",
                f"Blutter supports arm64-v8a snapshots, not {abi}",
                details={"supported_abis": sorted(self.supported_abis)},
            )
        if not self.command:
            raise ReversingMcpError(
                "dependency_missing",
                "Blutter is not configured. Set BLUTTER_COMMAND or pass "
                "options.blutter_command.",
            )
        invokes_upstream_script = any(
            Path(token).name.casefold() == "blutter.py" for token in self.command
        )
        if invokes_upstream_script and not self.allow_toolchain_build:
            raise ReversingMcpError(
                "implicit_toolchain_build_disabled",
                "Upstream blutter.py may clone and build a matching Dart runtime. "
                "Use a reviewed no-build wrapper or explicitly set "
                "allow_toolchain_build=true for this request.",
            )
        output = Path(output_directory).resolve()
        output.mkdir(parents=True, exist_ok=True)
        input_dir = output.parent / "analyzer-input"
        input_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(libapp_path, input_dir / "libapp.so")
        if libflutter_path:
            shutil.copy2(libflutter_path, input_dir / "libflutter.so")
        command = [*self.command, str(input_dir), str(output)]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except FileNotFoundError as error:
            raise ReversingMcpError(
                "dependency_missing", f"Blutter command was not found: {command[0]}"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise ReversingMcpError(
                "operation_timeout", f"Blutter exceeded the {timeout:g}s timeout"
            ) from error
        if completed.returncode != 0:
            raise ReversingMcpError(
                "analyzer_failed",
                f"Blutter exited with status {completed.returncode}",
                details={
                    "stdout": completed.stdout[-20_000:],
                    "stderr": completed.stderr[-20_000:],
                },
            )
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-20_000:],
            "stderr": completed.stderr[-20_000:],
        }


def configured_analyzer(options: Mapping[str, Any]) -> AotAnalyzer:
    analyzer_id = str(options.get("aot_analyzer", "blutter")).lower()
    if analyzer_id != "blutter":
        raise ReversingMcpError(
            "analyzer_not_found", f"Unknown Dart AOT analyzer: {analyzer_id}"
        )
    command = _command_tokens(
        options.get("blutter_command") or os.environ.get("BLUTTER_COMMAND", "")
    )
    allow_build_value = options.get("allow_toolchain_build")
    if allow_build_value is None:
        allow_build_value = os.environ.get(
            "REVERSING_MCP_ALLOW_AOT_TOOLCHAIN_BUILD", ""
        )
    allow_toolchain_build = (
        allow_build_value
        if isinstance(allow_build_value, bool)
        else str(allow_build_value).casefold() in {"1", "true", "yes", "on"}
    )
    return BlutterAnalyzer(command, allow_toolchain_build=bool(allow_toolchain_build))


class FlutterAnalysisCache:
    """Content-addressed cache that survives MCP session closure."""

    schema_version = 1

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root).expanduser().resolve() if root else _default_cache_root()

    def key(
        self,
        *,
        libapp_sha256: str,
        libflutter_sha256: str | None,
        abi: str,
        analyzer: AotAnalyzer,
    ) -> str:
        payload = {
            "schema": self.schema_version,
            "libapp": libapp_sha256,
            "libflutter": libflutter_sha256,
            "abi": abi,
            "analyzer": analyzer.identity,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def load(self, key: str) -> dict[str, Any] | None:
        index = self.root / key / "analysis.json"
        if not index.is_file():
            return None
        try:
            result = json.loads(index.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
        if not Path(str(result.get("output_directory", ""))).is_dir():
            return None
        return result

    def create_directory(self, key: str) -> tuple[Path, Path]:
        self.root.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{key[:12]}-", dir=self.root))
        return temporary, self.root / key

    def commit(self, temporary: Path, destination: Path) -> Path:
        if destination.exists():
            shutil.rmtree(temporary, ignore_errors=True)
            return destination
        try:
            temporary.replace(destination)
        except OSError:
            if destination.exists():
                shutil.rmtree(temporary, ignore_errors=True)
            else:
                raise
        return destination


def normalize_analysis(
    output_directory: Path,
    *,
    analyzer: AotAnalyzer,
    abi: str,
    input_digests: Mapping[str, str | None],
    execution: Mapping[str, Any],
) -> dict[str, Any]:
    files = []
    functions: list[dict[str, Any]] = []
    libraries: set[str] = set()
    for path in sorted(output_directory.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(output_directory).as_posix()
        size = path.stat().st_size
        files.append(
            {
                "path": relative,
                "size": size,
                "sha256": file_sha256(str(path)),
            }
        )
        if path.suffix.lower() not in _TEXT_OUTPUT_SUFFIXES or size > 64 * 1024 * 1024:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        libraries.update(_LIBRARY.findall(text))
        if path.suffix.lower() == ".dart":
            functions.extend(_dart_functions(text, relative))
            continue
        if path.suffix.lower() not in {".s", ".asm"}:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            address = None
            name = None
            if match := _FUNCTION_COMMENT.match(line):
                name, address = match.group(1).strip(), match.group(2)
            elif match := _ADDRESS_LABEL.match(line):
                address = f"0x{match.group(1).lower()}"
                name = (match.group(2) or match.group(3) or "").strip()
            elif match := _SYMBOL_LABEL.match(line):
                name = match.group(1)
            if not name:
                continue
            functions.append(
                {
                    "name": name,
                    "address": address,
                    "source_file": relative,
                    "line": line_number,
                }
            )
    return {
        "schema_version": FlutterAnalysisCache.schema_version,
        "analyzer": analyzer.analyzer_id,
        "analyzer_identity": analyzer.identity,
        "abi": abi,
        "input": dict(input_digests),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "output_directory": str(output_directory),
        "files": files,
        "functions": functions,
        "libraries": sorted(libraries),
        "execution": dict(execution),
        "limitations": [
            "Analyzer output reconstructs AOT machine code; it is not original "
            "Dart source.",
            "Inlining, tree shaking, specialization, and obfuscation can remove "
            "or rename entities.",
        ],
    }


def _dart_functions(text: str, relative: str) -> list[dict[str, Any]]:
    """Index Blutter's annotated Dart-like assembly files."""
    functions = []
    current_class = ""
    pending: dict[str, Any] | None = None
    pending_age = 0
    for line_number, line in enumerate(text.splitlines(), start=1):
        if match := _DART_CLASS.match(line):
            current_class = match.group(1)
        if match := _DART_METHOD.match(line):
            method = match.group(1)
            if method not in _DART_CONTROL_WORDS:
                if pending is not None:
                    functions.append(pending)
                pending = {
                    "name": f"{current_class}::{method}" if current_class else method,
                    "address": None,
                    "source_file": relative,
                    "line": line_number,
                }
                pending_age = 0
                continue
        if pending is None:
            continue
        pending_age += 1
        if match := _DART_ADDRESS.match(line):
            pending["address"] = match.group(1).lower()
            functions.append(pending)
            pending = None
        elif pending_age > 25:
            functions.append(pending)
            pending = None
    if pending is not None:
        functions.append(pending)
    return functions


def search_analysis_text(
    analysis: Mapping[str, Any],
    *,
    query: str,
    paths: set[str] | None = None,
    limit: int = 100,
    context_chars: int = 160,
    case_sensitive: bool = False,
) -> dict[str, Any]:
    if not query:
        raise ReversingMcpError("invalid_request", "query cannot be empty")
    root = Path(str(analysis["output_directory"]))
    needle = query if case_sensitive else query.casefold()
    results = []
    searched = 0
    for row in analysis.get("files", []):
        relative = str(row["path"])
        if paths is not None and relative not in paths:
            continue
        path = root / safe_relative_path(relative)
        if (
            path.suffix.lower() not in _TEXT_OUTPUT_SUFFIXES
            or int(row.get("size", 0)) > 64 * 1024 * 1024
            or not path.is_file()
        ):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        haystack = text if case_sensitive else text.casefold()
        searched += 1
        start = 0
        while (index := haystack.find(needle, start)) >= 0:
            results.append(
                {
                    "path": relative,
                    "line": text.count("\n", 0, index) + 1,
                    "start": index,
                    "context": text[
                        max(0, index - context_chars) : index
                        + len(query)
                        + context_chars
                    ],
                }
            )
            if len(results) >= limit:
                return {
                    "query": query,
                    "results": results,
                    "searched_files": searched,
                    "truncated": True,
                }
            start = index + max(1, len(needle))
    return {
        "query": query,
        "results": results,
        "searched_files": searched,
        "truncated": False,
    }


def file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def safe_relative_path(value: str) -> Path:
    """Convert normalized analyzer paths without accepting traversal."""
    parts = value.replace("\\", "/").split("/")
    if (
        any(part in {"", ".", ".."} for part in parts)
        or ":" in parts[0]
        or value.startswith(("/", "\\"))
    ):
        raise ReversingMcpError("unsafe_analysis_path", f"Unsafe result path: {value}")
    return Path(*parts)
