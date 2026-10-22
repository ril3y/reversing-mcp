"""Safe APK/XAPK inventory and bundled JavaScript analysis helpers."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Mapping

from .errors import ReversingMcpError

_ARCHIVE_SUFFIXES = {".apk", ".xapk", ".zip", ".apks", ".aab"}
_JAVASCRIPT_SUFFIXES = {".js", ".mjs", ".cjs"}
_MAX_MEMBER_BYTES = 64 * 1024 * 1024


def _safe_member_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ReversingMcpError(
            "unsafe_archive_path", f"Unsafe archive member path: {name}"
        )
    path = PurePosixPath(normalized)
    if not normalized or any(part in {"", ".", ".."} for part in path.parts):
        raise ReversingMcpError(
            "unsafe_archive_path", f"Unsafe archive member path: {name}"
        )
    return str(path)


def _decode_text(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace"), "utf-8-sig"
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), "utf-8-replace"


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    path: str
    size: int
    compressed_size: int
    container: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "compressed_size": self.compressed_size,
            "container": self.container,
        }


@dataclass(frozen=True, slots=True)
class JavascriptModule:
    module_id: str
    start: int
    end: int
    line: int


@dataclass(frozen=True, slots=True)
class JavascriptFunction:
    name: str
    start: int
    end: int
    line: int


class AndroidArtifact:
    """Read one APK/XAPK and own all temporary extraction beneath one root."""

    def __init__(self, path: str) -> None:
        self.path = Path(path).expanduser().resolve()
        if not self.path.is_file():
            raise ReversingMcpError(
                "target_not_found", f"Android artifact does not exist: {self.path}"
            )
        if self.path.suffix.lower() not in _ARCHIVE_SUFFIXES:
            raise ReversingMcpError(
                "unsupported_format",
                f"Expected an APK, XAPK, APKS, AAB, or ZIP: {self.path}",
            )
        if not zipfile.is_zipfile(self.path):
            raise ReversingMcpError(
                "unsupported_format",
                f"Artifact is not a valid ZIP container: {self.path}",
            )
        self._temporary = Path(tempfile.mkdtemp(prefix="reversing-mcp-android-"))
        self._nested_cache: dict[str, bytes] = {}
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        resolved = self._temporary.resolve()
        expected_parent = Path(tempfile.gettempdir()).resolve()
        if resolved.parent == expected_parent and resolved.name.startswith(
            "reversing-mcp-android-"
        ):
            shutil.rmtree(resolved, ignore_errors=True)
        self._nested_cache.clear()
        self._closed = True

    def _ensure_open(self) -> None:
        if self._closed:
            raise ReversingMcpError("session_closed", "Android artifact is closed")

    @property
    def temporary_directory(self) -> Path:
        return self._temporary

    def root_entries(self) -> list[zipfile.ZipInfo]:
        self._ensure_open()
        with zipfile.ZipFile(self.path) as archive:
            return [item for item in archive.infolist() if not item.is_dir()]

    def _nested_bytes(self, member: str) -> bytes:
        member = _safe_member_name(member)
        cached = self._nested_cache.get(member)
        if cached is not None:
            return cached
        with zipfile.ZipFile(self.path) as archive:
            try:
                info = archive.getinfo(member)
            except KeyError as error:
                raise ReversingMcpError(
                    "member_not_found", f"Archive member does not exist: {member}"
                ) from error
            if info.file_size > 512 * 1024 * 1024:
                raise ReversingMcpError(
                    "resource_constraint", f"Nested archive is too large: {member}"
                )
            data = archive.read(info)
        self._nested_cache[member] = data
        return data

    def iter_entries(self, *, include_nested: bool = True) -> Iterator[ArchiveEntry]:
        self._ensure_open()
        with zipfile.ZipFile(self.path) as root:
            for info in root.infolist():
                if info.is_dir():
                    continue
                name = _safe_member_name(info.filename)
                yield ArchiveEntry(
                    name, info.file_size, info.compress_size, self.path.name
                )
                if not include_nested or Path(name).suffix.lower() != ".apk":
                    continue
                try:
                    data = self._nested_bytes(name)
                    with zipfile.ZipFile(io.BytesIO(data)) as nested:
                        for child in nested.infolist():
                            if child.is_dir():
                                continue
                            child_name = _safe_member_name(child.filename)
                            yield ArchiveEntry(
                                f"{name}!/{child_name}",
                                child.file_size,
                                child.compress_size,
                                name,
                            )
                except (zipfile.BadZipFile, RuntimeError):
                    continue

    def read_member(
        self, virtual_path: str, *, max_bytes: int = _MAX_MEMBER_BYTES
    ) -> bytes:
        self._ensure_open()
        parts = virtual_path.replace("\\", "/").split("!/")
        if not 1 <= len(parts) <= 2:
            raise ReversingMcpError(
                "invalid_request", "Member paths support at most one nested archive"
            )
        first = _safe_member_name(parts[0])
        with zipfile.ZipFile(self.path) as root:
            try:
                info = root.getinfo(first)
            except KeyError as error:
                raise ReversingMcpError(
                    "member_not_found", f"Archive member does not exist: {first}"
                ) from error
            if len(parts) == 1:
                if info.file_size > max_bytes:
                    raise ReversingMcpError(
                        "resource_constraint",
                        f"Archive member exceeds {max_bytes} bytes",
                    )
                return root.read(info)
        nested_data = self._nested_bytes(first)
        second = _safe_member_name(parts[1])
        with zipfile.ZipFile(io.BytesIO(nested_data)) as nested:
            try:
                info = nested.getinfo(second)
            except KeyError as error:
                raise ReversingMcpError(
                    "member_not_found", f"Nested member does not exist: {virtual_path}"
                ) from error
            if info.file_size > max_bytes:
                raise ReversingMcpError(
                    "resource_constraint", f"Archive member exceeds {max_bytes} bytes"
                )
            return nested.read(info)

    def primary_apk(self) -> Path:
        """Return the APK JADX should open, extracting one XAPK member if needed."""
        self._ensure_open()
        if self.path.suffix.lower() == ".apk":
            return self.path
        candidates = [
            info
            for info in self.root_entries()
            if Path(info.filename).suffix.lower() == ".apk"
        ]
        if not candidates:
            raise ReversingMcpError(
                "apk_not_found", f"No APK is present inside {self.path.name}"
            )

        def score(info: zipfile.ZipInfo) -> tuple[int, int]:
            name = Path(info.filename).name.lower()
            priority = 0
            if name == "base.apk":
                priority += 100
            if not name.startswith(("config.", "split_", "split-")):
                priority += 20
            if "master" in name or "universal" in name:
                priority += 10
            return priority, info.file_size

        selected = max(candidates, key=score)
        target = self._temporary / "jadx-input.apk"
        target.write_bytes(self._nested_bytes(_safe_member_name(selected.filename)))
        return target

    def list_entries(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        prefix = str(arguments.get("prefix", ""))
        suffix = str(arguments.get("suffix", ""))
        limit = max(1, min(int(arguments.get("limit", 500)), 5000))
        matched = []
        total = 0
        for entry in self.iter_entries(
            include_nested=bool(arguments.get("nested", True))
        ):
            if prefix and not entry.path.startswith(prefix):
                continue
            if suffix and not entry.path.lower().endswith(suffix.lower()):
                continue
            total += 1
            if len(matched) < limit:
                matched.append(entry.to_dict())
        return {
            "artifact": str(self.path),
            "entries": matched,
            "matched": total,
            "returned": len(matched),
            "truncated": total > len(matched),
        }

    def extract(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        paths = arguments.get("paths")
        if paths is None:
            paths = [arguments.get("path", "")]
        if not isinstance(paths, list) or not paths or not all(paths):
            raise ReversingMcpError(
                "invalid_request", "Provide 'path' or a non-empty 'paths' list"
            )
        persistent = bool(arguments.get("output_directory"))
        output = (
            Path(str(arguments["output_directory"])).expanduser().resolve()
            if persistent
            else self._temporary / "extracted"
        )
        output.mkdir(parents=True, exist_ok=True)
        overwrite = bool(arguments.get("overwrite", False))
        extracted = []
        used_names: set[str] = set()
        for virtual_path in paths:
            virtual_path = str(virtual_path)
            data = self.read_member(virtual_path)
            relative = _safe_member_name(virtual_path.replace("!/", "/"))
            candidate = output.joinpath(*PurePosixPath(relative).parts)
            if candidate.name in used_names:
                digest = hashlib.sha256(virtual_path.encode()).hexdigest()[:8]
                candidate = candidate.with_name(
                    f"{candidate.stem}-{digest}{candidate.suffix}"
                )
            used_names.add(candidate.name)
            candidate.parent.mkdir(parents=True, exist_ok=True)
            if candidate.exists() and not overwrite:
                raise ReversingMcpError(
                    "output_exists",
                    f"Refusing to overwrite extracted file: {candidate}",
                )
            candidate.write_bytes(data)
            extracted.append(
                {
                    "member": virtual_path,
                    "path": str(candidate),
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        return {
            "output_directory": str(output),
            "temporary": not persistent,
            "cleanup": "Files are removed when the session closes"
            if not persistent
            else None,
            "files": extracted,
        }

    def javascript_search(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        query = str(arguments.get("query", arguments.get("pattern", "")))
        if not query:
            raise ReversingMcpError("invalid_request", "query cannot be empty")
        is_regex = bool(arguments.get("regex", False))
        case_sensitive = bool(arguments.get("case_sensitive", False))
        context = max(0, min(int(arguments.get("context_chars", 160)), 2000))
        limit = max(1, min(int(arguments.get("limit", 100)), 1000))
        requested_paths = arguments.get("paths")
        if requested_paths is not None and not isinstance(requested_paths, list):
            raise ReversingMcpError("invalid_request", "paths must be a list")
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            expression = re.compile(query if is_regex else re.escape(query), flags)
        except re.error as error:
            raise ReversingMcpError("invalid_regex", str(error)) from error
        results = []
        searched = 0
        skipped = []
        for entry in self.iter_entries(include_nested=True):
            if Path(entry.path).suffix.lower() not in _JAVASCRIPT_SUFFIXES:
                continue
            if requested_paths and not any(
                entry.path == path or entry.path.endswith(str(path))
                for path in requested_paths
            ):
                continue
            if entry.size > _MAX_MEMBER_BYTES:
                skipped.append({"path": entry.path, "reason": "size limit"})
                continue
            text, encoding = _decode_text(self.read_member(entry.path))
            searched += 1
            for match in expression.finditer(text):
                before = max(0, match.start() - context)
                after = min(len(text), match.end() + context)
                results.append(
                    {
                        "path": entry.path,
                        "line": text.count("\n", 0, match.start()) + 1,
                        "column": match.start() - text.rfind("\n", 0, match.start()),
                        "start": match.start(),
                        "end": match.end(),
                        "match": match.group(0),
                        "context": text[before:after],
                        "context_start": before,
                        "encoding": encoding,
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
        return {
            "query": query,
            "results": results,
            "searched_files": searched,
            "truncated": False,
            "skipped": skipped,
        }

    def javascript_source(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        path = str(arguments.get("path", ""))
        if not path:
            raise ReversingMcpError("invalid_request", "path cannot be empty")
        text, encoding = _decode_text(self.read_member(path))
        modules = javascript_modules(text)
        module_id = arguments.get("module_id")
        function_name = arguments.get("function")
        line = arguments.get("line")
        offset = arguments.get("offset")
        selected: JavascriptModule | None = None
        if module_id is not None:
            wanted = str(module_id)
            selected = next(
                (item for item in modules if item.module_id == wanted), None
            )
            if selected is None:
                raise ReversingMcpError(
                    "module_not_found",
                    f"Webpack module was not found: {wanted}",
                    details={
                        "available_module_ids": [
                            item.module_id for item in modules[:100]
                        ]
                    },
                )
        elif function_name is not None:
            wanted = str(function_name)
            match = _named_javascript_function(text, wanted)
            if match is None:
                raise ReversingMcpError(
                    "function_not_found", f"JavaScript function was not found: {wanted}"
                )
            selected = JavascriptModule(
                f"function:{match.name}", match.start, match.end, match.line
            )
        elif line is not None or offset is not None:
            location = (
                int(offset) if offset is not None else _line_offset(text, int(line))
            )
            selected = next(
                (item for item in modules if item.start <= location < item.end), None
            )
            match = _javascript_function_at(text, location)
            if match is not None:
                selected = JavascriptModule(
                    f"function:{match.name}", match.start, match.end, match.line
                )
        if selected is None:
            selected = JavascriptModule("document", 0, len(text), 1)
        raw = text[selected.start : selected.end]
        max_chars = max(1000, min(int(arguments.get("max_chars", 500_000)), 2_000_000))
        truncated = len(raw) > max_chars
        raw = raw[:max_chars]
        formatted, formatter = format_javascript(raw)
        return {
            "path": path,
            "module_id": selected.module_id,
            "start": selected.start,
            "end": selected.end,
            "line": selected.line,
            "encoding": encoding,
            "formatter": formatter,
            "source": formatted,
            "truncated": truncated,
            "module_count": len(modules),
        }

    def dcloud_inspect(self) -> dict[str, Any]:
        pattern = re.compile(r"(?:^|!/)assets/apps/([^/]+)/www/(.+)$", re.IGNORECASE)
        apps: dict[str, dict[str, Any]] = {}
        evidence = []
        for entry in self.iter_entries(include_nested=True):
            match = pattern.search(entry.path)
            if not match:
                if "io.dcloud" in entry.path.lower():
                    evidence.append(entry.path)
                continue
            app_id, relative = match.groups()
            app = apps.setdefault(
                app_id,
                {"app_id": app_id, "root": entry.path[: -len(relative)], "files": []},
            )
            app["files"].append(relative)
            evidence.append(entry.path)
        for app in apps.values():
            files = app.pop("files")
            app["file_count"] = len(files)
            app["entrypoints"] = sorted(
                name
                for name in files
                if name.lower()
                in {"app-service.js", "app-view.js", "manifest.json", "pages.json"}
            )
            app["pages"] = []
            app["modules"] = []
            root = app["root"]
            for manifest_name in ("pages.json", "manifest.json"):
                if manifest_name not in files:
                    continue
                try:
                    payload = json.loads(
                        _decode_text(self.read_member(root + manifest_name))[0]
                    )
                except (json.JSONDecodeError, ReversingMcpError):
                    continue
                pages = payload.get("pages", []) if isinstance(payload, dict) else []
                for page in pages:
                    value = page.get("path") if isinstance(page, dict) else page
                    if value and value not in app["pages"]:
                        app["pages"].append(value)
            service_path = root + "app-service.js"
            if "app-service.js" in files:
                service = _decode_text(self.read_member(service_path))[0]
                for page in re.findall(
                    r"(?:__definePage|registerPage)\(\s*['\"]([^'\"]+)", service
                ):
                    if page not in app["pages"]:
                        app["pages"].append(page)
                modules = javascript_modules(service)
                module_rows = [
                    {"id": item.module_id, "line": item.line, "start": item.start}
                    for item in modules[:5000]
                ]
                known_ids = {row["id"] for row in module_rows}
                for hint in re.finditer(
                    r"\bat\s+([^\"'\r\n]+?\.(?:vue|tsx?|jsx?)):\d+", service
                ):
                    module_id = hint.group(1).replace("\\", "/")
                    if module_id in known_ids:
                        continue
                    known_ids.add(module_id)
                    module_rows.append(
                        {
                            "id": module_id,
                            "line": service.count("\n", 0, hint.start()) + 1,
                            "start": hint.start(),
                            "kind": "source-location-hint",
                        }
                    )
                    if len(module_rows) >= 5000:
                        break
                app["modules"] = module_rows
                app["modules_truncated"] = len(modules) > 5000
                app["app_service_path"] = service_path
        return {
            "framework": "uni-app/dcloud" if apps else None,
            "detected": bool(apps or evidence),
            "artifact": str(self.path),
            "apps": list(apps.values()),
            "evidence": evidence[:100],
            "evidence_truncated": len(evidence) > 100,
        }

    def frameworks_detect(self) -> dict[str, Any]:
        """Run every registered package-framework detector."""
        from .android_frameworks import detect_android_frameworks

        return detect_android_frameworks(self)


def _line_offset(text: str, line: int) -> int:
    if line < 1:
        raise ReversingMcpError("invalid_request", "line must be at least 1")
    offset = 0
    for _ in range(line - 1):
        offset = text.find("\n", offset)
        if offset < 0:
            raise ReversingMcpError("invalid_request", "line is outside the source")
        offset += 1
    return offset


_MODULE_PATTERNS = (
    re.compile(r"/\*\s*(?:!{3}|-{3})?\s*(\d+)\s*\*/\s*(?:\(?function|\()"),
    re.compile(
        r"(?:^|[,;{])\s*['\"]([^'\"]*[/\\][^'\"]*)['\"]\s*:"
        r"\s*(?:function|\([^)]*\)\s*=>)",
        re.MULTILINE,
    ),
    re.compile(
        r"(?:^|[,;{])\s*(\d+)\s*:\s*(?:function|\([^)]*\)\s*=>)",
        re.MULTILINE,
    ),
    re.compile(r"__webpack_modules__\s*\[\s*(['\"]?[^\]'\"]+['\"]?)\s*\]\s*="),
)


def javascript_modules(source: str) -> list[JavascriptModule]:
    starts: dict[int, str] = {}
    for expression in _MODULE_PATTERNS:
        for match in expression.finditer(source):
            module_id = match.group(1).strip().strip("'\"")
            if module_id and len(module_id) <= 300:
                starts.setdefault(match.start(), module_id)
    positions = sorted(starts)
    return [
        JavascriptModule(
            starts[start],
            start,
            positions[index + 1] if index + 1 < len(positions) else len(source),
            source.count("\n", 0, start) + 1,
        )
        for index, start in enumerate(positions)
    ]


_FUNCTION_PATTERN = re.compile(
    r"(?:(?:async\s+)?function\s+([A-Za-z_$][\w$]*)?\s*\([^)]*\)"
    r"|(?<![.\w$])(?!(?:if|for|while|switch|catch|with)\s*\()"
    r"(?:(?:static|async)\s+)*([A-Za-z_$][\w$]*)\s*\([^)]*\)"
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
    r"\([^)]*\)\s*=>)\s*\{"
)


def javascript_functions(source: str) -> list[JavascriptFunction]:
    """Inventory functions; source-view lookups use bounded helpers below."""
    functions: list[JavascriptFunction] = []
    for match in _FUNCTION_PATTERN.finditer(source):
        function = _function_from_match(source, match)
        if function is not None:
            functions.append(function)
    return functions


def _function_from_match(
    source: str, match: re.Match[str]
) -> JavascriptFunction | None:
    closing = _matching_brace(source, match.end() - 1)
    if closing is None:
        return None
    name = next((group for group in match.groups() if group), "anonymous")
    return JavascriptFunction(
        name=name,
        start=match.start(),
        end=closing + 1,
        line=source.count("\n", 0, match.start()) + 1,
    )


def _named_javascript_function(source: str, name: str) -> JavascriptFunction | None:
    for match in _FUNCTION_PATTERN.finditer(source):
        candidate = next((group for group in match.groups() if group), "anonymous")
        if candidate == name:
            return _function_from_match(source, match)
    return None


def _javascript_function_at(source: str, location: int) -> JavascriptFunction | None:
    if location < 0 or location >= len(source):
        raise ReversingMcpError(
            "invalid_request", "Source location is outside the file"
        )
    # The innermost function normally has the nearest header. Bound the reverse
    # search so a large generated bundle never requires closing every function.
    candidates = list(_FUNCTION_PATTERN.finditer(source, 0, location + 1))[-256:]
    for match in reversed(candidates):
        function = _function_from_match(source, match)
        if function is not None and function.start <= location < function.end:
            return function
    return None


def _matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    quote = ""
    escaped = False
    index = opening
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            index += 1
            continue
        if character in "'\"`":
            quote = character
        elif character == "/" and following == "/":
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline
            continue
        elif character == "/" and following == "*":
            ending = source.find("*/", index + 2)
            index = len(source) if ending < 0 else ending + 2
            continue
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def format_javascript(source: str) -> tuple[str, str]:
    """Use an installed Prettier, with a conservative built-in fallback."""
    configured = os.environ.get("PRETTIER_COMMAND", "").strip()
    executable = configured or shutil.which("prettier") or shutil.which("prettier.cmd")
    if executable:
        command = (
            shlex.split(executable, posix=os.name != "nt")
            if configured
            else [executable]
        )
        try:
            completed = subprocess.run(  # noqa: S603 - explicit configured formatter
                [*command, "--parser", "babel"],
                input=source,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if completed.returncode == 0 and completed.stdout:
                return completed.stdout, "prettier"
        except (OSError, subprocess.TimeoutExpired):
            pass
    return _basic_javascript_format(source), "builtin"


def _basic_javascript_format(source: str) -> str:
    output: list[str] = []
    indent = 0
    parens = 0
    index = 0
    line_start = True

    def write(value: str) -> None:
        nonlocal line_start
        if line_start and value and value != "\n":
            output.append("  " * indent)
            line_start = False
        output.append(value)

    def newline() -> None:
        nonlocal line_start
        while output and output[-1] == " ":
            output.pop()
        if not output or output[-1] != "\n":
            output.append("\n")
        line_start = True

    while index < len(source):
        character = source[index]
        next_character = source[index + 1] if index + 1 < len(source) else ""
        if character in "'\"`":
            quote = character
            start = index
            index += 1
            escaped = False
            while index < len(source):
                current = source[index]
                index += 1
                if escaped:
                    escaped = False
                elif current == "\\":
                    escaped = True
                elif current == quote:
                    break
            write(source[start:index])
            continue
        if character == "/" and next_character == "/":
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            write(source[index:end].strip())
            newline()
            index = end + 1
            continue
        if character == "/" and next_character == "*":
            end = source.find("*/", index + 2)
            end = len(source) - 2 if end < 0 else end
            write(source[index : end + 2])
            newline()
            index = end + 2
            continue
        if character.isspace():
            if not line_start and output and output[-1] not in {" ", "\n"}:
                output.append(" ")
            index += 1
            continue
        if character == "(":
            parens += 1
            write(character)
        elif character == ")":
            parens = max(0, parens - 1)
            write(character)
        elif character == "{":
            write(" {") if output and output[-1] not in {" ", "\n"} else write("{")
            indent += 1
            newline()
        elif character == "}":
            indent = max(0, indent - 1)
            if not line_start:
                newline()
            write("}")
            if next_character not in ");,]":
                newline()
        elif character == ";":
            write(character)
            if parens == 0:
                newline()
            else:
                write(" ")
        elif character == ",":
            write(", ")
        else:
            write(character)
        index += 1
    return "".join(output).strip() + "\n"
