#!/usr/bin/env python3
"""
Standalone IDA spawn server — run this on the remote machine BEFORE IDA is open.

Listens on port 13336 (one below the IDA plugin range), accepts file uploads,
and launches IDA on them.  Once IDA opens, the in-IDA plugin takes over on
13337+ as usual.

Usage (Windows, GUI mode):
    python spawn_server.py
    python spawn_server.py --ida-path "C:\\Program Files\\IDA Pro 8.4\\ida64.exe"

Usage (Windows, headless / no GUI):
    python spawn_server.py --headless
    python spawn_server.py --headless \
        --ida-path "C:\\Program Files\\IDA Pro 8.4\\idat64.exe"

Headless mode uses idat64 (text UI) instead of ida64 and automatically passes
-A (auto-accept) and -S headless_runner.py so the MCP server stays alive without
a visible IDA window.  Requires idat64.exe to be on PATH or supplied via
--ida-path / IDA_PATH.

Environment variables:
    IDA_PATH        Path to ida64.exe / idat64.exe / ida64
    IDA_MCP_BIND    Bind address (default 127.0.0.1)
"""

import argparse
import base64
import http.server
import json
import os
import subprocess
import sys
import time

PORT = 13336
UPLOAD_DIR = os.path.join(os.path.expanduser("~"), ".ida_mcp", "uploads")
_RUNNER = os.path.join(os.path.dirname(__file__), "headless_runner.py")
_REGISTRATION_DIR = os.path.expanduser("~/.ida_mcp")

# Common IDA install locations to probe when --ida-path is not given.
# Each tuple is (gui_binary, headless_binary).
_CANDIDATE_PAIRS = [
    # Windows
    (
        r"C:\Program Files\IDA Pro 9.2\ida64.exe",
        r"C:\Program Files\IDA Pro 9.2\idat64.exe",
    ),
    (
        r"C:\Program Files\IDA Pro 8.4\ida64.exe",
        r"C:\Program Files\IDA Pro 8.4\idat64.exe",
    ),
    (
        r"C:\Program Files\IDA Pro 8.3\ida64.exe",
        r"C:\Program Files\IDA Pro 8.3\idat64.exe",
    ),
    (
        r"C:\Program Files\IDA Pro 8.2\ida64.exe",
        r"C:\Program Files\IDA Pro 8.2\idat64.exe",
    ),
    (
        r"C:\Program Files\IDA Pro 8.1\ida64.exe",
        r"C:\Program Files\IDA Pro 8.1\idat64.exe",
    ),
    (
        r"C:\Program Files\IDA Pro 8.0\ida64.exe",
        r"C:\Program Files\IDA Pro 8.0\idat64.exe",
    ),
    (
        r"C:\Program Files\IDA Pro 7.7\ida64.exe",
        r"C:\Program Files\IDA Pro 7.7\idat64.exe",
    ),
    # macOS
    (
        "/Applications/IDA Pro 9.2/ida64.app/Contents/MacOS/ida64",
        "/Applications/IDA Pro 9.2/idat64.app/Contents/MacOS/idat64",
    ),
    (
        "/Applications/IDA Pro 8.4/ida64.app/Contents/MacOS/ida64",
        "/Applications/IDA Pro 8.4/idat64.app/Contents/MacOS/idat64",
    ),
    # Linux
    ("/opt/idapro/ida64", "/opt/idapro/idat64"),
    (os.path.expanduser("~/ida/ida64"), os.path.expanduser("~/ida/idat64")),
]


def _find_ida(headless: bool = False) -> str | None:
    """Return the first suitable IDA binary that actually exists."""
    from_env = os.environ.get("IDA_PATH")
    if from_env and os.path.isfile(from_env):
        return from_env
    idx = 1 if headless else 0
    for pair in _CANDIDATE_PAIRS:
        if os.path.isfile(pair[idx]):
            return pair[idx]
        # A GUI launcher may fall back to text mode, but a headless request
        # must never unexpectedly open a window.
        if not headless and os.path.isfile(pair[1 - idx]):
            return pair[1 - idx]
    return None


def _default_database_path(source_path: str) -> str:
    stem, _extension = os.path.splitext(os.path.abspath(source_path))
    return f"{stem}.i64"


def _build_ida_command(
    ida_bin: str,
    source_path: str = "",
    database_path: str = "",
    headless: bool = False,
) -> tuple[list[str], str, str]:
    """Build an IDA create/reopen command without launching a process."""
    source = os.path.abspath(source_path) if source_path else ""
    database = os.path.abspath(database_path) if database_path else ""

    if source.lower().endswith((".i64", ".idb")) and not database:
        database, source = source, ""
    if database and not database.lower().endswith((".i64", ".idb")):
        raise ValueError("database_path must end in .i64 or .idb")
    if not database and source:
        database = _default_database_path(source)
    if database and os.path.isfile(database):
        target = database
        operation = "reopen"
    else:
        if not source or not os.path.isfile(source):
            raise ValueError(f"Source file not found: {source!r}")
        os.makedirs(os.path.dirname(database) or ".", exist_ok=True)
        target = source
        operation = "create"

    command = [ida_bin]
    if headless:
        command.extend(["-A", f"-S{_RUNNER}"])
    if operation == "create":
        command.append(f"-o{database}")
    command.append(target)
    return command, operation, database


def _spawn(
    ida_bin: str,
    source_path: str = "",
    database_path: str = "",
    headless: bool = False,
    bind_host: str = "127.0.0.1",
    autosave_policy: str = "after_mutation",
    allow_python: bool = False,
    wait_timeout: float = 0,
) -> dict:
    """Launch an IDA session, creating or reopening its persistent database."""
    command, operation, database = _build_ida_command(
        ida_bin,
        source_path=source_path,
        database_path=database_path,
        headless=headless,
    )
    source = os.path.abspath(source_path) if source_path else ""

    if not headless:
        # The GUI uses the same database selection semantics, without -A/-S.
        command = [ida_bin]
        if operation == "create":
            command.append(f"-o{database}")
            command.append(source)
        else:
            command.append(database)

    env = {
        **os.environ,
        "IDA_MCP_BIND": bind_host,
        "IDA_MCP_MODE": "headless" if headless else "gui",
        "IDA_MCP_SOURCE_PATH": source,
        "IDA_MCP_DATABASE_PATH": database,
        "IDA_MCP_AUTOSAVE": autosave_policy,
        "IDA_MCP_ALLOW_PYTHON": "1" if allow_python else "0",
    }
    if headless:
        # Suppress plugin auto-start until headless_runner finishes analysis;
        # the runner then starts the exact same bridge explicitly.
        env["IDA_HEADLESS"] = "1"
    else:
        env.pop("IDA_HEADLESS", None)

    if allow_python and bind_host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("allow_python requires a loopback bind address")

    if sys.platform == "win32":
        kwargs = {
            "creationflags": subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NEW_PROCESS_GROUP,
            "env": env,
        }
    else:
        kwargs = {"start_new_session": True, "close_fds": True, "env": env}

    proc = subprocess.Popen(command, **kwargs)
    result = {
        "pid": proc.pid,
        "session_id": f"ida-{proc.pid}",
        "ida_bin": ida_bin,
        "source_path": source,
        "database_path": database,
        "mode": "headless" if headless else "gui",
        "operation": operation,
        "protocol_version": "1.0",
        "autosave_policy": autosave_policy,
    }
    if not wait_timeout:
        return result

    deadline = time.monotonic() + max(wait_timeout, 0.1)
    registration_path = os.path.join(_REGISTRATION_DIR, f"{proc.pid}.json")
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return {
                **result,
                "ready": False,
                "error": "IDA exited before its MCP bridge registered",
                "exit_code": proc.returncode,
            }
        try:
            with open(registration_path, encoding="utf-8") as registration_file:
                registration = json.load(registration_file)
            return {**result, **registration, "ready": True}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            time.sleep(0.1)

    return {
        **result,
        "ready": False,
        "warning": (
            f"IDA did not register within {wait_timeout:g}s; process was left running"
        ),
    }


def _server_ida_binary(server, *, headless: bool) -> str | None:
    """Resolve the correct frontend for each request mode."""
    if server.ida_path_override:
        return server.ida_path_override
    return _find_ida(headless=headless)


class SpawnHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[spawn] {self.address_string()} {fmt % args}")

    def _json(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/ping":
            self._json(
                {
                    "status": "ok",
                    "server": "ida-spawn",
                    "ida": self.server.ida_bin or "not found",
                    "headless": self.server.headless,
                }
            )
        else:
            self._json({"error": f"Unknown: {self.path}"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        if self.path == "/upload":
            filename = (
                os.path.basename(body.get("filename", "upload.bin")) or "upload.bin"
            )
            data_b64 = body.get("data", "")
            spawn = body.get("spawn", True)

            if not data_b64:
                self._json({"error": "Provide 'data' (base64 bytes)"}, 400)
                return

            os.makedirs(UPLOAD_DIR, exist_ok=True)
            dest = os.path.join(UPLOAD_DIR, filename)
            try:
                raw = base64.b64decode(data_b64)
            except Exception as e:
                self._json({"error": f"Base64 decode failed: {e}"}, 400)
                return

            with open(dest, "wb") as f:
                f.write(raw)

            result = {"path": dest, "size": len(raw), "spawned": False}

            if spawn:
                headless = bool(body.get("headless", self.server.headless))
                ida_bin = _server_ida_binary(self.server, headless=headless)
                if not ida_bin:
                    result["spawn_error"] = (
                        "IDA binary not found. Pass --ida-path or set IDA_PATH env var."
                    )
                else:
                    try:
                        info = _spawn(
                            ida_bin,
                            source_path=dest,
                            database_path=body.get("database_path", ""),
                            headless=headless,
                            bind_host=self.server.bridge_bind,
                            autosave_policy=body.get(
                                "autosave_policy", self.server.autosave_policy
                            ),
                            allow_python=body.get(
                                "allow_python", self.server.allow_python
                            ),
                            wait_timeout=body.get(
                                "start_timeout", self.server.start_timeout
                            ),
                        )
                        result.update(info)
                        result["spawned"] = True
                        mode = "headless idat64" if headless else "IDA"
                        result["note"] = (
                            f"{mode} (PID {info['pid']}) opening {dest}. "
                            "After auto-analysis, use --scan to find the plugin port."
                        )
                    except Exception as e:
                        result["spawn_error"] = f"Popen failed: {e}"

            self._json(result)

        elif self.path == "/spawn":
            source_path = body.get("source_path", body.get("path", ""))
            database_path = body.get("database_path", "")
            if not source_path and not database_path:
                self._json(
                    {"error": "Provide source_path or an existing database_path"},
                    400,
                )
                return
            headless = bool(body.get("headless", self.server.headless))
            ida_bin = _server_ida_binary(self.server, headless=headless)
            if not ida_bin:
                self._json({"error": "IDA binary not found"}, 400)
                return
            try:
                info = _spawn(
                    ida_bin,
                    source_path=source_path,
                    database_path=database_path,
                    headless=headless,
                    bind_host=self.server.bridge_bind,
                    autosave_policy=body.get(
                        "autosave_policy", self.server.autosave_policy
                    ),
                    allow_python=body.get("allow_python", self.server.allow_python),
                    wait_timeout=body.get("start_timeout", self.server.start_timeout),
                )
                self._json({"spawned": True, **info})
            except (OSError, ValueError) as e:
                self._json({"error": f"Popen failed: {e}"}, 500)

        else:
            self._json({"error": f"Unknown: {self.path}"}, 404)


def main():
    parser = argparse.ArgumentParser(description="Standalone IDA spawn server")
    parser.add_argument(
        "--ida-path", default=None, help="Path to ida64.exe / idat64.exe / ida64"
    )
    parser.add_argument(
        "--headless", action="store_true", help="Spawn idat64 (no GUI) instead of ida64"
    )
    parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Spawn-server listen address (default: loopback)",
    )
    parser.add_argument(
        "--bridge-bind",
        default=os.environ.get("IDA_MCP_BIND", "127.0.0.1"),
        help="Bind address passed to launched IDA bridges (default: loopback)",
    )
    parser.add_argument(
        "--autosave-policy",
        choices=("after_mutation", "manual"),
        default="after_mutation",
    )
    parser.add_argument(
        "--allow-python",
        action="store_true",
        help="Allow arbitrary IDAPython in launched loopback-only sessions",
    )
    parser.add_argument(
        "--start-timeout",
        type=float,
        default=300.0,
        help="Seconds to wait for a launched IDA bridge registration",
    )
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    ida_bin = args.ida_path or _find_ida(headless=args.headless)
    if ida_bin:
        mode = "headless (idat64)" if args.headless else "GUI (ida64)"
        print(f"[spawn] IDA binary ({mode}): {ida_bin}")
        if args.headless and not os.path.isfile(_RUNNER):
            print(f"[spawn] WARNING: headless_runner.py not found at {_RUNNER}")
    else:
        print("[spawn] WARNING: IDA binary not found — uploads will save but not spawn")
        print("[spawn]   Pass --ida-path or set IDA_PATH to fix this")

    server = http.server.HTTPServer((args.bind, args.port), SpawnHandler)
    server.ida_bin = ida_bin
    server.ida_path_override = args.ida_path
    server.headless = args.headless
    server.bridge_bind = args.bridge_bind
    server.autosave_policy = args.autosave_policy
    server.allow_python = args.allow_python
    server.start_timeout = args.start_timeout
    print(f"[spawn] Listening on http://{args.bind}:{args.port}")
    print(f"[spawn] Upload dir: {UPLOAD_DIR}")
    print("[spawn] Stop with Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[spawn] Stopped.")


if __name__ == "__main__":
    main()
