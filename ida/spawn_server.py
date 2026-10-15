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
    python spawn_server.py --headless --ida-path "C:\\Program Files\\IDA Pro 8.4\\idat64.exe"

Headless mode uses idat64 (text UI) instead of ida64 and automatically passes
-A (auto-accept) and -S headless_runner.py so the MCP server stays alive without
a visible IDA window.  Requires idat64.exe to be on PATH or supplied via
--ida-path / IDA_PATH.

Environment variables:
    IDA_PATH        Path to ida64.exe / idat64.exe / ida64
    IDA_MCP_BIND    Bind address (default 0.0.0.0)
"""

import argparse
import base64
import http.server
import json
import os
import subprocess
import sys

PORT = 13336
UPLOAD_DIR = os.path.join(os.path.expanduser("~"), ".ida_mcp", "uploads")
_RUNNER = os.path.join(os.path.dirname(__file__), "headless_runner.py")

# Common IDA install locations to probe when --ida-path is not given.
# Each tuple is (gui_binary, headless_binary).
_CANDIDATE_PAIRS = [
    # Windows
    (r"C:\Program Files\IDA Pro 9.2\ida64.exe",  r"C:\Program Files\IDA Pro 9.2\idat64.exe"),
    (r"C:\Program Files\IDA Pro 8.4\ida64.exe",  r"C:\Program Files\IDA Pro 8.4\idat64.exe"),
    (r"C:\Program Files\IDA Pro 8.3\ida64.exe",  r"C:\Program Files\IDA Pro 8.3\idat64.exe"),
    (r"C:\Program Files\IDA Pro 8.2\ida64.exe",  r"C:\Program Files\IDA Pro 8.2\idat64.exe"),
    (r"C:\Program Files\IDA Pro 8.1\ida64.exe",  r"C:\Program Files\IDA Pro 8.1\idat64.exe"),
    (r"C:\Program Files\IDA Pro 8.0\ida64.exe",  r"C:\Program Files\IDA Pro 8.0\idat64.exe"),
    (r"C:\Program Files\IDA Pro 7.7\ida64.exe",  r"C:\Program Files\IDA Pro 7.7\idat64.exe"),
    # macOS
    ("/Applications/IDA Pro 9.2/ida64.app/Contents/MacOS/ida64",
     "/Applications/IDA Pro 9.2/idat64.app/Contents/MacOS/idat64"),
    ("/Applications/IDA Pro 8.4/ida64.app/Contents/MacOS/ida64",
     "/Applications/IDA Pro 8.4/idat64.app/Contents/MacOS/idat64"),
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
        # Fall back to the other variant if the preferred one is missing
        if os.path.isfile(pair[1 - idx]):
            return pair[1 - idx]
    return None


def _spawn(ida_bin: str, file_path: str, headless: bool = False) -> dict:
    """Launch IDA on file_path and return {pid, ida_bin, file}."""
    if headless:
        cmd = [ida_bin, "-A", f"-S{_RUNNER}", file_path]
    else:
        cmd = [ida_bin, file_path]

    # Always bind to all interfaces so the MCP plugin is reachable remotely.
    env = {**os.environ, "IDA_MCP_BIND": "0.0.0.0"}

    if sys.platform == "win32":
        kwargs = {
            "creationflags": subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
            "env": env,
        }
    else:
        kwargs = {"start_new_session": True, "close_fds": True, "env": env}

    proc = subprocess.Popen(cmd, **kwargs)
    return {"pid": proc.pid, "ida_bin": ida_bin, "file": file_path, "headless": headless}


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
            self._json({
                "status": "ok",
                "server": "ida-spawn",
                "ida": self.server.ida_bin or "not found",
                "headless": self.server.headless,
            })
        else:
            self._json({"error": f"Unknown: {self.path}"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}

        if self.path == "/upload":
            filename = os.path.basename(body.get("filename", "upload.bin")) or "upload.bin"
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
                ida_bin = self.server.ida_bin
                if not ida_bin:
                    result["spawn_error"] = (
                        "IDA binary not found. Pass --ida-path or set IDA_PATH env var."
                    )
                else:
                    try:
                        headless = self.server.headless
                        info = _spawn(ida_bin, dest, headless=headless)
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
            path = body.get("path", "")
            if not path or not os.path.isfile(path):
                self._json({"error": f"File not found: {path!r}"}, 400)
                return
            ida_bin = self.server.ida_bin
            if not ida_bin:
                self._json({"error": "IDA binary not found"}, 400)
                return
            try:
                info = _spawn(ida_bin, path, headless=self.server.headless)
                self._json({"spawned": True, **info})
            except Exception as e:
                self._json({"error": f"Popen failed: {e}"}, 500)

        else:
            self._json({"error": f"Unknown: {self.path}"}, 404)


def main():
    parser = argparse.ArgumentParser(description="Standalone IDA spawn server")
    parser.add_argument("--ida-path", default=None,
                        help="Path to ida64.exe / idat64.exe / ida64")
    parser.add_argument("--headless", action="store_true",
                        help="Spawn idat64 (no GUI) instead of ida64")
    parser.add_argument("--bind", default=os.environ.get("IDA_MCP_BIND", "0.0.0.0"))
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
    server.headless = args.headless
    print(f"[spawn] Listening on http://{args.bind}:{args.port}")
    print(f"[spawn] Upload dir: {UPLOAD_DIR}")
    print(f"[spawn] Stop with Ctrl+C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[spawn] Stopped.")


if __name__ == "__main__":
    main()
