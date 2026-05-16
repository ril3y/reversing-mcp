"""
Test fixtures shared across reversing-mcp tests.

Provides:
  - ``fake_bridge``: a tiny in-process HTTP server you can register endpoints
    on, used to verify the MCP servers POST the right JSON bodies and parse
    responses correctly without involving IDA / Ghidra / jadx / ILSpy.
  - ``reg_dir``: a temporary registration directory the MCP servers can
    discover the fake bridge through.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Iterator

import pytest

# Make repo root importable so ``import common`` works from tests/.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class FakeBridge:
    """Threaded HTTP server with caller-supplied per-endpoint handlers.

    Each handler is ``fn(method, body_dict) -> (status, dict)``.
    The last request seen by an endpoint is recorded for assertion.
    """

    def __init__(self) -> None:
        self.routes: dict[str, Callable[[str, dict], tuple[int, dict]]] = {}
        self.calls: list[tuple[str, str, dict]] = []  # (path, method, body)
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def route(self, path: str, handler: Callable[[str, dict], tuple[int, dict]]) -> None:
        self.routes[path] = handler

    @property
    def port(self) -> int:
        assert self._server is not None, "FakeBridge not started"
        return self._server.server_address[1]

    def start(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args, **_kwargs):
                pass  # silence default logging

            def _read_body(self) -> dict:
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0:
                    return {}
                raw = self.rfile.read(length)
                try:
                    return json.loads(raw.decode("utf-8"))
                except json.JSONDecodeError:
                    return {}

            def _serve(self, method: str) -> None:
                body = self._read_body() if method == "POST" else {}
                outer.calls.append((self.path, method, body))
                handler = outer.routes.get(self.path)
                if handler is None:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"unknown endpoint"}')
                    return
                status, payload = handler(method, body)
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler convention)
                self._serve("GET")

            def do_POST(self):  # noqa: N802
                self._serve("POST")

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)


@pytest.fixture
def fake_bridge() -> Iterator[FakeBridge]:
    """A loopback HTTP bridge for one test."""
    bridge = FakeBridge()
    bridge.start()
    try:
        yield bridge
    finally:
        bridge.stop()


@pytest.fixture
def reg_dir(tmp_path) -> str:
    """Empty per-test registration directory."""
    d = tmp_path / "reg"
    d.mkdir()
    return str(d)


def write_registration(reg_dir: str, *, port: int, name_key: str = "name",
                       name: str = "target", pid: int | None = None) -> int:
    """Write a registration JSON file pointing at ``port``. Returns the PID used."""
    if pid is None:
        pid = os.getpid()  # always alive — discovery treats it as live
    payload = {"pid": pid, "port": port, name_key: name}
    path = os.path.join(reg_dir, f"{pid}.json")
    with open(path, "w") as f:
        json.dump(payload, f)
    return pid


@contextmanager
def bridge_registered(fake_bridge: FakeBridge, reg_dir: str,
                      *, name_key: str = "name", name: str = "target") -> Iterator[int]:
    """Write+remove a registration that points at the live fake_bridge."""
    pid = write_registration(reg_dir, port=fake_bridge.port,
                             name_key=name_key, name=name)
    try:
        yield pid
    finally:
        try:
            os.unlink(os.path.join(reg_dir, f"{pid}.json"))
        except FileNotFoundError:
            pass
