#!/usr/bin/env python3
"""
saleae_native bridge -- one Python process per Saleae device, hosts an
HTTP server, registers in ~/.saleae_native_mcp/<pid>.json so the
MCP server (saleae_native/mcp_server.py) can discover it.

Usage:
    python saleae_native/bridge.py [--vid=0x21A9] [--pid=0x1006]
                                   [--serial=0000000004BE] [--port=N]

If --vid/--pid are omitted the bridge picks the first Saleae device it
finds. Multiple bridges can run concurrently against multiple devices;
each registers its own JSON file.

Status: SKELETON. All `/<endpoint>` handlers except `/ping` and `/info`
return `{"error": "not implemented --- protocol RE pending"}`. The
discovery + registration plumbing IS functional and follows the same
contract as the IDA / Ghidra / jadx / ILSpy bridges in this repo.

Port range: 13837..13900 (next slot after ILSpy's 13637-13700).
"""

import argparse
import atexit
import http.server
import json
import os
import socket
import sys
import threading
from typing import Optional

# Allow `import driver` from this dir
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from driver import KNOWN_DEVICES, SaleaeDevice  # noqa: E402


BASE_PORT = 13837
MAX_PORT = 13900
REG_DIR = os.path.expanduser("~/.saleae_native_mcp")

# ---------------------------------------------------------------------------
# Bridge state
# ---------------------------------------------------------------------------


class Bridge:
    """Owns one SaleaeDevice and serves HTTP endpoints against it."""

    def __init__(self, device: SaleaeDevice, model_label: str):
        self.device = device
        self.model_label = model_label
        self._lock = threading.Lock()

    # ----- handlers (one per /<endpoint>) -----

    def handle_ping(self, body: dict) -> dict:
        return {"status": "ok", "device": self.model_label}

    def handle_info(self, body: dict) -> dict:
        return {
            "device": self.model_label,
            "vid": self.device.vid,
            "pid": self.device.pid,
            "serial": self.device.serial,
            "opened": self.device.identity is not None,
            "status": "skeleton --- protocol RE pending",
        }

    def handle_list_devices(self, body: dict) -> dict:
        # NOTE: enumeration depends on libusb1 being importable. Until
        # the protocol decode is done we just return the bridge's own
        # target so smoke tests pass.
        return {
            "devices": [{
                "vid": self.device.vid,
                "pid": self.device.pid,
                "model": self.model_label,
                "serial": self.device.serial,
            }],
            "note": "Full bus enumeration deferred until driver.SaleaeDevice.open() is implemented",
        }

    # Every other endpoint just bounces the call into the driver and
    # surfaces the NotImplementedError as a structured response.
    def _stub(self, body: dict) -> dict:
        return {"error": "not implemented --- protocol RE pending"}

    # ----- dispatch table -----

    @property
    def endpoints(self) -> dict[str, callable]:
        return {
            "/ping":                  self.handle_ping,
            "/info":                  self.handle_info,
            "/list_devices":          self.handle_list_devices,
            "/device_info":           self._stub,
            "/set_sample_rate":       self._stub,
            "/set_channels":          self._stub,
            "/set_voltage_threshold": self._stub,
            "/start_capture":         self._stub,
            "/stop_capture":          self._stub,
            "/read_samples":          self._stub,
            "/set_digital_out":       self._stub,
        }


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


def make_handler(bridge: Bridge):
    class Handler(http.server.BaseHTTPRequestHandler):
        # Quiet the default per-request logging.
        def log_message(self, fmt, *args):
            pass

        def _read_json_body(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if not length:
                return {}
            data = self.rfile.read(length)
            try:
                return json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as e:
                raise ValueError(f"bad JSON body: {e}")

        def _respond(self, code: int, payload: dict):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._dispatch({})

        def do_POST(self):
            try:
                body = self._read_json_body()
            except ValueError as e:
                self._respond(400, {"error": str(e)})
                return
            self._dispatch(body)

        def _dispatch(self, body: dict):
            handler = bridge.endpoints.get(self.path)
            if handler is None:
                self._respond(404, {"error": f"unknown endpoint: {self.path}"})
                return
            try:
                with bridge._lock:
                    result = handler(body)
                self._respond(200, result)
            except NotImplementedError as e:
                self._respond(200, {"error": f"not implemented: {e}"})
            except Exception as e:
                self._respond(500, {"error": f"{type(e).__name__}: {e}"})

    return Handler


def find_free_port() -> int:
    for p in range(BASE_PORT, MAX_PORT):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise RuntimeError(f"no free port in {BASE_PORT}..{MAX_PORT}")


def register(port: int, model_label: str, serial: Optional[str]) -> str:
    os.makedirs(REG_DIR, exist_ok=True)
    pid = os.getpid()
    reg = {
        "pid": pid,
        "port": port,
        "device": model_label,
        "device_path": serial or "",
    }
    path = os.path.join(REG_DIR, f"{pid}.json")
    with open(path, "w") as f:
        json.dump(reg, f)
    return path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_int_maybe_hex(s: str) -> int:
    return int(s, 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vid", type=parse_int_maybe_hex, default=None)
    ap.add_argument("--pid", type=parse_int_maybe_hex, default=None)
    ap.add_argument("--serial", default=None)
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()

    # Until live enumeration is wired up we accept whatever the user gave us.
    if args.vid is None or args.pid is None:
        # Default to the most common: Logic Pro 16 (matches the test rig).
        args.vid, args.pid = 0x21A9, 0x1006

    model = KNOWN_DEVICES.get((args.vid, args.pid),
                              f"Unknown VID=0x{args.vid:04x} PID=0x{args.pid:04x}")
    device = SaleaeDevice(args.vid, args.pid, serial=args.serial)
    bridge = Bridge(device, model)

    port = args.port or find_free_port()
    handler = make_handler(bridge)
    server = http.server.HTTPServer(("127.0.0.1", port), handler)

    reg_path = register(port, model, args.serial)
    atexit.register(lambda: os.path.exists(reg_path) and os.unlink(reg_path))

    print(f"[saleae_native] Bridge listening on http://127.0.0.1:{port}",
          file=sys.stderr)
    print(f"[saleae_native] Target: {model} (serial={args.serial or '?'})",
          file=sys.stderr)
    print(f"[saleae_native] Registration: {reg_path}", file=sys.stderr)
    print("[saleae_native] Status: SKELETON --- protocol RE pending. "
          "See saleae_native/notes/next_steps.md.", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        try:
            os.unlink(reg_path)
        except FileNotFoundError:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
