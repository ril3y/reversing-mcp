#!/usr/bin/env python3
"""
MCP server for saleae_native -- proxies Claude Code tool calls to a
locally running Saleae USB driver bridge that talks to the device directly
over WinUSB / libusb (no dependency on Saleae's Logic 2 app).

This is NOT the official Saleae MCP server. The other one (`saleae/` in
this repo) wraps Saleae's documented gRPC automation API and requires
Logic 2 to be running. This server talks to the device.

Status: SKELETON. Protocol decoding is pending --- see
`saleae_native/notes/` for the reverse-engineering notes that will drive
the next phase. Every tool that touches the wire currently returns
`{"error": "not implemented --- protocol RE pending"}`.

Usage:
    python saleae_native/mcp_server.py              # stdio mode for Claude Code
    python saleae_native/mcp_server.py --list       # list active bridges
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.fastmcp import FastMCP

from common import call_instance, discover_instances, list_instances_text

REG_DIR = os.path.expanduser("~/.saleae_native_mcp")
TOOL = "saleae_native"
NAME_KEYS = ("device", "device_path")

mcp = FastMCP("saleae_native")


def _call(endpoint, body=None, device=None):
    return call_instance(REG_DIR, endpoint, body, target=device,
                         tool_name=TOOL, name_keys=NAME_KEYS, timeout=120)


@mcp.tool()
def list_instances() -> str:
    """List active saleae_native bridges and the device each one targets."""
    return list_instances_text(REG_DIR, TOOL, name_key="device")


@mcp.tool()
def info(device: str = "") -> dict:
    """Get info about the bridge state (driver class, port, target device).

    Args:
        device: Substring (model or serial) to target a specific bridge (optional)
    """
    return _call("/info", device=device or None)


@mcp.tool()
def list_devices(device: str = "") -> dict:
    """Enumerate connected Saleae logic analyzers on the host bus.

    Returns each device's VID, PID, serial (when readable), model name
    (resolved from the PID table in `notes/inf_analysis.md`), and whether
    it's currently in firmware-loaded "operating" mode or raw FX2/FX3
    boot-ROM mode.

    Args:
        device: Substring filter (optional)
    """
    return _call("/list_devices", device=device or None)


@mcp.tool()
def device_info(device: str = "") -> dict:
    """Get model / VID / PID / serial / firmware version for a single device.

    Args:
        device: Substring to target a specific device (optional)
    """
    return _call("/device_info", device=device or None)


@mcp.tool()
def set_sample_rate(rate_hz: int, device: str = "") -> dict:
    """Configure the digital sample rate.

    Args:
        rate_hz: Sample rate in Hz. Valid options depend on the model
            (Pro 16 supports up to 500 MS/s digital).
        device: Substring to target a specific device (optional)
    """
    return _call("/set_sample_rate", {"rate_hz": rate_hz},
                 device=device or None)


@mcp.tool()
def set_channels(channels: list[int], device: str = "") -> dict:
    """Enable/disable channels by channel-number list.

    Args:
        channels: List of channel indices to enable (others disabled)
        device: Substring to target a specific device (optional)
    """
    return _call("/set_channels", {"channels": channels},
                 device=device or None)


@mcp.tool()
def set_voltage_threshold(volts: float, device: str = "") -> dict:
    """Set the digital input voltage threshold.

    Pro family supports an adjustable threshold (DAC-driven); older Logic
    family supports a small fixed set (1.8V, 3.3+V).

    Args:
        volts: Threshold voltage (e.g. 1.8, 3.3)
        device: Substring to target a specific device (optional)
    """
    return _call("/set_voltage_threshold", {"volts": volts},
                 device=device or None)


@mcp.tool()
def start_capture(sample_rate: int = 0, duration_ms: int = 0,
                  channels: list[int] | None = None, device: str = "") -> dict:
    """Begin a capture and start streaming samples.

    Args:
        sample_rate: Sample rate in Hz (0 = use last `set_sample_rate`)
        duration_ms: Capture length in ms (0 = stream until `stop_capture`)
        channels: Channel mask (None = use last `set_channels`)
        device: Substring to target a specific device (optional)
    """
    body = {"sample_rate": sample_rate, "duration_ms": duration_ms}
    if channels is not None:
        body["channels"] = channels
    return _call("/start_capture", body, device=device or None)


@mcp.tool()
def stop_capture(device: str = "") -> dict:
    """Stop an in-progress capture and flush remaining samples.

    Args:
        device: Substring to target a specific device (optional)
    """
    return _call("/stop_capture", {}, device=device or None)


@mcp.tool()
def read_samples(since_index: int = 0, max_count: int = 65536,
                 device: str = "") -> dict:
    """Read decoded sample data from the bridge's ring buffer.

    Args:
        since_index: First sample index to return (0 = from start)
        max_count: Maximum number of samples to return in one call
        device: Substring to target a specific device (optional)
    """
    return _call("/read_samples",
                 {"since_index": since_index, "max_count": max_count},
                 device=device or None)


@mcp.tool()
def set_digital_out(channel: int, value: int, device: str = "") -> dict:
    """Drive one of the device's GPIO output pins (debug-port-finder helper).

    The Saleae devices expose a small number of GPIOs through the
    FX3-side `GpioConfigure_CommandHandler` / `GpioValue_CommandHandler`
    requests. This is intended for the future "find a UART/JTAG by
    wiggling a pin and watching for a response" workflow.

    Args:
        channel: GPIO index (device-specific; see device_info)
        value: 0 or 1
        device: Substring to target a specific device (optional)
    """
    return _call("/set_digital_out",
                 {"channel": channel, "value": value},
                 device=device or None)


if __name__ == "__main__":
    if "--list" in sys.argv:
        instances = discover_instances(REG_DIR)
        if not instances:
            print("No active saleae_native instances.")
        else:
            print(f"{len(instances)} active instance(s):")
            for inst in instances:
                print(f"  port:{inst['port']}  pid:{inst.get('pid','?')}  device:{inst.get('device','?')}")
                print(f"    path: {inst.get('device_path', '?')}")
    else:
        mcp.run(transport="stdio")
