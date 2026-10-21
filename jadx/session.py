"""Lifecycle helpers for owned, headless JADX bridge processes."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Callable


DEFAULT_START_TIMEOUT = 120.0


def default_bridge_jar() -> Path:
    """Return the configured bridge jar, or the repository build artifact."""
    configured = os.environ.get("JADX_MCP_BRIDGE_JAR")
    if configured:
        return Path(configured).expanduser().resolve()
    return (
        Path(__file__).parent
        / "jadx-mcp-bridge"
        / "build"
        / "libs"
        / "jadx-mcp-bridge.jar"
    )


def start_bridge(
    input_path: str,
    *,
    bridge_jar: str = "",
    java_command: str = "java",
    timeout: float = DEFAULT_START_TIMEOUT,
    registrations: Callable[[], list[dict]],
) -> dict:
    """Start an owned bridge and wait for its registration record."""
    target = Path(input_path).expanduser().resolve()
    if not target.is_file():
        return {"error": f"Input file does not exist: {target}"}

    jar = (
        Path(bridge_jar).expanduser().resolve() if bridge_jar else default_bridge_jar()
    )
    if not jar.is_file():
        return {
            "error": f"JADX MCP bridge jar does not exist: {jar}",
            "remediation": "Build it with gradle shadowJar or set JADX_MCP_BRIDGE_JAR.",
        }

    process = subprocess.Popen(  # noqa: S603 - caller explicitly selects local executable
        [java_command, "-jar", str(jar), str(target)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    deadline = time.monotonic() + max(timeout, 0.1)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return {
                "error": "JADX bridge exited before registering",
                "exit_code": process.returncode,
            }
        for instance in registrations():
            if instance.get("pid") == process.pid:
                return {
                    **instance,
                    "success": True,
                    "session_id": instance.get("session_id", f"jadx-{process.pid}"),
                    "provider_id": "jadx",
                    "mode": "headless",
                    "owned": True,
                    "read_only": True,
                    "target": str(target),
                }
        time.sleep(0.1)

    process.terminate()
    return {"error": f"Timed out waiting {timeout:g}s for JADX bridge registration"}
