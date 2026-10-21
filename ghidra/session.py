"""Launch helpers for owned Ghidra analyzeHeadless sessions."""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Callable


DEFAULT_START_TIMEOUT = 300.0


def find_analyze_headless(explicit: str = "") -> Path | None:
    """Resolve Ghidra's analyzeHeadless launcher without searching the network."""
    if explicit:
        candidate = Path(explicit).expanduser().resolve()
        return candidate if candidate.is_file() else None
    install = os.environ.get("GHIDRA_INSTALL_DIR")
    if not install:
        return None
    suffix = ".bat" if os.name == "nt" else ""
    candidate = (
        Path(install).expanduser().resolve() / "support" / f"analyzeHeadless{suffix}"
    )
    return candidate if candidate.is_file() else None


def _safe_project_name(target: Path) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", target.stem).strip("._") or "program"
    return f"mcp_{stem}_{int(time.time())}"


def _run_and_wait(
    command: list[str],
    *,
    registrations: Callable[[], list[dict]],
    existing_pids: set[int],
    match: Callable[[dict], bool],
    timeout: float,
    metadata: dict,
) -> dict:
    process = subprocess.Popen(  # noqa: S603 - command resolves to local Ghidra
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    deadline = time.monotonic() + max(timeout, 0.1)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return {
                "error": "Ghidra analyzeHeadless exited before registering",
                "exit_code": process.returncode,
            }
        for instance in registrations():
            pid = instance.get("pid")
            if pid not in existing_pids and match(instance):
                return {
                    **instance,
                    "success": True,
                    "session_id": instance.get("session_id", f"ghidra-{pid}"),
                    "provider_id": "ghidra",
                    "mode": "headless",
                    "owned": True,
                    "read_only": False,
                    **metadata,
                }
        time.sleep(0.2)
    process.terminate()
    return {"error": f"Timed out waiting {timeout:g}s for Ghidra registration"}


def create_headless_session(
    input_path: str,
    *,
    registrations: Callable[[], list[dict]],
    analyze_headless: str = "",
    project_dir: str = "",
    project_name: str = "",
    timeout: float = DEFAULT_START_TIMEOUT,
) -> dict:
    """Import a binary into an owned project and keep its bridge alive."""
    target = Path(input_path).expanduser().resolve()
    if not target.is_file():
        return {"error": f"Input file does not exist: {target}"}
    launcher = find_analyze_headless(analyze_headless)
    if launcher is None:
        return {
            "error": "Ghidra analyzeHeadless was not found.",
            "remediation": "Set GHIDRA_INSTALL_DIR or pass analyze_headless.",
        }
    projects = (
        Path(project_dir).expanduser().resolve()
        if project_dir
        else Path.home() / ".ghidra_mcp" / "projects"
    )
    projects.mkdir(parents=True, exist_ok=True)
    name = project_name or _safe_project_name(target)
    # Import and analyze to completion first. A post-script executed during the
    # initial import receives a transient Program whose canSave() is false;
    # keeping that script alive would prevent analyzeHeadless from performing
    # its own final save. Reopen the now-persistent program for the live bridge.
    import_command = [
        str(launcher),
        str(projects),
        name,
        "-import",
        str(target),
    ]
    try:
        imported = subprocess.run(  # noqa: S603 - local Ghidra launcher
            import_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Timed out after {timeout:g}s importing into Ghidra"}
    if imported.returncode != 0:
        return {
            "error": "Ghidra import failed",
            "exit_code": imported.returncode,
            "output": imported.stdout[-4000:],
        }

    script_dir = Path(__file__).resolve().parent / "scripts"
    existing = {item.get("pid") for item in registrations()}
    command = [
        str(launcher),
        str(projects),
        name,
        "-process",
        target.name,
        "-scriptPath",
        str(script_dir),
        "-postScript",
        "ghidra_mcp_bridge.java",
        "--headless-owned",
    ]
    return _run_and_wait(
        command,
        registrations=registrations,
        existing_pids=existing,
        match=lambda item: str(item.get("program", "")).lower() == target.name.lower(),
        timeout=timeout,
        metadata={
            "target": str(target),
            "project_dir": str(projects),
            "project_name": name,
        },
    )


def open_headless_session(
    project_dir: str,
    project_name: str,
    program_name: str,
    *,
    registrations: Callable[[], list[dict]],
    analyze_headless: str = "",
    timeout: float = DEFAULT_START_TIMEOUT,
) -> dict:
    """Open an existing Ghidra project program as an owned session."""
    launcher = find_analyze_headless(analyze_headless)
    if launcher is None:
        return {
            "error": "Ghidra analyzeHeadless was not found.",
            "remediation": "Set GHIDRA_INSTALL_DIR or pass analyze_headless.",
        }
    projects = Path(project_dir).expanduser().resolve()
    if not projects.is_dir():
        return {"error": f"Project directory does not exist: {projects}"}
    script_dir = Path(__file__).resolve().parent / "scripts"
    existing = {item.get("pid") for item in registrations()}
    command = [
        str(launcher),
        str(projects),
        project_name,
        "-process",
        program_name,
        "-scriptPath",
        str(script_dir),
        "-postScript",
        "ghidra_mcp_bridge.java",
        "--headless-owned",
    ]
    return _run_and_wait(
        command,
        registrations=registrations,
        existing_pids=existing,
        match=lambda item: program_name.lower() in str(item.get("program", "")).lower(),
        timeout=timeout,
        metadata={
            "project_dir": str(projects),
            "project_name": project_name,
            "program": program_name,
        },
    )
