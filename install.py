#!/usr/bin/env python3
"""
reversing-mcp interactive installer.

Walks the user through:
  1. Picking which MCP servers to install (multi-select).
  2. Picking install scope (user-global vs. this project only).
  3. Running per-tool build + install actions:
       - ida    → copy plugin.py to the IDA user plugins dir
       - ghidra → build the extension (if GHIDRA_INSTALL_DIR is set) and
                  extract it into the user Extensions dir
       - jadx   → gradle shadowJar (needs JDK 17+)
       - ilspy  → dotnet publish -c Release (needs .NET 8 SDK)
       - ble    → install the optional Bleak transport
       - capstone → install the optional raw-byte disassembly engine
  4. Registering the unified server with Claude Code and/or Codex.

Non-interactive mode for CI:
    python install.py --all --scope user --skip-builds --clients claude,codex
    python install.py --register-only --scope user --clients claude,codex

Re-runnable; reports what's already installed and offers to update/reinstall.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Self-bootstrap: install rich + questionary if missing.
# ---------------------------------------------------------------------------


def _ensure_deps() -> None:
    missing = []
    try:
        import rich  # noqa: F401
    except ImportError:
        missing.append("rich")
    try:
        import questionary  # noqa: F401
    except ImportError:
        missing.append("questionary")
    if missing:
        print(f"First run — installing installer dependencies: {', '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])


_ensure_deps()

import questionary  # noqa: E402
from questionary import Style  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.panel import Panel  # noqa: E402
from rich.text import Text  # noqa: E402


REPO_ROOT = Path(__file__).resolve().parent
console = Console()

QSTYLE = Style(
    [
        ("question", "bold fg:#5fafd7"),
        ("answer", "fg:#87d787 bold"),
        ("pointer", "fg:#ff8700 bold"),
        ("highlighted", "fg:#ffd75f bold"),
        ("selected", "fg:#87d787"),
        ("instruction", "fg:#808080 italic"),
    ]
)


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


@dataclass
class Tool:
    key: str
    label: str
    description: str
    presence_rel: str  # provider component used to detect checkout availability
    build: Callable[["Context"], "Result"]
    deploy: Callable[["Context"], "Result"]

    @property
    def presence_path(self) -> Path:
        return REPO_ROOT / self.presence_rel

    def present(self) -> bool:
        return self.presence_path.is_file()


@dataclass
class Context:
    scope: str  # "user" | "project"
    skip_builds: bool
    dry_run: bool
    clients: tuple[str, ...]
    allow_scripts: bool = False
    script_providers: str = ""
    # When False (default), build_* tries the prebuilt release asset first
    # and only falls back to a source build if the asset is missing or the
    # network is unreachable.
    from_source: bool = False
    # Which release to pull prebuilts from. "latest" → /releases/latest;
    # any other value is treated as a tag name like "v0.4.0".
    release_tag: str = "latest"


@dataclass
class Result:
    ok: bool
    summary: str
    note: str = ""


# ---------------------------------------------------------------------------
# Per-platform install paths
# ---------------------------------------------------------------------------


def ida_plugins_dir() -> Path:
    if platform.system() == "Windows":
        return Path(os.environ["APPDATA"]) / "Hex-Rays" / "IDA Pro" / "plugins"
    # POSIX
    return Path.home() / ".idapro" / "plugins"


def ghidra_user_extensions_dir() -> Path | None:
    """Locate the user's Ghidra .ghidra_<version>/Extensions/ directory.

    Picks the most-recently-modified one if multiple versions exist.
    Returns None if no Ghidra user dir is found.
    """
    candidates: list[Path] = []
    if platform.system() == "Windows":
        candidates.append(Path(os.environ.get("APPDATA", "")) / "ghidra")
        candidates.append(Path.home() / ".ghidra")
    else:
        candidates.append(Path.home() / ".ghidra")
        candidates.append(Path.home() / ".config" / "ghidra")
    for base in candidates:
        if not base.is_dir():
            continue
        versioned = sorted(
            (
                p
                for p in base.iterdir()
                if p.is_dir() and p.name.startswith(("ghidra_", ".ghidra_"))
            ),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if versioned:
            return versioned[0] / "Extensions"
    return None


# ---------------------------------------------------------------------------
# Per-tool: build + deploy
# ---------------------------------------------------------------------------


def _java_build_env() -> dict[str, str]:
    """Return an environment whose JAVA_HOME points at a JDK when available."""
    env = os.environ.copy()
    javac_name = "javac.exe" if platform.system() == "Windows" else "javac"
    configured = Path(env.get("JAVA_HOME", "")) / "bin" / javac_name
    if configured.is_file():
        return env
    javac = shutil.which("javac")
    if javac:
        env["JAVA_HOME"] = str(Path(javac).resolve().parent.parent)
    return env


def _run(
    cmd: list[str],
    cwd: Path | None = None,
    dry: bool = False,
    env: dict[str, str] | None = None,
) -> int:
    if dry:
        console.print(
            f"  [dim]would run:[/] [cyan]{' '.join(cmd)}[/]"
            + (f" [dim]in {cwd}[/]" if cwd else "")
        )
        return 0
    console.print(f"  [dim]$[/] [cyan]{' '.join(cmd)}[/]")
    return subprocess.call(cmd, cwd=str(cwd) if cwd else None, env=env)


# --- Prebuilt-release fast path ---------------------------------------------
#
# CI publishes bridge artifacts on every tag push (see .github/workflows/
# release.yml). If a matching asset is available, downloading it skips the
# whole gradle / dotnet build step.

RELEASES_REPO = "ril3y/reversing-mcp"
PREBUILT_CACHE = Path.home() / ".cache" / "reversing-mcp"


def _fetch_latest_release_assets(tag: str = "latest") -> list[tuple[str, str]]:
    """Return [(asset_name, download_url), ...] for the requested release.

    `tag="latest"` queries /releases/latest; any other value is treated as a
    literal tag (`/releases/tags/<tag>`). Returns `[]` on any network or
    parse failure — caller should fall back to source build.
    """
    path = "latest" if tag == "latest" else f"tags/{tag}"
    url = f"https://api.github.com/repos/{RELEASES_REPO}/releases/{path}"
    try:
        req = urllib.request.Request(
            url, headers={"Accept": "application/vnd.github+json"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []
    return [(a["name"], a["browser_download_url"]) for a in data.get("assets", [])]


def _download(url: str, dest: Path, dry: bool = False) -> bool:
    if dry:
        console.print(f"  [dim]would download:[/] {url} → {dest}")
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(url, timeout=60) as r, open(dest, "wb") as f:
            shutil.copyfileobj(r, f)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        console.print(f"  [yellow]download failed:[/] {exc}")
        return False
    return True


def _pick_asset(
    assets: list[tuple[str, str]], substr: str, suffix: str
) -> tuple[str, str] | None:
    """First asset whose name contains `substr` and ends with `suffix`."""
    for name, url in assets:
        if substr in name and name.endswith(suffix):
            return name, url
    return None


# ---- IDA ----


def build_ida(ctx: Context) -> Result:
    return Result(True, "no build step")


def deploy_ida(ctx: Context) -> Result:
    src = REPO_ROOT / "ida" / "plugin.py"
    if not src.is_file():
        return Result(False, f"missing source: {src}")
    dst_dir = ida_plugins_dir()
    if ctx.dry_run:
        console.print(f"  [dim]would copy:[/] {src} → {dst_dir / 'ida_mcp_plugin.py'}")
        return Result(True, f"(dry-run) → {dst_dir}")
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / "ida_mcp_plugin.py"
    shutil.copy2(src, dst)
    return Result(
        True,
        f"copied to {dst}",
        note="Plugin auto-starts on next IDA launch (Ctrl+Shift+M toggles).",
    )


# ---- Ghidra ----


def build_ghidra(ctx: Context) -> Result:
    if ctx.skip_builds:
        return Result(True, "(skipped per --skip-builds)")
    bridge_dir = REPO_ROOT / "ghidra" / "ghidra-mcp-bridge"
    dist = bridge_dir / "dist"

    # Fast path: prebuilt release asset.
    if not ctx.from_source:
        assets = _fetch_latest_release_assets(ctx.release_tag)
        pick = _pick_asset(assets, "ghidra-mcp-bridge", ".zip")
        if pick:
            name, url = pick
            dst = dist / name
            console.print(f"  [dim]prebuilt:[/] {name} from {ctx.release_tag}")
            if _download(url, dst, dry=ctx.dry_run):
                return Result(
                    True,
                    f"downloaded {name}",
                    note="No Ghidra install or JDK needed for this path.",
                )
            console.print("  [yellow]falling back to source build[/]")

    # Source build needs Ghidra to compile against.
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir:
        return Result(
            False,
            "GHIDRA_INSTALL_DIR not set",
            note="Either point GHIDRA_INSTALL_DIR at your Ghidra install root "
            "(e.g. C:\\ghidra_11.0.1_PUBLIC) for a source build, OR omit "
            "--from-source so the installer downloads the prebuilt release "
            "asset (none was found just now — first release pending?).",
        )
    gradlew = bridge_dir / (
        "gradlew.bat" if platform.system() == "Windows" else "gradlew"
    )
    cmd = [str(gradlew), "--no-daemon"] if gradlew.exists() else ["gradle"]
    rc = _run(cmd, cwd=bridge_dir, dry=ctx.dry_run, env=_java_build_env())
    if rc != 0:
        return Result(False, f"gradle build exited {rc}")
    return Result(True, "extension ZIP built")


def deploy_ghidra(ctx: Context) -> Result:
    dist = REPO_ROOT / "ghidra" / "ghidra-mcp-bridge" / "dist"
    if not dist.is_dir():
        return Result(False, "no dist/ — build failed or skipped")
    zips = sorted(dist.glob("*.zip"))
    if not zips:
        return Result(False, "no extension ZIP in dist/")
    target_dir = ghidra_user_extensions_dir()
    if not target_dir:
        return Result(
            False,
            "could not locate Ghidra user dir (no .ghidra_* found)",
            note="Install Ghidra and run it once to create the user dir, "
            "or copy the ZIP from dist/ manually.",
        )
    source_zip = zips[-1]
    with zipfile.ZipFile(source_zip) as archive:
        roots = {Path(name).parts[0] for name in archive.namelist() if name}
    if len(roots) != 1:
        return Result(False, f"extension ZIP has invalid roots: {sorted(roots)}")
    extension_name = roots.pop()
    install_dir = target_dir / extension_name
    if install_dir.resolve().parent != target_dir.resolve():
        return Result(False, f"unsafe extension path in ZIP: {extension_name}")
    if ctx.dry_run:
        console.print(f"  [dim]would extract:[/] {source_zip} → {install_dir}")
        return Result(True, f"(dry-run) → {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        if install_dir.exists():
            shutil.rmtree(install_dir)
        with zipfile.ZipFile(source_zip) as archive:
            archive.extractall(target_dir)
    except OSError as error:
        return Result(
            False,
            f"could not replace {install_dir}: {error}",
            note="Close running Ghidra processes and run the installer again.",
        )
    return Result(
        True,
        f"installed {extension_name} in {target_dir}",
        note="Restart Ghidra, then enable the MCP plugin in File → Configure.",
    )


# ---- jadx ----


def build_jadx(ctx: Context) -> Result:
    if ctx.skip_builds:
        return Result(True, "(skipped per --skip-builds)")
    bridge_dir = REPO_ROOT / "jadx" / "jadx-mcp-bridge"
    if not bridge_dir.is_dir():
        return Result(False, "jadx/jadx-mcp-bridge missing — branch checkout issue?")
    # Fast path: prebuilt fat JAR.
    if not ctx.from_source:
        assets = _fetch_latest_release_assets(ctx.release_tag)
        pick = _pick_asset(assets, "jadx-mcp-bridge", ".jar")
        if pick:
            name, url = pick
            dst = bridge_dir / "build" / "libs" / name
            console.print(f"  [dim]prebuilt:[/] {name} from {ctx.release_tag}")
            if _download(url, dst, dry=ctx.dry_run):
                return Result(
                    True, f"downloaded {name}", note="No JDK needed for this path."
                )
            console.print("  [yellow]falling back to source build[/]")

    # Source build via wrapper (preferred) or system gradle.
    gradlew = bridge_dir / (
        "gradlew.bat" if platform.system() == "Windows" else "gradlew"
    )
    if gradlew.exists():
        cmd = [str(gradlew), "--no-daemon", "shadowJar"]
    elif shutil.which("gradle") is not None:
        cmd = ["gradle", "shadowJar"]
    else:
        return Result(
            False,
            "no gradle wrapper and no system gradle",
            note="Update from upstream (vendored wrapper) or install gradle.",
        )
    rc = _run(cmd, cwd=bridge_dir, dry=ctx.dry_run, env=_java_build_env())
    if rc != 0:
        return Result(False, f"gradle shadowJar exited {rc}")
    return Result(
        True, "fat JAR built at jadx/jadx-mcp-bridge/build/libs/jadx-mcp-bridge.jar"
    )


def deploy_jadx(ctx: Context) -> Result:
    return Result(
        True,
        "no deploy step",
        note=(
            "Launch one bridge per APK: `java -jar "
            "jadx/jadx-mcp-bridge/build/libs/jadx-mcp-bridge.jar <apk>`"
        ),
    )


# ---- ILSpy ----


def build_ilspy(ctx: Context) -> Result:
    if ctx.skip_builds:
        return Result(True, "(skipped per --skip-builds)")
    proj_dir = REPO_ROOT / "ilspy" / "IlspyMcpBridge"
    if not proj_dir.is_dir():
        return Result(False, "ilspy/IlspyMcpBridge missing")

    # Fast path: prebuilt zip — extract into the publish dir so launching
    # the bridge resolves DLLs the same way as a from-source publish.
    if not ctx.from_source:
        assets = _fetch_latest_release_assets(ctx.release_tag)
        pick = _pick_asset(assets, "ilspy-mcp-bridge", ".zip")
        if pick:
            name, url = pick
            cache_zip = PREBUILT_CACHE / name
            console.print(f"  [dim]prebuilt:[/] {name} from {ctx.release_tag}")
            if _download(url, cache_zip, dry=ctx.dry_run):
                publish = proj_dir / "bin" / "Release" / "net8.0" / "publish"
                if not ctx.dry_run:
                    publish.mkdir(parents=True, exist_ok=True)
                    with zipfile.ZipFile(cache_zip) as z:
                        z.extractall(publish)
                return Result(
                    True,
                    f"unpacked {name} → {publish}",
                    note="No .NET SDK needed for this path. "
                    "Launch with `dotnet <publish>/ilspy-mcp-bridge.dll <asm>`.",
                )
            console.print("  [yellow]falling back to source build[/]")

    if shutil.which("dotnet") is None:
        return Result(
            False,
            "dotnet not on PATH",
            note="Install the .NET 8 SDK from https://dotnet.microsoft.com/download",
        )
    rc = _run(
        ["dotnet", "publish", "-c", "Release", "--nologo", "-v", "quiet"],
        cwd=proj_dir,
        dry=ctx.dry_run,
    )
    if rc != 0:
        return Result(False, f"dotnet publish exited {rc}")
    return Result(
        True, "binary built at ilspy/IlspyMcpBridge/bin/Release/net8.0/publish/"
    )


def deploy_ilspy(ctx: Context) -> Result:
    return Result(
        True,
        "no deploy step",
        note="Launch one bridge per assembly: `ilspy-mcp-bridge <path.dll>`",
    )


# ---- Frida ----
#
# Frida is the simplest of the tools to install: frida-python IS the client,
# so there's no in-tool bridge to build/copy. Just pip install the two
# packages and register the MCP server.


def build_frida(ctx: Context) -> Result:
    if ctx.skip_builds:
        return Result(True, "(skipped per --skip-builds)")
    rc = _run(
        [sys.executable, "-m", "pip", "install", "frida", "frida-tools"],
        dry=ctx.dry_run,
    )
    if rc != 0:
        return Result(False, f"pip install exited {rc}")
    return Result(
        True,
        "frida + frida-tools installed",
        note="Local instrumentation works now. For Android/iOS, "
        "push frida-server-<ver>-<arch> to the target — see "
        "frida/README.md.",
    )


def deploy_frida(ctx: Context) -> Result:
    return Result(
        True,
        "no deploy step",
        note="MCP server uses frida-python directly — no bridge/plugin to copy.",
    )


# ---- Bluetooth LE ----


def build_bluetooth_le(ctx: Context) -> Result:
    if ctx.skip_builds:
        return Result(True, "(skipped per --skip-builds)")
    rc = _run([sys.executable, "-m", "pip", "install", "bleak"], dry=ctx.dry_run)
    if rc != 0:
        return Result(False, f"pip install bleak exited {rc}")
    return Result(
        True,
        "Bleak installed",
        note="The bluetooth_le provider uses the host Bluetooth adapter.",
    )


def deploy_bluetooth_le(ctx: Context) -> Result:
    del ctx
    return Result(
        True,
        "no deploy step",
        note="BLE scan/connect/capture runs through the unified Python provider.",
    )


# ---- Capstone ----


def build_capstone(ctx: Context) -> Result:
    if ctx.skip_builds:
        return Result(True, "(skipped per --skip-builds)")
    command = [sys.executable, "-m", "pip", "install"]
    if platform.system() == "Windows":
        # Windows ARM64 has no stable Capstone 5 wheel for Python 3.13. Avoid
        # an accidental native build that requires Visual Studio/nmake; pip
        # can select Capstone's compatible abi3 wheel instead.
        command.append("--only-binary=:all:")
    command.append("capstone")
    rc = _run(command, dry=ctx.dry_run)
    if rc != 0:
        return Result(False, f"pip install capstone exited {rc}")
    return Result(
        True,
        "Capstone installed",
        note="The capstone provider decodes raw bytes and file regions headlessly.",
    )


def deploy_capstone(ctx: Context) -> Result:
    del ctx
    return Result(
        True,
        "no deploy step",
        note="Capstone runs in-process through the unified Python provider.",
    )


# ---- Registry ----

TOOLS: list[Tool] = [
    Tool(
        "ida",
        "IDA Pro",
        "C/C++ via IDA plugin (8.x/9.x). Copies plugin.py into your IDA user "
        "plugins dir.",
        "ida/plugin.py",
        build_ida,
        deploy_ida,
    ),
    Tool(
        "ghidra",
        "Ghidra",
        "Ghidra ProgramPlugin extension. Builds and installs it in your "
        "Ghidra Extensions dir.",
        "ghidra/ghidra-mcp-bridge/build.gradle",
        build_ghidra,
        deploy_ghidra,
    ),
    Tool(
        "jadx",
        "jadx",
        "Decompile Android/Java. Builds the standalone Java bridge (one JVM per APK).",
        "jadx/jadx-mcp-bridge/build.gradle",
        build_jadx,
        deploy_jadx,
    ),
    Tool(
        "ilspy",
        "ILSpy",
        "Decompile .NET. Builds the standalone .NET 8 bridge "
        "(one process per assembly).",
        "ilspy/IlspyMcpBridge/IlspyMcpBridge.csproj",
        build_ilspy,
        deploy_ilspy,
    ),
    Tool(
        "frida",
        "Frida",
        "Dynamic instrumentation via frida-python; mobile targets also require "
        "frida-server.",
        "reversing_mcp/providers/frida.py",
        build_frida,
        deploy_frida,
    ),
    Tool(
        "ble",
        "Bluetooth LE",
        "Scan, connect, inspect GATT, exchange frames, and save transcripts.",
        "reversing_mcp/providers/bluetooth_le.py",
        build_bluetooth_le,
        deploy_bluetooth_le,
    ),
    Tool(
        "capstone",
        "Capstone",
        "Read-only raw-byte and file-region disassembly for ARM, x86, and "
        "other supported architectures.",
        "reversing_mcp/providers/capstone.py",
        build_capstone,
        deploy_capstone,
    ),
]


# ---------------------------------------------------------------------------
# MCP registration
# ---------------------------------------------------------------------------


def client_exists(client: str) -> bool:
    return shutil.which(client) is not None


def _registration_prefix(client: str, scope: str) -> tuple[list[str], Result | None]:
    if client not in {"claude", "codex"}:
        return [], Result(False, f"unsupported client: {client}")
    if not client_exists(client):
        return [], Result(
            False,
            f"`{client}` CLI not on PATH",
            note=f"Install {client} before registering its MCP configuration.",
        )
    if client == "codex" and scope != "user":
        return [], Result(
            False,
            "Codex CLI registration is user-global",
            note=(
                "Use --scope user, or configure a project-local Codex MCP "
                "entry manually."
            ),
        )
    if client == "claude":
        return ["claude", "mcp", "add", "-s", scope], None
    return ["codex", "mcp", "add"], None


def _remove_existing_mcp(client: str, name: str, scope: str, *, dry: bool) -> None:
    """Best-effort removal makes repeated installs deterministic."""
    command = [client, "mcp", "remove", name]
    if client == "claude":
        command.extend(("-s", scope))
    if dry:
        _run(command, dry=True)
        return
    subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def local_jadx_bridge() -> Path:
    return (
        REPO_ROOT
        / "jadx"
        / "jadx-mcp-bridge"
        / "build"
        / "libs"
        / "jadx-mcp-bridge.jar"
    )


def register_unified_mcp(client: str, ctx: Context) -> Result:
    prefix, error = _registration_prefix(client, ctx.scope)
    if error:
        return error
    _remove_existing_mcp(client, "reversing-mcp", ctx.scope, dry=ctx.dry_run)

    python_paths = [str(REPO_ROOT)]
    inherited_python_path = os.environ.get("PYTHONPATH", "")
    python_paths.extend(
        path
        for path in inherited_python_path.split(os.pathsep)
        if path and path not in python_paths
    )
    environment = {"PYTHONPATH": os.pathsep.join(python_paths)}
    jadx_bridge = local_jadx_bridge()
    if jadx_bridge.is_file():
        environment["JADX_MCP_BRIDGE_JAR"] = str(jadx_bridge)
    if ctx.allow_scripts:
        environment["REVERSING_MCP_ALLOW_SCRIPTS"] = "1"
    if ctx.script_providers:
        environment["REVERSING_MCP_SCRIPT_PROVIDERS"] = ctx.script_providers

    env_args: list[str] = []
    env_flag = "-e" if client == "claude" else "--env"
    for key, value in environment.items():
        env_args.extend((env_flag, f"{key}={value}"))
    # Claude's variadic ``-e`` belongs after the positional server name;
    # Codex requires each ``--env`` before it. Keep the client grammars
    # explicit instead of relying on a deceptively similar shared ordering.
    if client == "claude":
        cmd = [
            *prefix,
            "reversing-mcp",
            *env_args,
            "--",
            sys.executable,
            "-m",
            "reversing_mcp",
        ]
    else:
        cmd = [
            *prefix,
            *env_args,
            "reversing-mcp",
            "--",
            sys.executable,
            "-m",
            "reversing_mcp",
        ]
    rc = _run(cmd, dry=ctx.dry_run)
    if rc != 0:
        return Result(False, f"{client} mcp add exited {rc}")
    return Result(
        True,
        f"registered unified server with {client} ({ctx.scope} scope)",
    )


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------


def header() -> None:
    console.print()
    console.print(
        Panel.fit(
            Text.assemble(
                ("reversing-mcp", "bold cyan"),
                " installer\n",
                ("Pick which MCP servers to install. Re-runnable.", "dim"),
            ),
            border_style="cyan",
        )
    )
    console.print()


def pick_tools(available: list[Tool], preselect_all: bool) -> list[Tool]:
    choices = [
        questionary.Choice(
            title=f"{t.label.ljust(8)}  — {t.description}",
            value=t,
            checked=preselect_all or t.key in ("ida", "ghidra"),
        )
        for t in available
    ]
    picked = questionary.checkbox(
        "Which MCP servers do you want to install?",
        choices=choices,
        style=QSTYLE,
        instruction="(space to toggle, enter to confirm)",
    ).ask()
    return picked or []


def pick_scope() -> str:
    return (
        questionary.select(
            "Install scope:",
            choices=[
                questionary.Choice(
                    "user    — visible to every Claude Code session", value="user"
                ),
                questionary.Choice(
                    "project — only the current project's .claude/.mcp.json",
                    value="project",
                ),
            ],
            style=QSTYLE,
            default="user",
        ).ask()
        or "user"
    )


def render_step(tool: Tool, phase: str, res: Result) -> None:
    icon = "[green]✓[/]" if res.ok else "[red]✗[/]"
    line = f"  {icon} [bold]{tool.label}[/] {phase}: {res.summary}"
    console.print(line)
    if res.note:
        for ln in res.note.splitlines():
            console.print(f"      [dim italic]↳ {ln}[/]")


def run_install(tools: list[Tool], ctx: Context) -> int:
    failures = 0
    for tool in tools:
        console.print()
        console.print(f"[bold cyan]▸[/] [bold]{tool.label}[/]")

        b = tool.build(ctx)
        render_step(tool, "build", b)
        if not b.ok:
            failures += 1
            continue

        d = tool.deploy(ctx)
        render_step(tool, "deploy", d)
        if not d.ok:
            failures += 1
            continue

    console.print()
    console.print("[bold cyan]>[/] [bold]Unified server[/]")
    for client in ctx.clients:
        result = register_unified_mcp(client, ctx)
        icon = "[green]OK[/]" if result.ok else "[red]FAIL[/]"
        console.print(f"  {icon} [bold]{client}[/] register: {result.summary}")
        if result.note:
            console.print(f"      [dim italic]-> {result.note}[/]")
        if not result.ok:
            failures += 1

    console.print()
    if failures == 0:
        summary = (
            f"{len(tools)} provider(s) installed."
            if tools
            else "Unified server registration complete."
        )
        console.print(
            Panel.fit(
                f"[green]Done.[/] {summary} "
                "Run your client's MCP list command to verify.",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel.fit(
                f"[yellow]Finished with {failures} failure(s).[/] "
                f"Review the messages above; re-run after fixing.",
                border_style="yellow",
            )
        )
    return failures


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description="reversing-mcp installer")
    ap.add_argument(
        "--all",
        action="store_true",
        help="select every available tool (non-interactive)",
    )
    ap.add_argument(
        "--tools",
        type=str,
        default="",
        help="comma-separated tool keys to install (e.g. ida,ghidra)",
    )
    ap.add_argument(
        "--scope",
        choices=("user", "project"),
        default=None,
        help="install scope (default: ask)",
    )
    ap.add_argument(
        "--clients",
        default="claude",
        help="comma-separated MCP clients: claude,codex (default: claude)",
    )
    ap.add_argument(
        "--register-only",
        action="store_true",
        help="skip provider build/deploy and only register the server",
    )
    ap.add_argument(
        "--allow-scripts",
        action="store_true",
        help="opt the unified server into provider-native script execution",
    )
    ap.add_argument(
        "--script-providers",
        default="",
        help="comma-separated provider allowlist for --allow-scripts",
    )
    ap.add_argument(
        "--skip-builds",
        action="store_true",
        help=(
            "register the unified MCP server and copy plugins, but don't "
            "compile jadx/ilspy/ghidra"
        ),
    )
    ap.add_argument(
        "--from-source",
        action="store_true",
        help="skip prebuilt releases and always compile provider bridges",
    )
    ap.add_argument(
        "--release-tag",
        default="latest",
        help="release tag to use for prebuilt assets (default: latest)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would run without doing anything",
    )
    args = ap.parse_args()

    header()

    available = [t for t in TOOLS if t.present()]
    if not available:
        console.print(
            "[red]No tool subdirs found. Are you running from the repo root?[/]"
        )
        return 1

    missing = [t.label for t in TOOLS if not t.present()]
    if missing:
        console.print(
            f"[dim]Not on this branch:[/] {', '.join(missing)} "
            "[dim](check out a branch that includes them or skip)[/]\n"
        )

    if args.register_only:
        selected = []
    elif args.all:
        selected = available
    elif args.tools:
        keys = {k.strip() for k in args.tools.split(",") if k.strip()}
        selected = [t for t in available if t.key in keys]
        unknown = keys - {t.key for t in available}
        if unknown:
            console.print(f"[red]Unknown tool(s):[/] {', '.join(sorted(unknown))}")
            return 2
    else:
        selected = pick_tools(available, preselect_all=False)
        if not selected:
            console.print("[yellow]Nothing selected.[/] Bye.")
            return 0

    scope = args.scope or ("user" if args.register_only else pick_scope())

    clients = tuple(
        dict.fromkeys(item.strip() for item in args.clients.split(",") if item.strip())
    )
    unknown_clients = set(clients) - {"claude", "codex"}
    if not clients or unknown_clients:
        invalid = ", ".join(sorted(unknown_clients)) or "(empty)"
        console.print(f"[red]Unknown client(s):[/] {invalid}")
        return 2
    if args.script_providers and not args.allow_scripts:
        console.print("[red]--script-providers requires --allow-scripts.[/]")
        return 2

    ctx = Context(
        scope=scope,
        skip_builds=args.skip_builds,
        dry_run=args.dry_run,
        clients=clients,
        allow_scripts=args.allow_scripts,
        script_providers=args.script_providers,
        from_source=args.from_source,
        release_tag=args.release_tag,
    )
    return 0 if run_install(selected, ctx) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
