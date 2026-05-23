#!/usr/bin/env python3
"""
reversing-mcp interactive installer.

Walks the user through:
  1. Picking which MCP servers to install (multi-select).
  2. Picking install scope (user-global vs. this project only).
  3. Running per-tool build + install actions:
       - ida    → copy plugin.py to the IDA user plugins dir
       - ghidra → build the extension (if GHIDRA_INSTALL_DIR is set) and place
                  the ZIP in the user Extensions dir for in-Ghidra activation
       - jadx   → gradle shadowJar (needs JDK 17+)
       - ilspy  → dotnet publish -c Release (needs .NET 8 SDK)
       - unicorn→ pip install unicorn capstone
  4. Registering each picked server with `claude mcp add`.

Non-interactive mode for CI:
    python install.py --all --scope user --skip-builds

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
from typing import Callable, Iterable


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
from rich.table import Table  # noqa: E402
from rich.text import Text  # noqa: E402


REPO_ROOT = Path(__file__).resolve().parent
console = Console()

QSTYLE = Style([
    ("question", "bold fg:#5fafd7"),
    ("answer", "fg:#87d787 bold"),
    ("pointer", "fg:#ff8700 bold"),
    ("highlighted", "fg:#ffd75f bold"),
    ("selected", "fg:#87d787"),
    ("instruction", "fg:#808080 italic"),
])


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

@dataclass
class Tool:
    key: str
    label: str
    description: str
    mcp_server_rel: str            # path to mcp_server.py from repo root
    build: Callable[["Context"], "Result"]
    deploy: Callable[["Context"], "Result"]
    requires_branch: str | None = None  # advisory, e.g. "unicorn"

    @property
    def mcp_server_path(self) -> Path:
        return REPO_ROOT / self.mcp_server_rel

    def present(self) -> bool:
        return self.mcp_server_path.is_file()


@dataclass
class Context:
    scope: str       # "user" | "project"
    skip_builds: bool
    dry_run: bool
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
            (p for p in base.iterdir() if p.is_dir() and p.name.startswith(".ghidra_")),
            key=lambda p: p.stat().st_mtime, reverse=True,
        )
        if versioned:
            return versioned[0] / "Extensions"
    return None


# ---------------------------------------------------------------------------
# Per-tool: build + deploy
# ---------------------------------------------------------------------------

def _run(cmd: list[str], cwd: Path | None = None, dry: bool = False) -> int:
    if dry:
        console.print(f"  [dim]would run:[/] [cyan]{' '.join(cmd)}[/]"
                      + (f" [dim]in {cwd}[/]" if cwd else ""))
        return 0
    console.print(f"  [dim]$[/] [cyan]{' '.join(cmd)}[/]")
    return subprocess.call(cmd, cwd=str(cwd) if cwd else None)


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
        req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
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


def _pick_asset(assets: list[tuple[str, str]], substr: str, suffix: str) -> tuple[str, str] | None:
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
    return Result(True, f"copied to {dst}",
                  note="Plugin auto-starts on next IDA launch (Ctrl+Shift+M toggles).")


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
                return Result(True, f"downloaded {name}",
                              note="No Ghidra install or JDK needed for this path.")
            console.print("  [yellow]falling back to source build[/]")

    # Source build needs Ghidra to compile against.
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if not ghidra_dir:
        return Result(
            False, "GHIDRA_INSTALL_DIR not set",
            note="Either point GHIDRA_INSTALL_DIR at your Ghidra install root "
                 "(e.g. C:\\ghidra_11.0.1_PUBLIC) for a source build, OR omit "
                 "--from-source so the installer downloads the prebuilt release "
                 "asset (none was found just now — first release pending?).",
        )
    gradlew = bridge_dir / ("gradlew.bat" if platform.system() == "Windows" else "gradlew")
    cmd = [str(gradlew), "--no-daemon"] if gradlew.exists() else ["gradle"]
    rc = _run(cmd, cwd=bridge_dir, dry=ctx.dry_run)
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
        return Result(False, "could not locate Ghidra user dir (no .ghidra_* found)",
                      note="Install Ghidra and run it once to create the user dir, "
                           "or copy the ZIP from dist/ manually.")
    if ctx.dry_run:
        console.print(f"  [dim]would copy:[/] {zips[-1]} → {target_dir}")
        return Result(True, f"(dry-run) → {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(zips[-1], target_dir)
    return Result(True, f"copied {zips[-1].name} to {target_dir}",
                  note="In Ghidra: File → Install Extensions → check the box, restart.")


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
        pick = _pick_asset(assets, "jadx-mcp-bridge", "-all.jar")
        if pick:
            name, url = pick
            dst = bridge_dir / "build" / "libs" / name
            console.print(f"  [dim]prebuilt:[/] {name} from {ctx.release_tag}")
            if _download(url, dst, dry=ctx.dry_run):
                return Result(True, f"downloaded {name}",
                              note="No JDK needed for this path.")
            console.print("  [yellow]falling back to source build[/]")

    # Source build via wrapper (preferred) or system gradle.
    gradlew = bridge_dir / ("gradlew.bat" if platform.system() == "Windows" else "gradlew")
    if gradlew.exists():
        cmd = [str(gradlew), "--no-daemon", "shadowJar"]
    elif shutil.which("gradle") is not None:
        cmd = ["gradle", "shadowJar"]
    else:
        return Result(False, "no gradle wrapper and no system gradle",
                      note="Update from upstream (vendored wrapper) or install gradle.")
    rc = _run(cmd, cwd=bridge_dir, dry=ctx.dry_run)
    if rc != 0:
        return Result(False, f"gradle shadowJar exited {rc}")
    return Result(True, "fat JAR built at jadx/jadx-mcp-bridge/build/libs/jadx-mcp-bridge.jar")


def deploy_jadx(ctx: Context) -> Result:
    return Result(True, "no deploy step",
                  note="Launch one bridge per APK: `java -jar jadx/jadx-mcp-bridge/build/libs/jadx-mcp-bridge.jar <apk>`")


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
                return Result(True, f"unpacked {name} → {publish}",
                              note="No .NET SDK needed for this path. "
                                   "Launch with `dotnet <publish>/IlspyMcpBridge.dll <asm>`.")
            console.print("  [yellow]falling back to source build[/]")

    if shutil.which("dotnet") is None:
        return Result(False, "dotnet not on PATH",
                      note="Install the .NET 8 SDK from https://dotnet.microsoft.com/download")
    rc = _run(["dotnet", "publish", "-c", "Release", "--nologo", "-v", "quiet"],
              cwd=proj_dir, dry=ctx.dry_run)
    if rc != 0:
        return Result(False, f"dotnet publish exited {rc}")
    return Result(True, "binary built at ilspy/IlspyMcpBridge/bin/Release/net8.0/publish/")


def deploy_ilspy(ctx: Context) -> Result:
    return Result(True, "no deploy step",
                  note="Launch one bridge per assembly: `ilspy-mcp-bridge <path.dll>`")


# ---- Unicorn ----

def build_unicorn(ctx: Context) -> Result:
    if ctx.skip_builds:
        return Result(True, "(skipped per --skip-builds)")
    rc = _run([sys.executable, "-m", "pip", "install", "unicorn", "capstone"],
              dry=ctx.dry_run)
    if rc != 0:
        return Result(False, f"pip install exited {rc}")
    return Result(True, "unicorn + capstone installed")


def deploy_unicorn(ctx: Context) -> Result:
    return Result(True, "no deploy step",
                  note="Launch: `python unicorn/bridge.py --arch thumb`")


# ---- Registry ----

TOOLS: list[Tool] = [
    Tool("ida",     "IDA Pro",
         "C/C++ via IDA plugin (8.x/9.x). Copies plugin.py into your IDA user plugins dir.",
         "ida/mcp_server.py",     build_ida,     deploy_ida),
    Tool("ghidra",  "Ghidra",
         "Ghidra ProgramPlugin extension. Builds the ZIP and places it in your Ghidra Extensions dir.",
         "ghidra/mcp_server.py",  build_ghidra,  deploy_ghidra),
    Tool("jadx",    "jadx",
         "Decompile Android/Java. Builds the standalone Java bridge (one JVM per APK).",
         "jadx/mcp_server.py",    build_jadx,    deploy_jadx),
    Tool("ilspy",   "ILSpy",
         "Decompile .NET. Builds the standalone .NET 8 bridge (one process per assembly).",
         "ilspy/mcp_server.py",   build_ilspy,   deploy_ilspy),
    Tool("unicorn", "Unicorn",
         "Pure-Python emulator MCP. WIP — lives on the `unicorn` branch.",
         "unicorn/mcp_server.py", build_unicorn, deploy_unicorn,
         requires_branch="unicorn"),
]


# ---------------------------------------------------------------------------
# MCP registration via `claude mcp add`
# ---------------------------------------------------------------------------

def claude_mcp_exists() -> bool:
    return shutil.which("claude") is not None


def register_mcp(tool: Tool, scope: str, dry: bool) -> Result:
    if not claude_mcp_exists():
        return Result(False, "`claude` CLI not on PATH",
                      note="Install Claude Code CLI: https://docs.claude.com/claude-code")
    cmd = ["claude", "mcp", "add", "-s", scope, tool.key, "--",
           sys.executable, str(tool.mcp_server_path)]
    rc = _run(cmd, dry=dry)
    if rc != 0:
        return Result(False, f"claude mcp add exited {rc}")
    return Result(True, f"registered ({scope} scope)")


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

def header() -> None:
    console.print()
    console.print(Panel.fit(
        Text.assemble(
            ("reversing-mcp", "bold cyan"), " installer\n",
            ("Pick which MCP servers to install. Re-runnable.", "dim"),
        ),
        border_style="cyan",
    ))
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
        choices=choices, style=QSTYLE,
        instruction="(space to toggle, enter to confirm)",
    ).ask()
    return picked or []


def pick_scope() -> str:
    return questionary.select(
        "Install scope:",
        choices=[
            questionary.Choice("user    — visible to every Claude Code session", value="user"),
            questionary.Choice("project — only the current project's .claude/.mcp.json", value="project"),
        ],
        style=QSTYLE,
        default="user",
    ).ask() or "user"


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

        r = register_mcp(tool, ctx.scope, ctx.dry_run)
        render_step(tool, "register", r)
        if not r.ok:
            failures += 1

    console.print()
    if failures == 0:
        console.print(Panel.fit(
            f"[green]Done.[/] {len(tools)} server(s) installed. "
            f"Run [cyan]claude mcp list[/] to verify.",
            border_style="green",
        ))
    else:
        console.print(Panel.fit(
            f"[yellow]Finished with {failures} failure(s).[/] "
            f"Review the messages above; re-run after fixing.",
            border_style="yellow",
        ))
    return failures


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="reversing-mcp installer")
    ap.add_argument("--all", action="store_true", help="select every available tool (non-interactive)")
    ap.add_argument("--tools", type=str, default="",
                    help="comma-separated tool keys to install (e.g. ida,ghidra)")
    ap.add_argument("--scope", choices=("user", "project"), default=None,
                    help="install scope (default: ask)")
    ap.add_argument("--skip-builds", action="store_true",
                    help="register MCP servers and copy plugins, but don't compile jadx/ilspy/ghidra")
    ap.add_argument("--from-source", action="store_true",
                    help="skip the prebuilt-release fast path; always compile from source "
                         "(default: try prebuilt first, fall back to source on failure)")
    ap.add_argument("--release-tag", default="latest",
                    help="which release to pull prebuilt assets from (default: latest)")
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would run without doing anything")
    args = ap.parse_args()

    header()

    available = [t for t in TOOLS if t.present()]
    if not available:
        console.print("[red]No tool subdirs found. Are you running from the repo root?[/]")
        return 1

    missing = [t.label for t in TOOLS if not t.present()]
    if missing:
        console.print(
            f"[dim]Not on this branch:[/] {', '.join(missing)} "
            "[dim](check out a branch that includes them or skip)[/]\n"
        )

    if args.all:
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

    scope = args.scope or pick_scope()

    ctx = Context(
        scope=scope,
        skip_builds=args.skip_builds,
        dry_run=args.dry_run,
        from_source=args.from_source,
        release_tag=args.release_tag,
    )
    return 0 if run_install(selected, ctx) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
