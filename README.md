# reversing-mcp

MCP servers that give Claude Code direct access to IDA Pro, Ghidra, jadx (Android/Java), ILSpy (.NET), and Unicorn Engine (emulator). Disassemble, decompile, rename, comment, search, navigate, and emulate without leaving your terminal.

## Install

### Fast path — interactive installer (recommended)

```bash
git clone https://github.com/ril3y/reversing-mcp.git
cd reversing-mcp
python install.py
```

Walks you through a colored checkbox menu of which servers to install, picks
`user` vs. `project` scope, and **runs all the build + deploy + register
steps for you**.

By default, the installer **pulls prebuilt bridge artifacts from the latest
GitHub release** so you don't need a JDK / .NET SDK / Ghidra install just to
get going:

| Tool   | Default path (no toolchain needed) | Fallback if download fails |
|--------|-------------------------------------|----------------------------|
| IDA    | Copies `ida/plugin.py` into your IDA user plugins dir | n/a — no build step |
| Ghidra | Downloads `ghidra-mcp-bridge.zip` from latest release → `~/.ghidra/.ghidra_<ver>/Extensions/` | `gradle build` against your `GHIDRA_INSTALL_DIR` (needs JDK 21) |
| jadx   | Downloads `jadx-mcp-bridge-all.jar` from latest release | `./gradlew shadowJar` (needs JDK 17+) |
| ILSpy  | Downloads `ilspy-mcp-bridge.zip` and unpacks it | `dotnet publish -c Release` (needs .NET 8 SDK) |
| Unicorn| `pip install unicorn capstone`     | n/a — pip is the build |

…then `claude mcp add` for each picked tool. Self-installs its own deps
(`rich`, `questionary`) on first run, so the *only* prerequisite is a working
`python` + `git` + `claude` CLI.

Non-interactive / CI usage:

```bash
python install.py --all --scope user                  # everything available on this branch
python install.py --tools ida,ghidra --scope user     # just two
python install.py --tools ida --skip-builds           # skip the bridge build step entirely
python install.py --tools ida --dry-run               # print what would happen, change nothing
python install.py --tools ghidra --from-source        # force source build, skip prebuilt
python install.py --tools ghidra --release-tag v0.5.0 # pin to a specific release
```

> Prebuilt artifacts are published by `.github/workflows/release.yml` on every
> `v*` tag — see the [Releases page](https://github.com/ril3y/reversing-mcp/releases).
> Source builds remain the source of truth and are always exercised in CI on
> every PR.

### Manual install (if you don't want to run the installer)

#### 1. Clone + Python deps

```bash
git clone https://github.com/ril3y/reversing-mcp.git
cd reversing-mcp
pip install mcp httpx
```

#### 2. Register the MCP servers with Claude Code

Pick the line that matches your shell. **Both lines use the four stable servers
on `main`** — `unicorn` and `saleae_native` live on WIP branches (see
[WIP branches](#wip-branches) below) and are not registered by default.

**Linux / macOS / Git Bash** (run from the repo root):

```bash
REPO=$(pwd)
for tool in ida ghidra jadx ilspy; do
  claude mcp add -s user "$tool" -- python "$REPO/$tool/mcp_server.py"
done
```

**Windows PowerShell** (run from the repo root):

```powershell
$repo = (Get-Location).Path
foreach ($tool in 'ida','ghidra','jadx','ilspy') {
  claude mcp add -s user $tool -- python "$repo/$tool/mcp_server.py"
}
```

> On Windows the launcher is `python` (not `python3`). If `python --version`
> shows the wrong interpreter, substitute an absolute path like
> `C:\Python312\python.exe`.

Or — if you'd rather edit your config directly — add this to `~/.claude.json`
(or `~/.claude/.mcp.json`) under `"mcpServers"`, with `/path/to/reversing-mcp`
replaced by your absolute clone path:

```json
{
  "ida":    { "command": "python", "args": ["/path/to/reversing-mcp/ida/mcp_server.py"] },
  "ghidra": { "command": "python", "args": ["/path/to/reversing-mcp/ghidra/mcp_server.py"] },
  "jadx":   { "command": "python", "args": ["/path/to/reversing-mcp/jadx/mcp_server.py"] },
  "ilspy":  { "command": "python", "args": ["/path/to/reversing-mcp/ilspy/mcp_server.py"] }
}
```

#### 3. Verify

```bash
claude mcp list
```

You should see all four marked `✓ Connected`. If a server isn't connecting,
launch its `mcp_server.py` manually — any traceback (missing `mcp` or `httpx`
packages, wrong Python, etc.) will print to stderr.

> The MCP server connecting only means the **stdio glue is alive** — it does
> *not* mean a bridge is running inside IDA/Ghidra/jadx/ILSpy. Open one of
> those tools (with the bridge installed per step 4) before you make calls,
> or each tool will return `"No <Tool> instances found."`.

#### 4. Install the in-tool bridge

You need a bridge running inside each RE tool so the MCP server can talk to it.
Install only the bridges for the tools you actually use.

#### Ghidra (Extension — recommended)

The extension auto-starts the bridge when you open a program. No manual script launching needed.

**Easiest path — download the prebuilt ZIP** from the latest
[release](https://github.com/ril3y/reversing-mcp/releases). Drop it in
`~/.ghidra/.ghidra_<version>/Extensions/` (Windows: `%APPDATA%\ghidra\.ghidra_<version>\Extensions\`).

**Or build from source** (requires JDK 21 + an unpacked Ghidra install):

```bash
cd ghidra/ghidra-mcp-bridge
export GHIDRA_INSTALL_DIR=/path/to/ghidra    # Windows: $env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra"
./gradlew                                    # Windows: .\gradlew.bat
```

(The `gradlew` wrapper is vendored — you don't need a system `gradle` install.)

Then in Ghidra: **File > Install Extensions > +**, pick the ZIP from
`ghidra/ghidra-mcp-bridge/dist/`, restart Ghidra, and open a program.
`mcp__ghidra__list_instances` should now show it.

#### Ghidra (Script — alternative)

If you prefer not to install an extension, copy `ghidra/bridge.java` to your `ghidra_scripts/` directory and run it from the Script Manager. The script blocks with a dialog — click "No" to stop the server.

#### IDA Pro

Drop `ida/plugin.py` into your IDA user plugins directory and restart IDA — the
plugin auto-starts when an IDB loads and binds `Ctrl+Shift+M` to toggle it.

**Linux / macOS**:
```bash
ln -sf "$(pwd)/ida/plugin.py" ~/.idapro/plugins/ida_mcp_plugin.py
```

**Windows PowerShell**:
```powershell
$plugins = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
New-Item -ItemType Directory -Force $plugins | Out-Null
Copy-Item ida\plugin.py "$plugins\ida_mcp_plugin.py"
```

The Output window will print `[MCP] Server started on http://127.0.0.1:13337`
when the bridge is up. Verify from a shell with `python ida/mcp_server.py --list`.

#### jadx (standalone Java bridge)

Unlike Ghidra/IDA, jadx has no resident GUI to host the bridge — it's a separate JVM process per APK/JAR. Either grab the prebuilt fat JAR from the latest [release](https://github.com/ril3y/reversing-mcp/releases) or build it once:

```bash
cd jadx/jadx-mcp-bridge
./gradlew shadowJar                        # Windows: .\gradlew.bat shadowJar  (JDK 17+ required)
java -jar build/libs/jadx-mcp-bridge-all.jar /path/to/app.apk
```

The bridge writes `~/.jadx_mcp/<pid>.json` and the MCP server picks it up. Run multiple bridges for multiple APKs; target one from Claude with `jar="app.apk"`.

#### ILSpy (standalone .NET bridge)

Same shape — a console process per loaded assembly:

```bash
cd ilspy/IlspyMcpBridge
dotnet publish -c Release                  # .NET 8 SDK required
./bin/Release/net8.0/publish/ilspy-mcp-bridge /path/to/lib.dll
```

The bridge writes `~/.ilspy_mcp/<pid>.json`. Target with `assembly="lib.dll"` when multiple are running.

#### Unicorn emulator (pure Python bridge)

Unicorn is different from the others — there's no separate RE tool to host the bridge inside. The bridge is just a Python script; `pip install` it and run one process per emulation session, picking the CPU mode on argv:

```bash
pip install unicorn                                  # capstone is pulled in too if not already
python unicorn/bridge.py --arch thumb                # picks a free port in 13737-13800
python unicorn/bridge.py --arch x86_64 --port 13745  # explicit port
```

The bridge writes `~/.unicorn_mcp/<pid>.json` with `{pid, port, arch}`. Target with `arch="thumb"` when multiple are running. The bridge is deliberately generic — `--arch` is the only required flag; memory map, register state, hooks, and snapshots are all configured at runtime through MCP calls (see `cookbooks/mt7697-bringup.md` for a worked example).

Supported archs: `thumb`, `arm`, `arm64`, `x86`, `x86_64`, `mips`, `mipsel`, `mips64`, `riscv32`, `riscv64`.

### Use it

Open a binary in Ghidra or IDA, then ask Claude Code to analyze it:

```
> decompile the function at 0x80001000
> what does main() do?
> find all callers of send_packet
> rename 0x80004500 to parse_header
```

## Architecture

```
Claude Code  ←stdio→  mcp_server.py  ←HTTP→  bridge process
                           │
                      common.py (shared discovery)
```

Each bridge runs an HTTP server and registers itself in `~/.<tool>_mcp/<pid>.json` with `{pid, port, <target>, <target_path>}`. The MCP servers discover running instances automatically. Multiple instances are supported — use the `program`/`idb`/`jar`/`assembly` parameter to target a specific one by substring match.

Bridges come in two shapes:
- **Resident plugin** (IDA, Ghidra) — runs inside the tool's GUI; auto-starts when a binary is loaded.
- **Standalone process** (jadx, ILSpy) — a separate JVM/.NET process launched with the target file as an argument. Decouples MCP access from a heavy GUI.

```
reversing-mcp/
├── common.py                       Shared instance discovery + HTTP proxy
├── ghidra/
│   ├── bridge.java                 GhidraScript bridge (runs inside Ghidra)
│   ├── GhidraMcpPlugin.java        ProgramPlugin bridge (auto-starts)
│   ├── ghidra-mcp-bridge/          Ghidra extension (Gradle project)
│   └── mcp_server.py
├── ida/
│   ├── plugin.py                   IDA plugin (runs inside IDA)
│   └── mcp_server.py
├── jadx/
│   ├── jadx-mcp-bridge/            Standalone jadx-core Java app (Gradle)
│   └── mcp_server.py
├── ilspy/
│   ├── IlspyMcpBridge/             Standalone ICSharpCode.Decompiler .NET app
│   └── mcp_server.py
├── unicorn/
│   ├── bridge.py                   Pure-Python in-process Unicorn HTTP bridge
│   ├── mcp_server.py
│   └── SMOKE.md                    Live smoke test transcript
├── cookbooks/                      Worked examples of bridge primitives
└── tests/                          pytest suite for common.py + MCP servers
```

## Available Tools

The IDA and Ghidra servers expose the same binary-level tools:

| Tool | Description |
|------|-------------|
| `list_instances` | List active tool instances and loaded binaries |
| `idb_info` | Program info (function count, segments, processor, bitness) |
| `get_function` | Get function by address or name |
| `disassemble` | Disassemble a function or address range |
| `decompile` | Decompile to C pseudocode (Ghidra decompiler / Hex-Rays) |
| `xrefs_to` / `xrefs_from` | Cross-references |
| `get_callers` / `get_callees` | Call graph |
| `search_functions` / `search_strings` | Substring search |
| `get_segments` / `get_bytes` | Memory layout / raw bytes |
| `rename` / `add_comment` | Mutate the database |
| `create_function` / `delete_function` | Function management |

IDA additionally has `make_code` and `find_micromips_prologues`.

The jadx and ILSpy servers expose a higher-level managed-language surface:

| jadx | ILSpy | Description |
|------|-------|-------------|
| `info` | `info` | Loaded archive/assembly info |
| `list_classes` | `list_types` | Enumerate (with optional prefix) |
| `search_classes` | `search_types` | Substring search |
| `get_class` | — | Class metadata + method list |
| `decompile_class` | `decompile_type` | Full Java / C# source |
| `list_methods` | `list_methods` | Methods of a class/type |
| `decompile_method` | `decompile_method` | Single-method source |
| — | `get_il` | Raw IL for a method |
| `search_strings` | `search_strings` | Source-level string grep with line/snippet |
| `xrefs_to` | — | Usages of a class or method |
| — | `list_assemblies` | Referenced assemblies |

The Unicorn server exposes a generic emulator surface — there's no "program loaded", just an arch and whatever memory map you build at runtime:

| Tool | Description |
|------|-------------|
| `info` | Bridge state: arch, mapped regions, PC, hook/snapshot counts |
| `list_regions` / `map_region` / `unmap_region` | Memory map management |
| `load_bytes` / `load_file` | Write hex blob or host file into a mapped region |
| `read_mem` / `write_mem` | Raw memory I/O (hex strings) |
| `read_reg` / `write_reg` | CPU register access (arch-specific names: `pc`, `r0`, `rax`, `x0`, ...) |
| `disasm` | Disassemble bytes at an address (uses capstone) |
| `step` / `run_until` | Execute N instructions / run until PC / instruction budget / timeout |
| `add_hook` / `remove_hook` / `list_hooks` | Install `mem_read+stub`, `mem_read+trace`, `mem_write+trace`, `code+stub`, `code+break`, `block+trace` hooks |
| `snapshot` / `restore` / `list_snapshots` | Capture and roll back register state + region contents |

## Multi-Instance Support

If you have multiple binaries open (e.g., two Ghidra windows), pass the program name to target a specific one:

```
> decompile main in firmware.bin
> list all ghidra instances
```

The MCP server resolves instances by substring match on the program/IDB name.

## Troubleshooting

**"No Ghidra/IDA instances found"** — The bridge isn't running. For Ghidra, make sure the extension is installed and a program is open. For IDA, check the plugin loaded (Output window should show the MCP port).

**Check active instances manually:**

```bash
python3 ghidra/mcp_server.py  --list
python3 ida/mcp_server.py     --list
python3 jadx/mcp_server.py    --list
python3 ilspy/mcp_server.py   --list
python3 unicorn/mcp_server.py --list
```

**Registration files are stale** — If a bridge crashed, stale files in `~/.<tool>_mcp/` get auto-cleaned on next discovery (dead PIDs are pruned, and refused-connection registrations are unlinked).

## Running the tests

```bash
pip install pytest
python -m pytest tests/
```

The suite covers `common.py` discovery/proxy logic plus the jadx, ILSpy, and Unicorn MCP servers against an in-process HTTP bridge. No IDA / Ghidra / jadx / ILSpy / Unicorn installation is needed to run the tests (the bridge layer is mocked).

## Adding a New Tool

1. Create `toolname/` directory
2. Write the in-tool bridge (starts HTTP server, registers in `~/.toolname_mcp/`)
3. Write `mcp_server.py` using `common.py` for discovery
4. `claude mcp add toolname -- python3 /path/to/reversing-mcp/toolname/mcp_server.py`

## WIP branches

The references above to **Unicorn** (`unicorn/`) and **saleae_native** (`saleae_native/`)
describe code that lives on branches and has not yet merged to `main`:

| Branch | Status | Contents |
|--------|--------|----------|
| `unicorn` | Functional, pending stabilization | `unicorn/` bridge + server, `tests/test_unicorn_server.py`, `cookbooks/mt7697-bringup.md` |
| `saleae` | RE-in-progress skeleton | `saleae_native/` (driver/bridge/server stubs + IDA-driven RE notes) |

Check those out separately (`git checkout unicorn`, `git checkout saleae`) to use them
while they bake.
