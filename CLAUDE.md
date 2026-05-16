# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

MCP servers that proxy Claude Code tool calls into running RE-tool bridges over HTTP. Five tools today: **IDA Pro**, **Ghidra**, **jadx** (Android/Java), **ILSpy** (.NET), and **Unicorn Engine** (emulator). Each side has two parts: a Python MCP stdio server (`<tool>/mcp_server.py`) and a bridge process that hosts the HTTP API.

## Architecture

```
Claude Code  ←stdio→  <tool>/mcp_server.py  ←HTTP→  bridge process
                              │
                        common.py (discovery + proxy)
```

Each bridge writes a JSON registration file to `~/.<tool>_mcp/<pid>.json` containing `{pid, port, <name_key>, <name_key>_path}` where `<name_key>` is `idb`/`program`/`jar`/`assembly` depending on the tool. `common.py:discover_instances` reads that directory, prunes entries whose PID is dead, and `resolve_instance` picks one — by substring match on the name keys when the user provides a target argument, otherwise the first live entry. `call_instance` then POSTs/GETs JSON to `http://127.0.0.1:<port><endpoint>`; on `ConnectError` it deletes the stale registration. All MCP tools route through this single helper.

The five MCP servers are deliberate mirrors of each other in shape — every tool is a thin `_call(endpoint, body, target=...)` wrapper. They differ mainly in:
- the target-name parameter (`idb`/`program`/`jar`/`assembly`/`arch`)
- the tool surface (IDA/Ghidra are binary-level; jadx/ILSpy are managed-language; Unicorn is a generic emulator)
- IDA-only extras: `make_code`, `find_micromips_prologues`

Each server `sys.path.insert(0, parent)` to import `common.py`.

### Three bridge shapes

The IDA/Ghidra bridges are **resident plugins** that auto-start when the user opens a binary inside the RE tool's GUI. The jadx/ILSpy bridges are **standalone processes** that the user launches separately, passing the target file on argv:

```
java -jar jadx-mcp-bridge.jar app.apk            # → ~/.jadx_mcp/<pid>.json
./ilspy-mcp-bridge lib.dll                       # → ~/.ilspy_mcp/<pid>.json
```

The Unicorn bridge is a **pure-Python in-process emulator** — a single Python script, no JVM or .NET runtime layer, no resident GUI to host it in. It's launched with `--arch <mode>` and that's the only target identifier; everything else (memory map, registers, hooks) is set at runtime via MCP calls:

```
python unicorn/bridge.py --arch thumb            # → ~/.unicorn_mcp/<pid>.json
```

Same registration contract, same wire format — the discovery layer doesn't know or care which shape produced the registration.

### Port ranges

Each tool reserves a 60-port slice to avoid collisions when multiple are running:

| Tool    | Range          |
|---------|----------------|
| IDA     | 13337–13400    |
| Ghidra  | 13437–13500    |
| jadx    | 13537–13600    |
| ILSpy   | 13637–13700    |
| Unicorn | 13737–13800    |

### IDA bridge threading model

`ida/plugin.py` runs `http.server.HTTPServer` in a background thread, but the IDA API is not thread-safe. Every handler dispatches through `_run_on_main_thread(func, ...)`, which enqueues the call and blocks on a `threading.Event` until a `ida_kernwin.register_timer` callback (`_MainThreadTimer._tick`, 100ms) drains the queue on the UI thread and signals the event. Do **not** call `execute_sync` here — the comment in `_run_on_main_thread` notes that path deadlocks. Any new endpoint must keep its IDA-API work inside the function passed through `_run_on_main_thread`.

### jadx Java bridge (standalone)

`jadx/jadx-mcp-bridge/` is a Gradle `application` + `shadow` project that produces a fat JAR. Source is split into `JadxMcpBridge` (entry point, HTTP routing, registration), `JadxService` (jadx-core wrapper — lazy decompilation per class, single-method extraction by brace-balanced slicing), and `Json` (hand-rolled writer + flat reader, no Jackson/Gson dependency). The same `Json` reader is shared by the Ghidra plugin's `parseJsonBody` (each implementation is its own copy — be conservative if you change the body wire format).

The single-method decompile (`JadxService.decompileMethod`) slices the class source at `JavaMethod.getDecompiledLine()` and brace-counts to the matching `}`. When the decompiled line is 0 (rare — happens for synthetic methods), it falls back to returning the whole class.

`search_strings` walks `getCode()` on every class — first invocation is slow (decompiles everything), subsequent calls hit jadx-core's internal cache.

### ILSpy .NET bridge (standalone)

`ilspy/IlspyMcpBridge/` is a single `Program.cs` .NET 8 console app depending on `ICSharpCode.Decompiler`. `IlspyService` wraps `CSharpDecompiler` + `PEFile` under a single `lock`. The `Router` uses `System.Net.HttpListener` + `System.Text.Json.Nodes` (no manual JSON, unlike the Java side).

`search_strings` decompiles every type and greps the C# source — same trade-off as jadx (slow first call, cached after). Walking the user-string `#US` heap directly via `MetadataReader` isn't a public API; the source-grep approach matches the jadx surface and is what users actually want anyway (line + snippet, not just raw token).

### Unicorn bridge (pure Python, in-process)

`unicorn/bridge.py` is the only bridge with no native runtime wrapper — it's a single Python file that imports the `unicorn` PyPI package directly. One `Uc` instance + hook table + snapshot dict all live behind one `threading.Lock` (Unicorn is not thread-safe, so every HTTP handler enters the lock before touching the emulator). The MCP wire format follows the same conventions as the other bridges: addresses as hex strings, memory as hex strings, registers as `{name, value}` with value as a hex string.

The bridge is deliberately **generic** — `--arch <thumb|arm|arm64|x86|x86_64|mips|mipsel|mips64|riscv32|riscv64>` is the only required flag. There's no `init_cortex_m`, `boot_firmware`, ELF auto-load, or vendor-MMIO model anywhere in the bridge. Use cases (e.g. MT7697 firmware bring-up) are compositions of `map_region` / `load_file` / `add_hook` / `write_reg` / `run_until`, documented as recipes in `cookbooks/` rather than bridge endpoints. The bridge should never grow target-specific code paths.

The `step` and `run_until` implementations pass a 32- or 64-bit "no end" sentinel to `Uc.emu_start` (rather than `0`) so that an instruction-count budget works correctly when `pc == 0`. The Thumb-bit marker is OR'd into the start address by the bridge automatically when `--arch thumb`; user-facing PC values are plain addresses.

### Ghidra bridge: two artifacts, one source

- `ghidra/ghidra-mcp-bridge/` — Gradle project that builds the **extension** (`GhidraMcpPlugin` as a `ProgramPlugin` that auto-starts on program open). This is the recommended install path. The plugin source under `src/main/java/ghidramcp/GhidraMcpPlugin.java` is the one the build consumes.
- `ghidra/GhidraMcpPlugin.java` — top-level copy of the plugin source, kept alongside `bridge.java` (the standalone GhidraScript fallback users can drop into `ghidra_scripts/`).

When changing Ghidra plugin behavior, update the source inside `ghidra-mcp-bridge/src/main/java/ghidramcp/` (the one that actually builds) and keep the top-level `GhidraMcpPlugin.java` / `bridge.java` in sync if you want the script fallback to match.

## Adding or changing a tool

A tool change is a **two-file edit**: the bridge endpoint and the `mcp_server.py` wrapper. The MCP wrapper is purely declarative — it builds a body dict and calls `_call(endpoint, body, target=...)`. The behavior lives in the bridge's request dispatcher (`_dispatch` in IDA, `handle*` methods in Ghidra, `Router.route` in jadx/ILSpy).

For IDA/Ghidra: address arguments are passed as hex strings end-to-end and parsed in the bridge (`_parse_addr` on the IDA side). Both `address` and `name` are accepted on most endpoints; the bridge resolves `name` to an address before falling through to the same code path.

For jadx/ILSpy: identifiers are class/type full names and method names. The Python wrapper takes `class_name`/`type_name` and the bridge resolves substrings; both also accept exact short_id / full signature for overload disambiguation.

## Common commands

```bash
# Install Python deps for MCP servers
pip install mcp httpx

# List active instances (sanity check that bridges are running)
python3 ida/mcp_server.py     --list
python3 ghidra/mcp_server.py  --list
python3 jadx/mcp_server.py    --list
python3 ilspy/mcp_server.py   --list
python3 unicorn/mcp_server.py --list

# Tests (no IDA/Ghidra/jadx/ILSpy required — uses an in-process fake bridge)
pip install pytest
python -m pytest tests/

# Build the Ghidra extension ZIP
cd ghidra/ghidra-mcp-bridge
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew
# Output: ghidra/ghidra-mcp-bridge/dist/*.zip

# Build the jadx fat JAR (JDK 17+)
cd jadx/jadx-mcp-bridge
gradle shadowJar
# Output: build/libs/jadx-mcp-bridge.jar
# Run: java -jar build/libs/jadx-mcp-bridge.jar path/to/app.apk

# Build + run the ILSpy bridge (.NET 8 SDK)
cd ilspy/IlspyMcpBridge
dotnet run -- path/to/lib.dll

# Launch a Unicorn bridge (no build step — pure Python)
pip install unicorn
python unicorn/bridge.py --arch thumb
```

## Tests

`tests/` is a pytest suite. The `FakeBridge` fixture in `tests/conftest.py` stands up a loopback `HTTPServer` and writes a registration file pointing at it, so MCP servers can be exercised end-to-end without spinning up any real RE tool. `test_common.py` covers discovery (live/dead PID, corrupt JSON, substring resolve across multiple name keys) and the proxy (HTTP body, ConnectError → registration cleanup). The per-server tests (`test_jadx_server.py`, `test_ilspy_server.py`, `test_unicorn_server.py`) verify each MCP tool builds the right request body — they load each `mcp_server.py` by explicit file path (all share the bare module name `mcp_server` so sys.path imports collide).

## WIP branches

The `unicorn/`, `saleae_native/`, `cookbooks/`, and `tests/test_unicorn_server.py` paths
described above live on branches and have NOT merged to `main` yet:

- `unicorn` — Unicorn Engine MCP server (functional, 17 passing tests, smoke-tested). Holds:
  `unicorn/bridge.py`, `unicorn/mcp_server.py`, `unicorn/SMOKE.md`, `cookbooks/mt7697-bringup.md`,
  `tests/test_unicorn_server.py`.
- `saleae` — `saleae_native/` skeleton + IDA-driven RE notes for the Saleae Logic Pro 16.
  Driver/bridge/server stubs; protocol decode still pending. See
  `saleae_native/notes/session_2026-05-15_ida_pass.md` for the carry-forward state.

Until those branches merge, references to Unicorn or `saleae_native` in this doc describe
intent, not what's on `main`.
