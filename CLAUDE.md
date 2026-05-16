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

## Workflow guidance — read this before driving the IDA bridge

### Bank discoveries to the IDB as you find them

The point of the rename / add_comment / define_type / apply_type / set_function_prototype / rename_local_var / set_local_var_type endpoints is that **annotations compound**: every re-decompile after a rename shows the renamed identifier in the pseudocode, every re-decompile after `set_function_prototype` shows the named parameters, every type applied to a struct field gets `self->named_field` in place of `*((_QWORD *)self + 5)`. **A 5-minute investment up front saves dozens of squints on later questions about the same code.**

If during analysis you discover **any** of these, persist it *before* moving on:

| Discovery | Endpoint |
|---|---|
| Function name from assertion / RTTI / vtable / xref pattern | `rename` |
| Calling convention or parameter purposes | `set_function_prototype` |
| Struct / class layout (even partial — pad the unknowns) | `define_type` + `apply_type` |
| State change / non-obvious behavior / DRM observation at an address | `add_comment` (use `repeatable=true` so the comment shows at all xrefs) |
| Hex-Rays local-variable purpose | `rename_local_var` (+ `set_local_var_type` if you also know the type) |
| Whole memory region's meaning (e.g. MMIO range, runtime-allocated VM area) | `add_segment` + `set_segment_attrs` |
| Cross-cutting insight / hypothesis / discovery not anchored to one address | `scratch_log(category, content)` — appends a timestamped markdown section to a persistent per-IDB lab notebook |

The `scratch_*` endpoints (`scratch_read` / `scratch_log` / `scratch_append` / `scratch_replace` / `scratch_clear`) store free-form markdown in a netnode inside the IDB. The notebook auto-saves with the IDB and accumulates across sessions, so a future Claude session in the same IDB can `scratch_read` and immediately know what previous sessions discovered. Use `scratch_log` for the common case of "remember this for next time"; categories like `Discovery`, `Hypothesis`, `Open question`, `Dynamic capture` help future search.

**Start every fresh session in an IDB with `scratch_read`** — that's how prior context gets handed forward.

### Debugger safety — mutations are blocked while attached

Mutating the IDA type library / function index / segment table **while the debugger is paused at a breakpoint** can crash IDA. Observed 2026-05-16 during a Saleae live-test — `ida64.exe` died mid-session, lost several captured payloads. The plugin guards against this: any `_MUTATING` endpoint called while `dbg_state() in ("paused", "running")` returns a refusal error. Workflow:

1. Capture register state + memory bytes *while paused* (those endpoints are safe).
2. `dbg_detach()`.
3. Apply renames / comments / types.
4. Re-attach if you still need to keep debugging.

Don't try to skip step 2. The guard refuses for a reason.

### Debugger silencing — auto-runs on `dbg_attach` / `dbg_launch`

Commercial protections (iLok / VMProtect / SmartHeap / custom firmware checks) often **raise structured exceptions as part of normal control flow** AND/OR install dialogs that block IDA's main thread. Without silencing, every exception traps IDA in a loop at the same PC, and modal dialogs wedge every queued MCP request.

`_silence_debugger()` runs automatically inside `dbg_attach` / `dbg_launch`. It:

- Sets `DOPT_EXCDLG` to `EXCDLG_NEVER` — no modal "Exception happened" popup.
- Iterates every known exception via `ida_dbg.get_exception_count()` + `get_exception_info(i)` + `set_exception_info(...)` (the per-exception API, not the vector form which IDA 8.4 doesn't expose). Clears `EXC_BREAK`, sets `EXC_HANDLE | EXC_SILENT`. Result: exceptions pass through to the target's SEH chain instead of pausing IDA.

If a session pre-dates a plugin load, call `mcp__ida__dbg_silence()` manually. There's also a "Single step execution error" dialog with a "don't display again" checkbox — clicking that suppresses it persistently in IDA's config.

### Anti-watchdog: non-pausing trace BPs (`dbg_set_trace_bp`)

When reversing a protocol with a **timing watchdog** (iLok, VMProtect, FX3 firmware that drops the session if inter-packet gap > X ms), a standard BP+pause+dump+continue cycle takes hundreds of ms per hit and trips the watchdog. The target then refuses subsequent commands with a generic error (Logic 2 surfaced `devicesetupfailure`).

**Trace BPs solve this.** They're real BPs that:

- Fire as usual (CPU interrupt → IDA notified)
- Have `BPT_BRK` cleared on the underlying `bpt_t` so IDA does NOT pause execution — fall-through is automatic, total pause is microseconds
- Are routed through a `DBG_Hooks.dbg_bpt()` subscriber that reads registers + dereferences memory at configured pointer/size registers, appends a record to an in-process log, returns immediately

End result: BP fires N times silently during a live capture, log fills up, the target never notices a timing anomaly. **Watchdog defeated** without injecting code or hiding the debugger.

#### Setting up a trace BP

```python
# MCP-side
dbg_set_trace_bp(
    address="0x1814C4BBB",     # WinUsb_WritePipe call site
    label="WinUsbWrite",       # free-form tag, stored in each record
    addr_reg="r8",             # Win64 fastcall: arg3 = data pointer
    size_reg="r9",             #                  arg4 = data size
)
# ... run capture, BP fires N times silently ...
records = dbg_get_trace_log(clear=True)["entries"]
```

Direct HTTP also works (useful when Claude Code's MCP subprocess holds stale tool wrappers):

```pwsh
Invoke-RestMethod -Uri "http://127.0.0.1:13337/dbg_set_trace_bp" -Method Post `
  -Body '{"address":"0x1814C4BBB","label":"WinUsbWrite","addr_reg":"r8","size_reg":"r9"}' `
  -ContentType "application/json"
```

#### `fixed_dumps`: multi-pointer capture when you don't know which register holds the data

At a function entry where the calling convention is unknown (typically reversing an internal callee whose vtable doesn't expose the prototype), dump fixed-size regions from every plausibly-pointer-shaped register at once:

```python
dbg_set_trace_bp(
    address="0x1807CFBB0",     # function entry
    label="serializer_entry",
    addr_reg="", size_reg="",  # disable the addr+size mode
    fixed_dumps=[
        {"reg": "rcx", "size": 128},   # arg1
        {"reg": "rdx", "size": 256},   # arg2
        {"reg": "r8",  "size": 256},   # arg3
        {"reg": "r9",  "size": 64},    # arg4 (often a size — but try anyway)
    ],
)
```

Each register is read; if its value is in user-mode address range (`0x10000 <= ptr < 0x7FFFFFFFFFFF`), the configured size is dumped. Otherwise the record notes `"skip": "not pointer-shaped"`.

This is how we discovered (2026-05-16) that `Logic2FpgaDevice__SerializeCommand_iLokVM` takes **plaintext input** — the device-name string `"Logic Pro 16"` appeared in RCX's dump even though the function's output is iLok-encrypted.

### `reload_plugin` — iterating on the plugin without restarting IDA

After editing `ida/plugin.py` and re-syncing it to IDA's plugins folder, call `mcp__ida__reload_plugin()` (or POST to `/reload_plugin`). It schedules a background-thread `importlib.reload(...)` of the plugin module — server stops, module re-imports from disk, server restarts on the same port within ~0.5s. The IDB, all breakpoints, and the scratch netnode persist.

**Caveat**: the FIRST reload after a plugin change still requires either a manual `importlib.reload` paste OR a full IDA restart, because the OLD plugin doesn't have the `/reload_plugin` endpoint yet. Every subsequent iteration is one MCP call. `Ctrl+Shift+M` toggling the plugin via IDA's menu only restarts the HTTP server — it does NOT re-import the .py from disk.

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
