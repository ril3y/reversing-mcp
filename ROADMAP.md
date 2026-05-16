# reversing-mcp roadmap

Tracking note for follow-up bridge improvements, cross-cutting features,
and integrations identified during real-world RE sessions. Each item is a
self-contained chunk of work — pick whatever's highest leverage.

Effort estimates assume working in-tree with the existing patterns:
**S** = under 100 LOC, ~1 hour · **M** = 100–500 LOC, ~half a day · **L** = full feature, ~1+ days.

## ✅ Shipped: Interactive markdown notebook (in-IDA GUI)

Landed as `_NotebookViewer` (PluginForm + QTextBrowser) inside
`ida/plugin.py`. New endpoints: `scratch_show`, `scratch_refresh`.
Hotkey `Ctrl+Shift+N` opens the viewer; auto-refresh polls the scratch
netnode every 200 ms and re-renders + auto-scrolls when the buffer
grows (skips auto-scroll if the user manually scrolled away — standard
chat-UI pattern). Click on `sub_XXXXXX` or `0x...` jumps the disassembly
view. `{{decompile:0xADDR}}` macro in markdown source expands to live
Hex-Rays pseudocode at render time, so renames propagate the next time
the notebook re-renders.

Renderer: prefers the Python `markdown` package; ships a hand-rolled
fallback that handles headers, fenced code, inline code, bold/italic,
lists, paragraphs, and links so a fresh IDA-Python install still works.

### Still-open follow-ups

- **`IDB_Hooks` auto-refresh.** Today the viewer refreshes when the
  scratch netnode grows. Wiring `ida_idp.IDB_Hooks` (rename_done,
  cmt_changed, func_added/deleted) into `_render_now()` would make the
  embedded `{{decompile:...}}` blocks re-render the *moment* you commit
  a rename in IDA — no scratch write needed.
- **`scratch_stream(category, chunks)`** convenience endpoint. Makes
  agent intent explicit ("I'm streaming these sections in order") and
  inserts tiny delays so the viewer renders each chunk before the next
  arrives. Today an agent calling `scratch_append` in a loop works
  fine — this is sugar.
- **More macros.** `{{disasm:0xADDR,N}}` (N lines of disassembly),
  `{{xrefs:0xADDR}}` (caller table). Same expansion pattern as the
  decompile macro.

## ✅ Shipped this session: IDA debugger integration

22 new endpoints (`dbg_state`, `dbg_attach`/`launch`/`detach`/`terminate`,
`dbg_continue`/`pause`/`run`, `dbg_step_into`/`over`/`out`,
`dbg_run_until_ret`, `dbg_run_to`, `dbg_set/del/list_breakpoint(s)`,
`dbg_read/write_memory`, `dbg_get/set_reg`/`get_regs`, `dbg_wait_event`,
`dbg_callstack`/`threads`/`modules`) plus Hex-Rays local-var endpoints
(`rename_local_var`, `set_local_var_type`). Verification target — the
Saleae buffer-capture flow described below — is the next session's first
task. Original design notes preserved below for context.

## ★ Original proposal: IDA debugger integration

IDA has a full built-in debugger (Windows/Linux/macOS, local + remote, every
arch IDA supports). Wiring it into the bridge unlocks **dynamic analysis** —
the missing capability that the iLok wall on Saleae's `graph_server_shared.dll`
defeated us with statically. The wire-format serializer is virtualized, but
the *output* of the serializer (the bytes about to be written to USB) is
plaintext in a buffer we can read by breaking on `WinUsb_WritePipe` and
inspecting the args. We dont have to crack iLok — we just have to see what
it produced.

Same workflow generalizes:
- Step into a function and watch state evolve to validate the structs we
  defined (the field offsets are right? wrong?).
- Set a write-watch on a memory address to find every code path that
  modifies a struct field.
- Run-to-address to skip past the iLok decoder loop and resume at a
  predictable post-decode state.

### Endpoint surface (~16 endpoints)

| Endpoint | Purpose |
|---|---|
| `dbg_attach(pid)` / `dbg_launch(path, args)` / `dbg_detach()` | Process attach + lifecycle |
| `dbg_run()` / `dbg_pause()` / `dbg_continue()` | Run-state control |
| `dbg_step_into()` / `dbg_step_over()` / `dbg_step_out()` | Single-step |
| `dbg_run_to(addr)` | Temp BP + continue (common idiom) |
| `dbg_set_breakpoint(addr, type)` / `dbg_del_breakpoint` / `dbg_list_breakpoints` | BP management. `type ∈ {sw, hw_exec, hw_read, hw_write, hw_rw}` |
| `dbg_read_memory(addr, size)` / `dbg_write_memory(addr, hex)` | Live memory R/W (auto-pauses if running) |
| `dbg_get_reg(name)` / `dbg_set_reg(name, value)` / `dbg_get_regs()` | Register R/W |
| `dbg_callstack()` / `dbg_threads()` / `dbg_modules()` | Process introspection |
| `dbg_wait_event(timeout_ms)` | Blocking poll: returns `{event: "bp"\|"exception"\|"exit"\|"timeout", details}` |

### Implementation notes

- Python API: `idc.start_process`, `idc.attach_process`, `idc.suspend_process`,
  `idc.resume_process`, `idc.run_to`, `idc.step_into`, `idc.step_over`,
  `idc.set_bpt`, `idc.del_bpt`, `idc.get_reg_value`, `idc.set_reg_value`,
  `idc.read_dbg_memory`, `idc.write_dbg_memory`, `idc.get_thread_qty`,
  `idc.get_callstack`. Mature, well-documented, all callable from the
  main-thread queue we already use.

- **State machine is the hard part**: the debuggee runs asynchronously.
  The bridge must track `{detached, attached_paused, attached_running, exited}`
  and gate operations accordingly (e.g. `dbg_read_memory` while running
  should either auto-pause or return a clear error). Add a small
  `dbg_state()` endpoint.

- **Event pump**: `dbg_wait_event(timeout_ms)` is the natural primitive.
  Internally it uses `ida_dbg.wait_for_next_event(WFNE_SUSP, timeout)` or
  the equivalent. Polls naturally fit the MCP request/response model.

- **Anti-debug**: Saleae's binary may have iLok-installed anti-debug checks.
  If so, `dbg_attach` will be detected. Workarounds (ScyllaHide, stealth
  plugins) are out of scope for the bridge — we just need to attach
  successfully or fail cleanly with a useful error.

### Effort

**M+ to L**. ~200–300 LOC on `ida/plugin.py`, plus matching MCP wrappers.
Mostly mechanical once the state machine is right.

### Verification target

The dogfood test is the Saleae buffer-capture flow: launch Logic 2, attach,
BP at `WinUsb_WritePipe` call inside `WindowsUsbDevice__Write`, trigger a
Logic 2 capture, dump `(rdx, rcx)` on each hit, collect a corpus of real
FX3 commands. Cross-reference against the `*_CommandHandler` string names
already in `saleae_native/notes/dll_protocol_strings.md` to map opcode
bytes → command names.

## IDA bridge (`ida/plugin.py` + `ida/mcp_server.py`)

The most-developed bridge. Surface is solid for static work, gaps are around iteration ergonomics.

| # | Endpoint | Why | Sketch | Effort | Status |
|---|---|---|---|---|---|
| 1 | `list_types`, `get_type` | Read back defined types so we can iterate on a struct without losing the previous definition or grepping the IDB. Right now `define_type` is one-shot and opaque. | `idc.get_type(name)` for the C-decl string; iterate `ida_typeinf.get_ordinal_qty()` and `ida_typeinf.get_numbered_type()` for listing. | S | Proposed |
| 2 | `rename_local_var`, `set_local_var_type` | The 80% readability win still missing from decompiles. Locals like `v10, v40, Buffer` are real state we should be able to name + type. This compounds across re-decompiles. | `ida_hexrays.rename_lvar(func_ea, old, new)` and `ida_hexrays.set_lvar_type(func_ea, name, tinfo)`. Need a fresh `cfunc_t` per call. | M | Proposed |
| 3 | `set_struct_member_comment` | Annotate individual struct fields (e.g. "this is std::optional has-value flag") without redefining the whole struct. Keeps annotation stable across edits. | `ida_struct.set_member_cmt(member_t, cmt, repeatable)` — or the new typeinf equivalent. | S | Proposed |
| 4 | `/auto_status` | Lets agents tell "no xrefs because indexing isn't done" from "no xrefs, period". We guessed for hours during the Saleae pass. | `ida_auto.auto_is_ok()` + `ida_auto.get_auto_state()` returning `{idle, pass_name}`. | S | Proposed |
| 5 | `/log_tail?lines=N` | Surfaces what's in IDA's Output window. We need this to see why Hex-Rays popped a modal (the actual error text), and to confirm rename/comment side-effects. | `ida_kernwin.msg_get_lines(N)`. | S | Proposed |
| 6 | `parse_decl` (dry-run for `define_type`) | When the agent is unsure if a C decl is well-formed, validate without committing. Saves "did that actually parse?" round-trips. | `idc.parse_decl(decl, flags)` returns `None` on error. | S | Proposed |
| 7 | `bulk_rename(names: list[(addr,name)])` | We already fan out N parallel rename calls today, but a single batched endpoint would amortize the IDA-main-thread tick cost. | One handler that iterates inside `_run_on_main_thread` so the timer drains in one tick. | S | Nice-to-have |

## Ghidra bridge (`ghidra/`)

Has the original IDA surface but **not the new endpoints we added in this branch** (`define_type`, `apply_type`, `set_function_prototype`, `add_segment`, `set_segment_attrs`). The MCP wrappers are 1:1 mirrors — the gap is on the Java/Ghidra side.

| # | Endpoint | Why | Sketch | Effort |
|---|---|---|---|---|
| 8 | `define_type` (Ghidra side) | Parity with IDA. Ghidra's `DataTypeManager` + `DataTypeParser` does this; can take a single C declaration string. | `DataTypeParser.parse(decl)` → add to `program.getDataTypeManager()`. | M |
| 9 | `apply_type` | Apply a `DataType` at an address via `program.getListing().createData(addr, dt)`. | M |
| 10 | `set_function_prototype` | `Function.setSignature(FunctionSignature)` after parsing the C decl. | M |
| 11 | `add_segment` / `set_segment_attrs` | `program.getMemory().createInitializedBlock(...)` / `MemoryBlock.set*(...)`. Useful for marking MMIO regions in firmware. | M |
| 12 | `rename_local_var` / `set_local_var_type` | Equivalent of IDA item #2 on Ghidra's decompiler — `HighFunctionDBUtil.updateDBVariable(...)`. | M |

## jadx bridge (`jadx/`)

Mostly stable for read-only queries. Mutation isn't really applicable (jadx is a decompiler, not an IDE — it doesn't have a persistent "user-edited DB" the way IDA/Ghidra do).

| # | Endpoint | Why | Effort |
|---|---|---|---|
| 13 | `search_methods` | Substring search across method names globally (currently you have to list-classes then filter). Useful for "find all `verify*` methods". | S |
| 14 | `get_method_xrefs_from` | Outgoing calls from a method — what does it invoke? Complements existing `xrefs_to`. | S |

## ILSpy bridge (`ilspy/`)

Same — read-only by nature. Add the missing read endpoints to match jadx surface.

| # | Endpoint | Why | Effort |
|---|---|---|---|
| 15 | `get_class_metadata` / equivalent | Mirror jadx's `get_class` — return type info + method list without source. | S |
| 16 | `xrefs_to` (call sites) | The C# decompiler library exposes a usage analyzer (`UsageAnalysis`). Wire it up. | M |

## Unicorn bridge (`unicorn` branch)

The branch is functional. Future work is mostly use-case driven:

| # | Endpoint | Why | Effort |
|---|---|---|---|
| 17 | `/load_elf` / `/load_pe` | Auto-map sections from a binary file (today the agent does `map_region` + `load_file` by hand). Lower priority — the manual composition is *the* test of generic primitives. | M |
| 18 | `/fuzz_until_crash` | Run a function with mutated input (AFL-unicorn-style) until a `UcError` fires; return the failing input + register state. | L |
| 19 | `/coverage` / `/trace_basic_blocks` | Always-on block trace exposed as a queryable list — for measuring how much of a function we explored. | M |

## saleae_native (`saleae` branch)

The IDA RE found that the wire-format serializer is iLok-virtualized — static reverse won't work past that. The realistic finish-line is sigrok-cli shim, not pushing through. See `saleae_native/notes/session_2026-05-15_ida_pass.md` for the carry-forward.

| # | Item | Effort |
|---|---|---|
| 20 | Refactor `driver.py` as a `sigrok-cli` subprocess wrapper. Endpoints become flag mappings on top of `sigrok-cli --driver saleae-logic-pro`. | M |
| 21 | USBPcap a live Logic 2 capture, recover the 500 MS/s mode bytes sigrok hasn't reversed, contribute upstream. | L |
| 22 | Debug-port-finder mode (passive JTAG/SWD/UART classifier on the captured samples). | M |

## Hybrid static + dynamic (cross-bridge composition)

The bridges already compose loosely — an agent (Claude) can pull bytes
from one bridge and feed them to another. Several patterns are worth
codifying as cookbook recipes or meta-tools:

### IDA static → Unicorn emulation (no new bridge code required)

Pull a function's bytes via `ida.get_bytes`, map + load into Unicorn,
write registers, run, observe. ~8 MCP calls today; works on the existing
servers. Killer apps:

- Validate struct-field hypotheses without re-decompiling.
- Crypto/hash function discovery: emulate with known inputs, check
  outputs against an oracle.
- Branch exploration to map reachable code paths.

Worth writing as `cookbooks/ida-to-unicorn-emulation.md`.

### IDA debugger → Unicorn (iLok bypass via runtime dump)

The big one for the Saleae case. iLok JIT-allocates its VM bytecode at
runtime addresses outside the static PE (`0x1C99508A7`-ish), which means
pure-static Unicorn can't follow. **Combination**: use IDA's debugger
(top-priority item above) to attach to a live Logic 2, wait for iLok to
materialise the VM region, `dbg_read_memory` to dump it, then feed the
dump into Unicorn. Now we can emulate the post-iLok serializer offline
with mutated inputs, indefinitely, no live process required.

Three legs of the stool: **static IDA + IDA debugger + Unicorn**.

### Meta-tool: `emulate_function(idb, address, arch_instance, inputs)`

Once the unified `reversing_mcp.py` lands (cross-cutting item #23), it
can expose meta-tools that bridge across servers in one call:

```python
emulate_function(
    idb="graph_server_shared",
    address="0x1807EB510",
    arch_instance="x86_64",
    inputs={"rcx": 0x1234, "rdx": 0x40000000},
    timeout_ms=5000,
) -> {final_pc, regs, exit_reason}
```

Internally: 8-call dump+map+load+run sequence. Externally: one tool call.
Effort: **S** once the unified server is in place.

## Cross-cutting

| # | Item | Why | Effort |
|---|---|---|---|
| 23 | **Unified `reversing_mcp.py`** | One stdio MCP server replacing the per-tool ones. User installs one entry in Claude Code instead of five; cross-tool meta-tools (`compare_ida_vs_ghidra_decompile(addr)`) become possible. Bridges-in-tools layer is unchanged. | M |
| 24 | **`version_info` MCP tool + 24h GitHub Releases cache** | The MCP can tell the user "an update is available" opportunistically. ~50 LOC in `common.py` + one tool wrapper. | S |
| 25 | **`install.py --update`** | `git pull` + re-run build/deploy for already-installed tools. Idempotent. | S |
| 26 | **GitHub Actions release pipeline** | Tag push (`v*`) → CI builds jadx fat JAR + ILSpy bin + Ghidra ZIP (if a Ghidra dir is provided as a workflow input) → attaches to release. Lets `install.py --update` pull binaries instead of building locally. | M |
| 27 | **x64dbg integration** | New `x64dbg/` bridge using `~/Desktop/x64debug/pluginsdk/`. Surface: `attach/detach/run/step_*/breakpoints/regs/memory/callstack/run_command`. Dynamic debug complements static IDA/Ghidra perfectly. | L |
| 28 | **Bridge testing under load** | The Saleae session found two distinct failure modes — modal-dialog wedge (fixed via `idc.batch`) and PID-kill via `os.kill(pid, 0)` on Windows (fixed via `OpenProcess`). Suite of fault-injection tests would catch the next class of these. | M |

## Recently shipped (just so future-you knows what's done)

- **Bridge ergonomics under debug**: `dbg_silence` endpoint (auto-runs on
  attach/launch) that disables `DOPT_EXCDLG` AND marks every known
  exception as pass-through (`EXC_HANDLE` + `EXC_SILENT`, clears
  `EXC_BREAK`). Required for iLok/VMProtect-style protections that throw
  exceptions as normal control flow. Without it, IDA traps the first one
  and the debuggee can never make progress.
- **Per-request audit logging**: every MCP hit logs `[MCP MUT|   ] /path body`
  to IDA's Output window. Slow requests (>1s) log `[MCP SLOW] /path took Xs`.
  Stalled-queue warnings name the path: `[MCP] WARNING: '/decompile' queued for >5s`.
- **Markdown viewer**: pip-installs `markdown` package on a background thread
  (no more main-thread stall), shows install-instructions page only if that fails.
- **MCP HTTP timeout** lowered to 10s default (was 30s); `dbg_wait_event` uses
  `timeout_s + 5` so legitimate waits aren't cut short.
- **In-IDA markdown notebook viewer.** `_NotebookViewer` PluginForm +
  `scratch_show` / `scratch_refresh` endpoints + `Ctrl+Shift+N` action.
  `{{decompile:0xADDR}}` live macro. Replaced the (never-worked)
  Notepad mirror.
- `define_type`, `apply_type`, `set_function_prototype`, `add_segment`, `set_segment_attrs` on the IDA bridge. (`cb84048` ish)
- Modal-dialog watchdog + `idc.batch(1)` per-handler wrapping in `_MainThreadTimer._tick`.
- Windows-safe PID liveness check in `common.py` (do not regress this — it killed a live IDA during dev).
- `install.py` interactive installer with build+deploy+register actions for all five tools.
- `unicorn` and `saleae` branches pushed, not merged.
