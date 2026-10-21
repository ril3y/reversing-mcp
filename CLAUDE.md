# CLAUDE.md

This file describes the repository conventions for coding agents.

## Repository purpose

`reversing-mcp` is one unified MCP server for multiple reverse-engineering
providers. Clients launch:

```shell
python -m reversing_mcp
```

Do not add a provider-specific MCP entrypoint. Provider-specific code belongs
behind the shared session protocol.

```text
MCP client
    |
    | stdio
    v
reversing_mcp.server
    |
    v
SessionManager -> AnalysisBackend -> AnalysisSession
                                      |
                         native SDK or loopback bridge
```

The currently registered built-ins are IDA, Ghidra, JADX, ILSpy, Binary Ninja,
radare2, Capstone, Frida, Bluetooth LE, and offline protocol utilities.
Optional SDKs are imported lazily so one unavailable engine does not prevent
the server from starting.

## Core package

- `reversing_mcp/models.py`: protocol version, lifecycle actions, capability
  IDs, canonical operation names, descriptors, and result envelopes.
- `reversing_mcp/backends.py`: `AnalysisBackend` and `AnalysisSession` base
  classes.
- `reversing_mcp/registry.py`: provider registry and built-in registration.
- `reversing_mcp/manager.py`: stable session IDs, lifecycle validation,
  per-session serialization, script policy, dispatch, and mutation autosave.
- `reversing_mcp/capstone_engine.py`: Capstone architecture/mode normalization
  and provider-independent instruction decoding.
- `reversing_mcp/server.py`: the only FastMCP surface.
- `reversing_mcp/providers/`: provider adapters.

Protocol version `1.0` uses one result envelope:

```json
{"ok": true, "data": {}}
```

Expected failures use stable error codes:

```json
{
  "ok": false,
  "error": {
    "code": "unsupported_capability",
    "message": "...",
    "details": {}
  }
}
```

Do not return a silent no-op when a mode cannot implement a capability.

## Provider contract

Subclass `AnalysisBackend` and implement:

```python
async def open(self, request: SessionRequest) -> AnalysisSession: ...
```

The request lifecycle is `open`, `create`, `reopen`, or `attach`. Return an
`AnalysisSession` that implements:

```python
async def invoke(self, operation, arguments): ...
async def save(self): ...
async def close(self, *, save=True): ...
async def run_script(self, *, language, source, arguments): ...  # optional
```

Use canonical operation names such as `analysis.decompile`,
`analysis.disassemble`, `references.to`, `symbols.rename`, and
`comments.write`. Namespace provider-only operations, for example
`ida.debugger.state`. Declare every exposed operation with `OperationSpec` and
mark mutations with `mutating=True` so the manager can autosave. Reuse a
provider-neutral namespace when another engine could implement the same
concept (`debugger.*`, `managed.*`); use a provider namespace only for truly
provider-specific behavior such as `frida.messages.drain`.

Provider capabilities are mode-specific. A GUI-attached session may support a
different subset than an owned headless session. Persistent providers should
advertise `lifecycle.save` and `lifecycle.close`; read-only providers must not
pretend that save succeeded.

The manager owns public session IDs. Providers own native resources and must
not invent a second public ID layer.

## Script policy

Script execution is a separate, guarded route. Generic `invoke` rejects
`script.*` operations. `run_python` and `run_script` succeed only when:

1. `REVERSING_MCP_ALLOW_SCRIPTS` enables scripts.
2. The optional `REVERSING_MCP_SCRIPT_PROVIDERS` allowlist includes the
   provider.
3. The live session advertises the matching capability, such as
   `script.python` or `script.javascript`.

Capture stdout, stderr, return data, and tracebacks in provider results where
the runtime permits it. Python defaults to saving on persistent providers;
dynamic scripts default to no save. Never imply that a timeout interrupted an
arbitrary in-process script.

## Bridge architecture

IDA, Ghidra, JADX, and ILSpy use provider bridges because their analysis APIs
live in another runtime. The adapters own discovery, launch, and HTTP
translation; IDA/Ghidra/JADX share `local_bridges.py`, while ILSpy has its own
provider module because it also owns the .NET child process.

Each bridge writes a JSON registration beneath `~/.<provider>_mcp/` with its
PID, loopback port, and target identity. `common.py` provides safe discovery and
HTTP helpers. On Windows, process liveness must use read-only `OpenProcess`;
do not replace it with `os.kill(pid, 0)`, which has killed a live IDA process in
this project.

Keep bridges bound to loopback unless the user explicitly configures a trusted
remote interface. There is no authentication layer.

## IDA details

`ida/plugin.py` serves HTTP from a background thread, but IDAPython analysis
APIs are not thread-safe. Every handler must run IDA work through the existing
main-thread timer queue. Do not replace that mechanism with `execute_sync`; the
plugin documents a deadlock on that path.

Headless sessions are launched by `ida/spawn_server.py` and
`ida/headless_runner.py`. They must support the same non-GUI mutations as the
attached plugin: renames, comments, types, function edits, and scratch notes.
Explicit save and close are required for durable `.i64`/`.idb` state.

Treat the IDB as the investigation notebook:

- Rename a function as soon as its purpose is supported.
- Add repeatable comments for non-obvious state changes.
- Define/apply types and function prototypes as layouts become clear.
- Rename and type Hex-Rays locals when doing so improves later decompilation.
- Record cross-cutting findings and open questions in the scratch notebook.
- Read the scratch notebook at the start of a resumed database session.

Mutating IDA metadata while the debugger is paused or running can crash IDA.
Capture live registers/memory, detach, and then apply database mutations. The
bridge deliberately rejects unsafe mutation requests during debugging.

For timing-sensitive targets, non-pausing trace breakpoints capture registers
and memory without a normal stop/continue cycle. Preserve the existing
debugger-silencing and trace-breakpoint behavior when changing the plugin.

## Ghidra details

The built extension source is:

```text
ghidra/ghidra-mcp-bridge/src/main/java/ghidramcp/GhidraMcpPlugin.java
```

The headless script is `ghidra/scripts/ghidra_mcp_bridge.java`; keep its shared
behavior aligned with the extension. GUI mode attaches to a user-owned program
and must not close it remotely. Headless mode uses `analyzeHeadless` and a
blocking post-script. Its outer transaction becomes durable when
`close_session(save=true)` lets the process exit normally; a killed process can
lose the current session's edits.

Ghidra bridge API calls and mutations must stay inside the appropriate Ghidra
transaction. The headless Java bridge does not advertise `script.python`.

## JADX details

The JADX bridge is a standalone Java process built from
`jadx/jadx-mcp-bridge/`. The provider launches one owned JVM for each APK, AAB,
JAR, or DEX. Sessions are read-only and do not advertise persistence or Python
execution.

Single-method decompilation uses a decompiled line and brace-balanced slicing;
when line metadata is unavailable it falls back to the complete class. String
search decompiles classes and is slow on the first request because it warms the
jadx-core cache.

## ILSpy details

ILSpy is a read-only managed-code provider backed by the standalone .NET
bridge in `ilspy/IlspyMcpBridge/`. It supports only real lifecycle operations:
open, attach, and close for owned children. It must not advertise save, create,
or reopen. Attached bridges remain externally owned. Owned close must wait for
the child and remove its registration file even when Windows process
termination bypasses the bridge's exit handler.

## Frida details

Frida is a dynamic provider with lazy SDK import. A blank-target open creates
an inventory session; attach binds to a running process; a targeted open spawns
suspended and requires an explicit resume. JavaScript must go through the
guarded script route. Track every script, message queue, native session, and
spawned PID inside the owning session so close can unload/detach and optionally
kill only the process it created.

## Binary Ninja, radare2, and Capstone

These providers use Python APIs directly and import optional dependencies only
when opened. Do not import `binaryninja` or `r2pipe` at unified-server startup.
Both SDKs are stateful; keep provider calls serialized. Binary Ninja persists
`.bndb` files. radare2 persists projects and must validate project names before
constructing commands.

Capstone is a read-only, stateless decoder with a lazy optional import. Keep
architecture, instruction mode, endianness, base address, and file offset
explicit in results. It must not advertise analysis-database features such as
function discovery, xrefs, comments, types, or saving.

## Installer

`install.py` builds or deploys provider components and registers only the
unified server. Preserve these noninteractive paths:

```shell
python install.py --register-only --scope user --clients claude,codex
python install.py --all --scope user --clients claude,codex
```

Script opt-in is explicit through `--allow-scripts` and optional
`--script-providers`. Keep dry-run output faithful to the exact client command.

## Tests and style

Run:

```shell
python -m ruff format --check .
python -m ruff check .
python -m pytest -q
```

Unit tests should not require IDA, Ghidra, JADX, ILSpy, Binary Ninja, Capstone,
radare2, or Frida. Use fake bridges, fake SDK modules, or skip an optional
engine-specific decoding assertion. Every persistent provider
needs a round-trip test:

1. Create a database from a fixture artifact.
2. Perform representative mutations.
3. Run a provider script when supported.
4. Save and close.
5. Reopen and prove the mutations survived.
6. Verify the original artifact was not modified.

Use `apply_patch` for source edits. Preserve unrelated dirty worktree changes.
Do not add a second MCP server or bypass the shared registry/session manager.
