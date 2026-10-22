# reversing-mcp

One MCP server for reverse engineering with IDA Pro, Ghidra, JADX, Flutter/Dart
AOT, ILSpy, Binary Ninja, radare2, Capstone, Frida, Bluetooth LE, and offline
protocol utilities. It
provides stable session IDs, a common
capability model, persistent database lifecycle, headless operation, and
guarded provider-native script execution.

```text
Claude Code / Codex
        |
        | stdio
        v
python -m reversing_mcp
        |
        v
SessionManager + provider registry
        |
        +-- IDA adapter --------> IDA plugin or owned idat64 process
        +-- Ghidra adapter -----> GUI extension or analyzeHeadless
        +-- JADX adapter -------> owned jadx-core JVM
        +-- Flutter adapter ----> APK/XAPK/AAB inspector + optional Blutter
        +-- ILSpy adapter ------> owned .NET bridge
        +-- Binary Ninja -------> Python API
        +-- radare2 ------------> r2pipe
        +-- Capstone -----------> in-process raw-byte disassembly
        +-- Frida adapter ------> local/USB/remote Frida device
        +-- Bluetooth LE -------> Bleak and the host Bluetooth adapter
        `-- Protocol -----------> checksum, Modbus, and register-map helpers
```

The native bridges remain provider-specific, but clients register only the
unified `reversing_mcp` server. Provider differences are reported through
capabilities and operation metadata rather than separate MCP tool sets.

## Quick start

Clone the repository and install the common Python dependencies:

```shell
git clone https://github.com/ril3y/reversing-mcp.git
cd reversing-mcp
python -m pip install mcp httpx
```

Run the installer interactively:

```shell
python install.py
```

Or register the unified server non-interactively without changing any provider
installation:

```shell
python install.py --register-only --scope user --clients claude,codex
```

To build and deploy every provider component available in the checkout:

```shell
python install.py --all --scope user --clients claude,codex
```

For only IDA and Ghidra, install their bridges and register the single unified
server in both clients with:

```shell
python install.py --tools ida,ghidra --scope user --clients claude,codex
```

This creates one MCP entry named `reversing-mcp`; IDA and Ghidra are providers
selected through `open_session`, `create_session`, `reopen_session`, or
`attach_session`. Do not register separate `ida` or `ghidra` MCP servers.

Use `--dry-run` to inspect commands first. Codex CLI registration is
user-global, so select `--scope user` when `codex` is one of the clients.

The installed command is:

```shell
python -m reversing_mcp
```

See [the unified server guide](docs/UNIFIED_SERVER.md) for manual registration,
script policy, and lifecycle details.

## Unified MCP surface

The server exposes a small lifecycle-oriented API:

| Tool | Purpose |
|---|---|
| `list_backends` | List providers, capabilities, and declared operations |
| `list_sessions` | List sessions owned by the server process |
| `capabilities` | Inspect one provider or live session |
| `open_session` | Open a target using a provider's normal lifecycle |
| `create_session` | Create a persistent database from an artifact |
| `reopen_session` | Reopen an existing database or project |
| `attach_session` | Attach to a compatible GUI or provider process |
| `invoke` | Run a declared, non-script analysis operation |
| `run_script` | Run a guarded provider-native script in its declared language |
| `run_python` | Run provider-native Python when policy allows it |
| `save_session` | Persist the provider database or project |
| `close_session` | Save and close an owned session |

Common operation names include `target.info`, `analysis.decompile`,
`analysis.disassemble`, `references.to`, `references.from`,
`symbols.rename`, `comments.write`, `types.define`, and `types.apply`.
Each session advertises its exact operation set; unsupported behavior returns a
structured error.

Mutating operations save by default. A session should still be closed with
`close_session(save=true)` so the provider can flush and exit normally.

## Provider setup

### IDA Pro

The installer copies `ida/plugin.py` to the IDA user plugin directory. On
Windows this is normally:

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp_plugin.py
```

The plugin starts its loopback HTTP bridge when a database opens. It marshals
all IDA API work onto IDA's main thread; the HTTP worker never calls IDAPython
analysis APIs directly.

For an owned headless database, start the local spawn service:

```powershell
python ida\spawn_server.py --headless `
  --ida-path "C:\Program Files\IDA Pro 8.4\idat64.exe"
```

Then use `create_session` or `reopen_session` with `provider="ida"` and
`mode="headless"`. Names, comments, types, function edits, and the scratch
notebook persist in the `.i64`/`.idb`. See [IDA headless
sessions](ida/HEADLESS.md).

Remote exposure is opt-in and unauthenticated. Bind spawn and bridge services
only to trusted interfaces. Remote IDA bridges refuse Python execution.

### Ghidra

Set `GHIDRA_INSTALL_DIR`, then let the installer build and deploy the extension:

```powershell
$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra"
python install.py --tools ghidra --scope user --clients claude
```

Enable the extension in Ghidra and restart. GUI sessions attach to a program
owned by the user; remote close is rejected. Headless sessions launch
`analyzeHeadless`, create or reopen a project program, and save when the owned
process closes. See [Ghidra headless lifecycle](ghidra/HEADLESS.md).

### JADX

JADX runs without a GUI. Build the fat JAR with JDK 17 or newer:

```shell
cd jadx/jadx-mcp-bridge
gradle shadowJar
```

The unified provider starts an owned JVM per APK, XAPK, AAB, JAR, or DEX. Set
`JADX_MCP_BRIDGE_JAR` when the artifact is not in the default Gradle output
directory. For APK/XAPK inputs the same session can inventory and extract nested
members, search bundled JavaScript with context, pretty-print a selected module
or function, and identify DCloud/uni-app apps, pages, and modules. Temporary
extractions are removed when the session closes. JADX sessions are intentionally
read-only. See [JADX provider notes](jadx/PROVIDER.md).

### Flutter and Dart AOT

The `flutter` provider inspects APK, split APK/XAPK, APKS, AAB, and ZIP
containers without requiring JADX. It detects Flutter packaging, inventories
ABIs, AOT loading units, assets, plugin candidates, and platform-channel string
candidates, and safely extracts members. An optional `AotAnalyzer` adapter adds
cached Dart AOT reconstruction; the first adapter is Blutter and is configured
explicitly with `BLUTTER_COMMAND`. Upstream toolchain acquisition is blocked
unless the request or server environment opts in. See
[Flutter and Dart AOT](docs/FLUTTER.md).

### Bluetooth LE and protocol analysis

Install the optional Bleak transport into the registered Python environment:

```shell
python install.py --tools ble --scope user --clients claude,codex
```

Open a `bluetooth_le` session with an optional device address. Its operations
cover scanning, connecting, service/characteristic inventory, reads, writes,
notifications, and timestamped JSON/JSONL transcripts. The same session exposes
checksum, Modbus RTU, and register-map decoding operations. An offline
`protocol` session exposes those protocol operations without Bluetooth or a
target file. See [Android, JavaScript, BLE, and protocol tools](docs/ANDROID_BLE.md).

### ILSpy

ILSpy is a read-only, headless managed-code provider. Build its .NET bridge:

```shell
dotnet publish ilspy/IlspyMcpBridge/IlspyMcpBridge.csproj -c Release
```

`open_session(provider="ilspy", target_path="...dll")` starts and owns one
bridge process per assembly. It supports assembly/type/method discovery, C#
decompilation, raw IL, referenced assemblies, and string search. Because the
analysis is read-only, ILSpy advertises open/attach/close but not fake
save/create/reopen capabilities.

### Frida

Install the Python client and, for Android/iOS, run a matching `frida-server`
on the target:

```shell
python -m pip install frida frida-tools
```

Frida supports inventory-only sessions, attach, suspended spawn/resume,
module/import/export inspection, bounded memory reads, JavaScript injection,
message draining, and RPC exports. JavaScript goes through guarded
`run_script(language="javascript", ...)`; closing detaches and optionally
kills only a process spawned by that session. See [Frida provider
notes](frida/README.md).

### Binary Ninja

Configure the `binaryninja` Python module for the same interpreter registered
with the MCP client. The adapter imports the SDK lazily, so a missing Binary
Ninja installation does not prevent other providers from starting. Persistent
state is stored in `.bndb` files.

### radare2

Install radare2 and make its executable available on `PATH`, then install the
Python transport:

```shell
python -m pip install r2pipe
```

The adapter opens targets headlessly and persists state through radare2
projects. Project names are validated before being passed to radare2.

### Capstone

Install the optional Capstone engine into the Python interpreter registered
with the clients:

```shell
python install.py --tools capstone --scope user --clients claude,codex
```

The `capstone` provider decodes raw bytes or bounded file regions without a GUI
or analysis database. It supports explicit architecture, mode, endianness,
base address, and file offset settings, including ARM Cortex-M Thumb images.
It intentionally does not advertise function discovery, xrefs, decompilation,
annotations, or persistence. See [Capstone raw disassembly](docs/CAPSTONE.md).

## Script execution

Provider-native scripts are disabled by default. Enable them only for trusted
local targets:

```shell
python install.py --register-only --scope user --clients claude,codex \
  --allow-scripts --script-providers ida,ghidra,frida,binary_ninja,radare2
```

This sets `REVERSING_MCP_ALLOW_SCRIPTS=1` and an optional
`REVERSING_MCP_SCRIPT_PROVIDERS` allowlist. Generic `invoke` cannot bypass the
guard; scripts must use `run_python` or `run_script`, and the live session must
advertise the corresponding capability such as `script.python` or
`script.javascript`.

Scripts run with the provider process's privileges and may modify its database
or host. Arbitrary in-process Python cannot always be interrupted safely. A
client timeout does not prove that the provider stopped executing the script.

## Development

The shared Python package is organized as follows:

```text
reversing_mcp/
|-- models.py              Wire models, capabilities, and common operations
|-- backends.py            AnalysisBackend and AnalysisSession interfaces
|-- registry.py            Provider registration
|-- manager.py             Lifecycle, policy, persistence, and dispatch
|-- android_artifacts.py   Nested APK/XAPK and bundled JavaScript analysis
|-- android_frameworks.py  Extensible Android framework detector registry
|-- flutter_artifacts.py   Flutter package and asset inspection
|-- dart_aot.py            Pluggable AOT analyzers and persistent result cache
|-- capstone_engine.py     Architecture/mode normalization and decoding
|-- protocols.py           Checksums, Modbus RTU, and register maps
|-- server.py              Unified FastMCP surface
`-- providers/
    |-- local_bridges.py   IDA, Ghidra, and JADX adapters
    |-- ilspy.py           ILSpy read-only bridge adapter
    |-- frida.py           Frida dynamic instrumentation adapter
    |-- flutter.py         Flutter package and Dart AOT orchestration
    |-- binary_ninja.py    Binary Ninja adapter
    |-- bluetooth_le.py    Bleak transport and transcript capture
    |-- capstone.py        Lightweight raw-byte disassembly provider
    |-- protocol.py        Offline protocol-analysis provider
    `-- radare2.py         radare2 adapter
```

Provider bridges live in their own directories and communicate over loopback
HTTP where an in-process SDK is not practical. Registration files under
`~/.<provider>_mcp/` identify live bridge processes.

Run the checks with:

```shell
python -m ruff format --check .
python -m ruff check .
python -m pytest -q
```

To add a provider, implement `AnalysisBackend` and `AnalysisSession`, declare
capabilities and `OperationSpec` entries, add it to
`reversing_mcp.providers.builtin_backends()`, and add lifecycle round-trip
tests. Persistent providers should prove that a rename/comment/type mutation
survives save, close, and reopen without modifying the input artifact.

## Safety notes

- Bridges bind to loopback by default and do not provide authentication.
- IDA mutations are blocked while its debugger is running or paused because
  changing database structures in that state can crash IDA.
- Ghidra headless changes are durable only after its outer transaction closes.
- Static decompilation is evidence about program structure, not observed
  runtime behavior.
- Keep provider SDKs and analysis engines pinned in reproducible automation.

Use these tools only on software and devices you are authorized to analyze.
