# Unified MCP server

The unified server presents one provider-neutral MCP surface for persistent
headless and GUI-attached reversing sessions. A session has a stable
`session_id`; provider differences are advertised through capabilities and
provider-specific operation names.

## Install and register

Install the common Python dependencies first:

```shell
python -m pip install mcp httpx
```

The installer can non-interactively register the unified server with Claude
Code, Codex, or both without changing provider installations:

```shell
python install.py --register-only --scope user --clients claude,codex
```

Omit `--register-only` and add `--all` when the installer should also build
and deploy every available provider bridge.

To install just the IDA and Ghidra components and register the unified server
with both clients:

```shell
python install.py --tools ida,ghidra --scope user --clients claude,codex
```

The result is still one MCP entry named `reversing-mcp`. IDA and Ghidra are
provider IDs passed to the shared lifecycle tools; they are not separately
registered MCP servers.

Codex's CLI registration is user-global; use `--scope user` when Codex is
selected.

The registered command is:

```shell
python -m reversing_mcp
```

The installer also records the repository root in `PYTHONPATH`, so user-global
registrations work outside the clone directory. To run it manually without a
registration, execute the command from the repository root.

Manual registration from the repository root is also possible:

```shell
claude mcp add -s user -e PYTHONPATH=/absolute/path/to/reversing-mcp \
  reversing-mcp -- /absolute/path/to/python -m reversing_mcp

codex mcp add --env PYTHONPATH=/absolute/path/to/reversing-mcp \
  reversing-mcp -- /absolute/path/to/python -m reversing_mcp
```

On Windows, use the equivalent absolute Windows paths.

## Optional providers

Provider SDKs are imported lazily; a missing optional dependency does not stop
the unified server or other providers from starting.

- Binary Ninja requires its `binaryninja` Python module to be importable by the
  interpreter registered above. Configure the Binary Ninja API for that exact
  interpreter using the vendor-supported installation method.
- radare2 requires the `radare2` executable on `PATH` and `r2pipe` in the
  registered Python environment: `python -m pip install r2pipe`.
- Frida requires `frida` in the registered Python environment. Android/iOS
  targets also require a matching `frida-server` on the device.
- ILSpy requires the published .NET bridge under
  `ilspy/IlspyMcpBridge/bin/Release/net8.0/publish`, or an explicit
  `ILSPY_MCP_BRIDGE` path.
- Bluetooth LE requires `bleak` in the registered Python environment. Install
  it with `python install.py --tools ble --scope user --clients claude,codex`.
- Capstone requires `capstone` in the registered Python environment. Install
  it with
  `python install.py --tools capstone --scope user --clients claude,codex`.
  It provides read-only raw-byte and file-region disassembly without an
  analysis database; see [Capstone raw disassembly](CAPSTONE.md).
- The `protocol` provider has no external dependency or target requirement.

IDA, Ghidra, JADX, and ILSpy still require their corresponding native bridge
or plugin setup. The unified protocol owns and drives those components; it
does not replace their analysis engines.

## Script execution policy

Provider-native scripts are disabled by default. Generic `invoke` calls cannot
bypass this guard; scripts must use `run_python` or `run_script`, and the
session must advertise the matching capability such as `script.python` or
`script.javascript`.

Opt in during registration only on trusted, local systems:

```shell
python install.py --register-only --scope user --clients claude,codex \
  --allow-scripts
```

Restrict execution to selected providers with an allowlist:

```shell
python install.py --register-only --scope user --clients claude,codex \
  --allow-scripts \
  --script-providers ida,ghidra,frida,binary_ninja,radare2
```

These flags set the following server environment variables:

- `REVERSING_MCP_ALLOW_SCRIPTS=1` enables script execution.
- `REVERSING_MCP_SCRIPT_PROVIDERS=ida,ghidra,frida,binary_ninja,radare2`
  optionally limits it to the listed provider IDs.

Scripts execute with the privileges of the provider process and may modify its
database or host. `run_python` saves by default on persistent providers;
generic `run_script` defaults to `save_after=false`, which is appropriate for
dynamic providers such as Frida that have no analysis database.

Ghidra Python execution is available when attached to the installed GUI
extension, which embeds Jython 2.7. The owned `analyzeHeadless` bridge is Java
only and therefore does not advertise `script.python`.

## Lifecycle

Typical persistent headless use is:

1. `create_session` creates a provider database from an input artifact, or
   `reopen_session` loads an existing database.
2. `capabilities` reports the operations available in that exact mode.
3. `invoke` performs declared read or mutation operations. Mutations save by
   default.
4. `save_session` creates an explicit checkpoint.
5. `close_session` persists and closes the provider resource.

`attach_session` binds to a compatible process or GUI instance. Unsupported
GUI-only or headless-only behavior returns a structured
`unsupported_capability` result instead of silently disappearing.

Read-only providers advertise only real lifecycle behavior. ILSpy opens or
attaches to an assembly bridge and closes owned processes without a fake save
operation. Frida opens an inventory/spawn session or attaches to a process,
then detaches on close; it likewise has no database save capability.
JADX keeps archive and JavaScript operations read-only and removes its owned
temporary XAPK extraction when the session closes. Bluetooth sessions own a
live connection but never claim database persistence; transcript files are
written only by an explicit `ble.transcript.save` operation.
