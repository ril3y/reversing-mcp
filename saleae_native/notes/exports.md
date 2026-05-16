# PE exports — `graph_server_shared.dll` and `graph-interface.node`

Parsed with a hand-rolled Python parser (no third-party PE libs); cross-checked
against `llvm-objdump --private-headers`.

## `graph_server_shared.dll`

- format: PE32+ x86-64 DLL ; ImageBase = `0x180000000`
- 62 exports total (40 are C++ mangled vtables/operators that aren't useful externally)
- Built with MSVC linker 14.44 ; timestamp 2026-02-25 (build CI box: `actions-runner-6\_work\monorepo\monorepo\graph-io\...`)

### The actual public C API

These 6 are the **entire** Electron-facing surface — everything else inside the DLL is reached through `DriveRequest` over its own loopback WebSocket:

| Ordinal | RVA          | Name                |
|---------|--------------|---------------------|
| 41      | `0x001b9f40` | `CreateGraphServer` |
| 42      | `0x001ba920` | `DestroyGraphServer`|
| 43      | `0x001ba950` | `DriveRequest`      |
| 44      | `0x001ba960` | `FlushLog`          |
| 45      | `0x001ba980` | `FreeResponseBuffer`|
| 46      | `0x001baa40` | `ResponseQueueSize` |
| 53      | `0x001baaa0` | `PopResponse`       |
| 54      | `0x001bb5a0` | `SetLogCallback`    |
| 55      | `0x001ba990` | `SetLogFileName`    |

`CreateGraphServer(int* port_inout, int max_clients, bool electronIsDev)` is
loaded by the Electron renderer via `ffi-napi.Library(...)` — see
`asar_findings.md`. The function starts a WebSocket server on `*port_inout`
(or chooses one if 0), returns an opaque server handle, and from then on the
JS side either:

1. (**direct mode**) calls `DriveRequest(handle, json_or_protobuf_bytes, len)` and polls `PopResponse(handle)`, OR
2. (**websocket mode**) connects from the renderer via `ws://127.0.0.1:<port>/saleae` and exchanges the same messages over WS.

On **Windows the direct path is unsupported** (`startGraphServer` throws on
`win32` in `main.js`) — Electron always uses the WebSocket path. So Logic 2's
own JS knows the wire format we need.

### Python embedding

```
PyInit_analog_span_adc   PyInit_analog_span_wdc   PyInit_digital_data
PyInit_frame             PyInit_runner            PyInit_timing
```

The DLL embeds CPython 3.14 (`python314.dll` ships alongside) and exposes six
internal modules to Python (likely for the analyzer scripting API). Not
relevant for the wire-protocol RE but useful to know if `python314.dll` shows
up imported.

### C++ analyzer surface (legacy SDK ABI)

Ordinals 1-38 are the **Saleae Analyzer SDK** — every protocol analyzer DLL
that ships in `Analyzers/*.dll` links against these symbols (`Analyzer2`,
`AnalyzerSettings`, `AnalyzerResults`, `AnalyzerChannelData`,
`SimulationChannelDescriptorGroup`, ...). This is the **public** ABI for
third-party analyzer plug-ins, documented at
`https://github.com/saleae/SampleAnalyzer`. It is **not** the USB-protocol
surface — the analyzers consume the already-decoded sample stream.

### pace_wrapping_* (PACE iLok DRM)

```
pace_wrapping_ca / _cz / _d / _fc / _fi / _ia / _iz   (8 symbols)
BadCodeHostFnPtr_DefaultBadCode_mfort6317_
```

These are PACE iLok obfuscation harness hooks. Strings like `Ilok.cpp`,
`IlokOpener.cpp`, `ILokConduit_ILokUSB.cpp`, `Ilok1Protocols.cpp`,
`Ilok2Protocols.cpp`, `VerifiedBinaryProtocol.cpp`, `IlokFirmwareException`
and a giant table of `kCMD_*` PACE error codes are all present in the
strings dump. **This is unrelated to USB protocol RE** — it's likely the
license-check wrapper Saleae applies to the DLL to protect against patching.
Caveat the user: many functions in Ghidra will look like control-flow
nonsense because PACE wraps them. The good news is the USB code is
unobfuscated (we can read the `WindowsUsbDevice` methods cleanly in the
strings).

## `graph-interface.node`

- format: PE32+ x86-64 DLL (just renamed `.node` for Node.js convention)
- only **2 exports** — the standard N-API entry points:

| Ordinal | Name                              |
|---------|-----------------------------------|
| 1       | `napi_register_module_v1`         |
| 2       | `node_api_module_get_api_version_v1` |

There is no useful public surface here — the module registers its functions
internally with N-API via `napi_define_properties`. Imports of interest:

```
KERNEL32.dll: LoadLibraryW, GetProcAddress, ...
              (no direct WinUSB symbols — confirms USB is not in this module)
```

So `graph-interface.node` is a **thin wrapper** that loads
`graph_server_shared.dll` via `LoadLibraryW` and exposes its exports to JS.
We do not need to RE this further — its job is identical to the `ffi-napi`
direct-load path in `main.js` (Linux/macOS). The actual N-API binding names
can be found by greping the binary for known function names:
`CreateGraphServer`, `DriveRequest`, `Utils` — see `asar_findings.md`.

## Practical implication for the MCP server

Because the protocol the renderer speaks is **WebSocket to a port owned by
`graph_server_shared.dll`**, we have a second path beyond raw USB RE: we
could ALSO write an MCP that proxies the existing `graph_server_shared.dll`
the way Logic 2 does — load the DLL, call `CreateGraphServer`, talk to it.
But that's basically what Saleae's own SDK already exposes (`saleae` MCP),
so it adds nothing. The point of `saleae_native` is to **skip the DLL
entirely** and talk to the USB device ourselves, which means the
`*_CommandHandler` strings + `WindowsUsbDevice::*` methods are what we
actually need to decode in Ghidra.
