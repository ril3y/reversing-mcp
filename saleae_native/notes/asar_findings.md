# Asar archive findings

Archive: `C:\Program Files\Logic\resources\app.asar` (130 MB, 5 925 files)

Format (verified by direct read):

```
[u32 LE = 4]          // pickle header size (always 4)
[u32 LE = totalSize+8]
[u32 LE = headerJsonSize + 4]
[u32 LE = headerJsonSize]
[headerJsonSize bytes of UTF-8 JSON header]
[file payloads, indexed by offset/size in header]
```

The JSON header is a recursive `{"files": {name: <node>}}` tree; leaves have
`{size, offset, [unpacked]}`. We extract only `dist/main.js` and
`dist/logic/bundle.js` (the smallest paths that touch the device protocol).
Extraction dir lives in temp, not committed.

## Native modules live OUTSIDE the asar

```
resources/
├── app.asar                                 (the JS we just unpacked)
└── app.asar.unpacked/
    └── node_modules/@saleae/graph-interface/
        └── bin/win32-x64-118/graph-interface.node    <- THE BRIDGE
```

Anything that has to be loaded via `dlopen`/`LoadLibrary` ends up in
`.unpacked/` — that's why the `.node` is there and not in the archive.

## What `main.js` does on startup (Electron main process — 28 kB, unminified-ish)

Key fragment (slightly reformatted):

```js
const h = path.join(getLibsPath(), getPlatformArch(),
                    platform === 'win32' ? 'graph_server_shared.dll'
                                         : 'libgraph_server_shared.*');

if (launchArgs.useExistingGraph) {
    f.searchParams.append('logic_websocket', `127.0.0.1:${s}`);
}
else if (Utils.needsOutOfProcessBackend()) {
    const { serverPort, disconnect, flushLog } = startGraphServer({
        port: s, graphDllPath: h, pythonHomePath: C(),
        logFileName: getCurrentLogName(), electronIsDev: p,
    });
    f.searchParams.append('logic_websocket', `127.0.0.1:${serverPort}`);
}
else {
    // in-process mode (Win32 only takes this branch)
    f.searchParams.append('logic_shared_path', h);
    f.searchParams.append('python_home_path', C());
}
```

Then `startGraphServer` itself (also in `main.js`):

```js
exports.startGraphServer = ({port, graphDllPath, ...}) => {
    if (process.platform === 'win32') throw new Error('not supported');
    if (process.platform === 'linux') throw new Error('not supported');

    const ref = require('ref-napi');
    const ffi = require('ffi-napi');
    const lib = ffi.Library(graphDllPath, {
        CreateGraphServer:  ['pointer', ['int*', 'int', 'bool']],
        DestroyGraphServer: ['void',    ['pointer']],
        SetLogFileName:     ['void',    ['string']],
        FlushLog:           ['void',    []],
    });
    lib.SetLogFileName(logFileName);
    const portRef = ref.alloc('int'); portRef.writeInt32LE(port, 0);
    const handle = lib.CreateGraphServer(portRef, 100, electronIsDev);
    return { serverPort: ref.deref(portRef), disconnect: ..., flushLog: ... };
};
```

**Takeaways:**

1. The C function signature is now confirmed:
   ```c
   void* CreateGraphServer(int* port_inout, int max_clients_or_buffer, bool dev_mode);
   ```
   (The second arg literally `100` — probably max clients or queue depth.)
2. macOS uses the out-of-process WebSocket path; **Win32 + Linux load the DLL
   in-process** inside the renderer (`logic_shared_path` query param). The
   N-API binding for that path lives in `graph-interface.node`.
3. Either way the front-end speaks **WebSocket on `ws://127.0.0.1:<port>/saleae`** — the same wire format in both modes (the in-process path just runs the WS server inside the renderer).

## What `bundle.js` reveals (renderer — 14 MB minified)

`require("@saleae/graph-interface").Utils` is the only JS-visible binding.
The class that owns the connection is one big graph-socket abstraction:

```js
connect(A) {
    return A.mode === "websocket"
        ? this.graphSocket.connect(A.url, ...)
        : ...      // direct mode
}
// elsewhere:
new ConnectArgs({
    mode: A.websocketAddress ? "websocket" : "direct",
    url: A.websocketAddress ? `ws://${A.websocketAddress}/saleae` : ...,
    graphServerSharedPath: A.graphServerSharedPath,
    pythonHomePath:        A.pythonHomePath,
    logFileName:           A.logFileName,
})
```

So the **endpoint URL is `/saleae`** under whichever loopback port
`graph_server_shared.dll` opens.

We did **not** find any of:

- raw USB VID/PID literals (`0x21A9`, `0x1006`) in JS — none. **All USB
  enumeration is inside the DLL.**
- a packet schema / Protobuf definition in JS — none. The graph-socket
  payload is opaque from the renderer's perspective.
- `WinUsb_*` references — none. Confirms JS never touches USB directly.

The only structured-API surface we *did* find is the **gRPC automation
interface** at the well-known Saleae port (`automationPort: 10430` default,
arg `--automationPort=N`):

```
/saleae.automation.Manager/GetAppInfo
/saleae.automation.Manager/GetDevices
/saleae.automation.Manager/StartCapture
/saleae.automation.Manager/StopCapture
/saleae.automation.Manager/WaitCapture
/saleae.automation.Manager/CloseCapture
/saleae.automation.Manager/SaveCapture
/saleae.automation.Manager/LoadCapture
/saleae.automation.Manager/AddAnalyzer
/saleae.automation.Manager/RemoveAnalyzer
/saleae.automation.Manager/AddHighLevelAnalyzer
/saleae.automation.Manager/RemoveHighLevelAnalyzer
/saleae.automation.Manager/LegacyExportAnalyzer
/saleae.automation.Manager/ExportDataTableCsv
/saleae.automation.Manager/ExportRawDataBinary
/saleae.automation.Manager/ExportRawDataCsv
```

These are the methods that the **existing** Saleae MCP server (the official
one, in this repo at `saleae/`) wraps. They require Logic 2 to be running.
The whole point of `saleae_native` is to NOT require Logic 2, so this
endpoint is documented here only to disambiguate: **it is not what we're
RE-ing.**

## Conclusion: the JS code is a dead-end for protocol RE

All USB / FPGA / firmware-load logic is in `graph_server_shared.dll`. The JS
side just speaks a thin command-response protocol over `/saleae` WS to the
DLL. To skip the DLL we must decode the underlying WinUSB transfers in
Ghidra against `graph_server_shared.dll` — see `notes/next_steps.md`.
