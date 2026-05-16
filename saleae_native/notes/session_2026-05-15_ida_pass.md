# Session 2026-05-15 — first IDA-driven RE pass on `graph_server_shared.dll`

Logic 2 install at `C:\Program Files\Logic\`. Target binary:
`resources\windows-x64\graph_server_shared.dll` (172 MB, 105,281 functions
auto-recognized, no PDB).

## Bridge / setup state

- IDA Pro 8.4 with Hex-Rays 8.4.0.240527 loaded the DLL.
- `ida/plugin.py` installed persistently at
  `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp_plugin.py`. Auto-starts on
  IDB load; toggle via `Ctrl+Shift+M`. IDB is saved
  (`graph_server_shared.i64` alongside the DLL).
- Bridge registers on port 13337 (`~/.ida_mcp/<pid>.json`).
- **Common.py bug fixed mid-session**: `os.kill(pid, 0)` was killing live
  processes on Windows via `TerminateProcess`. Replaced with
  `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`. Regression test in
  `tests/test_common.py::test_pid_alive_does_not_signal_live_target`.

## Confirmed function addresses (carry forward)

### USB transport layer (`WindowsUsbDevice`)

| Function | Address | Notes |
|----------|---------|-------|
| `WindowsUsbDevice::Write(UsbEndpoint&, u8*, u32, bool, const char*)` | `0x1814C4AA0` | Decompiled. Wraps `WinUsb_SetPipePolicy(timeout=1000ms) → WinUsb_WritePipe → SetPipePolicy(0)`. |
| `WindowsUsbDevice::Read` (synchronous) | `0x1814B8E10` | 879 B, same SetPipePolicy/ReadPipe/SetPipePolicy pattern. |
| Stream-read thread (mutex + condvar + perf_counter) | `0x1814B81B0` | 3 KB, producer/consumer queue. |
| Payload encoder (caller-buffer → transport frame) | `0x1814C97D0` | Called from Write only. Three sub-encoders at `0x1814C9A30 / 0x1814CB210 / 0x1814CDE80`. |

Class field offsets (`a1` = `WindowsUsbDevice*`):
- `+40` — encoder context pointer
- `+116` — 4-byte field (sequence number? mode bits?)
- `+176` — `WINUSB_INTERFACE_HANDLE`
- `+184` — bool init-flag (set by `Open`)

Source path leaked from assertion strings:
`monorepo\graph-io\devices\usb_device\src\WindowsUsbDevice.cpp`.

### `Logic2FpgaDevice` (device class)

| Method | Address | Size | DRM? |
|--------|---------|------|------|
| `CryptoChipVerify` | `0x1807D6EE0` | 5,297 B | **iLok-virtualized** (only 2 callees: std::string ctor + assert helper) |
| `WriteAd9637Register(u16, u16)` | `0x1807EB510` | 1,521 B | Normal C++ |
| `InitHmcad1100(Hmcad1100Settings)` | `0x1807DC4C0` | 517 B | Normal C++ (likely) |
| `FakeReadThread` (simulator path) | `0x1807D83A0` | 5,530 B | Normal — calls `SimulationChannelDescriptor::*`, NOT the real device path |

All Logic2FpgaDevice methods cluster in `0x1807D0000–0x1807F0000`.

Strings catalogue at `0x1823F05C0..0x1823F1xxx` includes 13+ method
signatures from `Logic2FpgaDevice.cpp` — see `dll_protocol_strings.md`.

### FX3 firmware vendor-command names

~50 `*_CommandHandler` strings packed densely at `0x1834A6476..0x1834A6AD2`
(in `.rdata`). Full inventory in `dll_protocol_strings.md`. These are the
*host's* knowledge of the FX3 dispatch table by string — the host calls
them by ID, not name. To recover the IDs we either:

1. Find a host helper that prints `cmd_id → name` for logging (none seen
   yet; the strings aren't xref'd from a single dispatch printer).
2. Reverse the FX3 firmware itself (dumped from flash via firmware-load
   USB sequence, or pulled from a Logic 2 install package).
3. USBPcap a live capture and reconstruct IDs from observed traffic.

## What we couldn't get past

- **`UsbDevice::Write` is a virtual method**. Direct xrefs find only the
  vtable slot at `0x183B38FE4`, not the 50+ command-builder callers. The
  vtable is in a PACE-style 32-bit-RVA table format, not a normal C++
  vtable — reversing through it requires walking the dispatch indirection
  by hand or with a script.
- **C++ symbol demangling is partial** — `search_functions` returns empty
  for `Logic2Fpga`, `SetCaptureParameters`, etc. RTTI demangling appears
  in `callees` lists (we saw `SimulationChannelDescriptor::*`) but isn't
  surfaced through the name index. Likely an IDA setting / auto-analysis
  pass that hasn't completed.
- **`CryptoChipVerify` is iLok-virtualized** — 5 KB function body with 2
  direct callees means the code is interpreted from a data table. Skip
  it for static RE.
- **Bridge has no `/auto_status` or `/log_tail`** — we had to guess
  whether silent xref responses meant "no refs" or "indexing in
  progress". Adding these endpoints is the highest-impact bridge
  improvement.

## Recommended next move

**USBPcap during a Logic 2 capture session.** Install USBPcap, start
Wireshark, plug in the Saleae, launch Logic 2, run one short capture,
stop. The captured pcap will contain:

- The firmware-upload control transfers (Cypress FX3 boot ROM → operational
  firmware), revealing the `bmRequestType / bRequest / wValue / wIndex`
  for `LoadFirmware`.
- The FPGA bitstream upload (vendor command stream).
- The post-init vendor-command sequence (start-of-capture handshake).
- The bulk-IN data stream framing.

Cross-reference the captured byte sequences against the names from
`dll_protocol_strings.md` and we have a working command table without
needing to push through iLok. With the bridge findings in hand we can
even predict which control transfer is which.

## Alternative paths

- **sigrok**: `libsigrok/src/hardware/saleae-logic-pro/` already RE'd
  this device in 2018-19. Reuse rather than re-derive.
- **FX3 firmware dump**: extract the firmware blob from the Logic 2
  install (it's somewhere in `app.asar.unpacked` per `asar_findings.md`).
  The FX3 firmware contains the dispatch table *with* command IDs, not
  just the names.

## Files / state preserved

- IDB: `C:\Program Files\Logic\resources\windows-x64\graph_server_shared.i64`
  (next IDA launch with the persistent plugin will resume right here).
- Bridge plugin: `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp_plugin.py`.
- All addresses in this doc are stable across IDA restarts (image base
  fixed by PE optional header).

## Bridge improvements to ship before next pass

Two small additions to `ida/plugin.py` that would have saved us time:

1. **`GET /auto_status`** — returns `{auto_running, current_pass}` via
   `ida_auto.auto_is_ok()` + `ida_auto.get_auto_state()`. Lets callers
   know whether empty xrefs mean "no refs" or "still indexing".
2. **`GET /log_tail?lines=N`** — returns the last N lines from the IDA
   Output window via `ida_kernwin.msg_get_lines()`. Useful when Hex-Rays
   pops a modal we can't see and the bridge appears hung.

Both are ~15 LOC each and match the existing handler pattern.
