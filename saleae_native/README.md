# saleae_native

MCP server that talks **directly** to a Saleae Logic device over USB.
Bypasses Saleae's Logic 2 application and its `graph_server_shared.dll` --
this is a clean-room driver intended to make the device usable from any
host without the official app installed.

This is the **fifth** MCP server in this repo. It is intentionally separate
from the existing `saleae/` server, which wraps Saleae's official gRPC
automation API and requires Logic 2 to be running. Do not confuse them:

| Server         | Talks to                    | Requires Logic 2? |
|----------------|-----------------------------|-------------------|
| `saleae/`      | Logic 2's gRPC API on :10430| Yes               |
| `saleae_native/` | The Saleae USB device, raw  | No (eventually)   |

## Status

**Skeleton, not functional yet.** What's done:

- [x] Static analysis: `Saleae.inf`, `graph_server_shared.dll` (strings + PE
      exports), `graph-interface.node`, `app.asar` JS bundle. Findings in
      `notes/`.
- [x] Live device descriptor dump (Logic Pro 16, VID `0x21A9` / PID
      `0x1006`, serial `0000000004BE`).
- [x] Identified the wire-protocol surface inside `graph_server_shared.dll`
      (the `*_CommandHandler` family and `WindowsUsbDevice::*` methods).
- [x] MCP server + bridge + driver scaffolding using the same shape as
      `jadx/`, `ilspy/` (HTTP discovery via `~/.saleae_native_mcp/<pid>.json`).
- [x] Tool surface declared: `list_devices`, `device_info`, `start_capture`,
      `stop_capture`, `read_samples`, `set_sample_rate`, `set_channels`,
      `set_voltage_threshold`, `set_digital_out`.

What's pending:

- [ ] Decompile the WinUSB call paths in `graph_server_shared.dll` to
      recover (a) the FX3 boot-mode firmware-load sequence, (b) the
      `bRequest` for `VendorRequest_CommandHandler`, (c) the table of
      `command_id -> *_CommandHandler`, (d) the operating-mode endpoint
      addresses, and (e) the `SetCaptureParameters` payload format.
- [ ] Wire `driver.SaleaeDevice.open()` and the per-command methods.
- [ ] Implement the sample-stream decoder (the device sends
      bulk-IN bursts with periodic "stats packets" --- format TBD).
- [ ] Handle the crypto-chip authentication step
      (`CryptoChipVerify`, `GetPublicKey`). Per the user's reading of
      DMCA 1201(f), we will **not** extract keys; we will document
      the auth surface and either bypass it via firmware patching of
      the side that we control (the host) or skip features that require
      a successful challenge.

## Layout

```
saleae_native/
├── README.md               This file
├── mcp_server.py           FastMCP stdio server (Claude Code talks to this)
├── bridge.py               HTTP bridge process; one per device
├── driver.py               SaleaeDevice -- USB transport layer (skeleton)
└── notes/                  Reverse-engineering findings
    ├── inf_analysis.md     VID/PID table + WinUSB binding from Saleae.inf
    ├── live_device.md      Live descriptor dump (Pro 16, boot-ROM mode)
    ├── dll_protocol_strings.md   Curated strings from graph_server_shared.dll
    ├── exports.md          PE export tables for the DLL and the .node
    ├── asar_findings.md    What we extracted from app.asar (JS layer)
    └── next_steps.md       Concrete Ghidra prompts to run next
```

## Not yet installed in the global MCP config

Don't add `saleae_native` to `claude mcp add` until the driver actually
works. Until then, the MCP server will respond to every protocol call
with `{"error": "not implemented --- protocol RE pending"}` --- useful
for smoke-testing the discovery plumbing but not for capturing logic.

## Driving the next phase from Ghidra

The work is now back in the main Claude Code session:

1. Load `C:\Program Files\Logic\resources\windows-x64\graph_server_shared.dll`
   into Ghidra. Wait for analysis to finish (this is a 63 MB DLL, expect
   30-60 minutes the first time).
2. Verify the `ghidra-mcp` extension is loaded and registered (see
   `python ghidra/mcp_server.py --list`).
3. Drive the queries in `notes/next_steps.md`. They are written as
   ready-to-paste prompts.

## Tests

There are no unit tests yet --- the driver is a skeleton. Once the protocol
is decoded, add tests under `tests/test_saleae_native_server.py` mirroring
`tests/test_jadx_server.py` (FakeBridge fixture, MCP-tool-builds-right-body
assertions). The driver itself can be tested by hand against the device.

## Legal

This work is performed under the DMCA 1201(f) **interoperability** exemption:
the user owns the device and is reverse-engineering only the protocol
necessary for an open driver to interoperate with it. No proprietary
signing keys / DRM bypass artifacts are extracted. The PACE iLok wrapping
in the DLL (`pace_wrapping_*` exports) is documented as present in
`notes/exports.md` but not bypassed --- our driver doesn't load Saleae's
code at all.
