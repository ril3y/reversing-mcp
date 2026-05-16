# Next steps -- driven from the main Claude Code session via the Ghidra MCP

## Setup (one-time, manual)

1. Open Ghidra. Create a new project (or reuse).
2. **File > Import File** -> `C:\Program Files\Logic\resources\windows-x64\graph_server_shared.dll`.
   - Format: Portable Executable (PE)
   - Language: `x86:LE:64:default`
   - Compiler: `windows`
3. Open the imported file in the CodeBrowser. Accept the auto-analysis
   defaults plus enable **"Decompiler Parameter ID"** and **"PDB Universal"**
   (Saleae ships no PDB but the option is cheap). Click **Analyze**.
   Expect 30-60 minutes on first analyze; the binary is 63 MB.
4. Confirm the Ghidra-MCP bridge is registered:
   ```bash
   python3 ghidra/mcp_server.py --list
   ```
   You should see one instance pointing at `graph_server_shared.dll`.

## Caveats Claude should know about

Before driving queries, the main session must internalize three things:

1. **PACE iLok obfuscation is present.** The DLL exports
   `pace_wrapping_ca/_cz/_d/_fc/_fi/_ia/_iz` and contains the giant
   `kCMD_*` PACE error-code table. Any function whose decompile looks
   like spaghetti with weird jump-tables and `pace_*` calls is wrapped
   --- skip past it and use the *callers* of the wrapper functions to
   find the real logic. The USB path (`WindowsUsbDevice::*`) is **NOT**
   wrapped --- those should decompile cleanly.

2. **Heavy C++ name mangling.** Lots of `??$RegisterPipeHandler@U...@Z`
   style symbols. Ghidra's Microsoft demangler handles them but the
   resulting names are still long. Prefer searching by the unique
   middle of the name (e.g. `VendorRequest_CommandHandler` not the full
   mangled form).

3. **Source filenames are embedded as string constants.** Cross-refs to
   the literal `"WindowsUsbDevice.cpp"`, `"fpga_gpif.cpp"`,
   `"LogicProfessionalDevice.cpp"`, etc. are an excellent anchor because
   they're used in log-statement formatters --- you get pinned to the
   exact translation-unit a function belongs to.

## First five prompts (paste these into the main Claude Code session)

These assume `ghidra-mcp` is the active MCP server with
`graph_server_shared.dll` loaded.

### Prompt 1 -- Map the WinUSB API surface

```
Use the ghidra mcp to find every function in graph_server_shared.dll that
calls WinUsb_WritePipe, WinUsb_ReadPipe, WinUsb_ControlTransfer, or
WinUsb_QueryPipe. Use search_functions / search_strings to locate them,
then xrefs_to on each WinUsb_* import thunk. Group the callers by which
C++ class they're a method of (WindowsUsbDevice::BulkRead, BulkWrite,
SendControlTransfer, etc.) and list each method's address. We want the
exact entry points for the bulk-IN data stream and the
control/command path.
```

### Prompt 2 -- Recover the FX3 vendor-command dispatch table

```
Find the function called VendorRequest_CommandHandler (or the function
that calls into the string literal "VendorRequest_CommandHandler" and
the strings "ILLEGAL_CMD" and "BAD_CMD_ARG"). It almost certainly
contains a switch statement that maps a 1- or 2-byte command id onto
specific handler functions. Decompile it. Each case should reach a
"*_CommandHandler" sub-function -- list the (command_id, handler_name)
pairs you can recover. The full list of handler names is in
saleae_native/notes/dll_protocol_strings.md.
```

### Prompt 3 -- Decode SetCaptureParameters / StartSampling

```
Decompile LogicProfessionalDevice::SendStartRecordingCommand and
Logic2FpgaDevice::SetCaptureParameters. We need the serialized byte
layout that ends up in the USB bulk-out (or control transfer) buffer:
what fields, in what order, what sizes. Cross-reference any FPGA
register addresses with the strings in fpga.cpp / fpga_gpif.cpp --
they likely reference named registers. Output the layout as a C
struct or a Python struct.pack format string.
```

### Prompt 4 -- Find the post-firmware-load endpoint addresses

```
Find the function FpgaDeviceFeatures::DownloadBitstream and trace its
callers up to the device-open path. We need to know:
  (a) the exact USB control-transfer (bmRequestType, bRequest, wValue,
      wIndex) used to upload the FX3 ARM firmware,
  (b) the same for the Lattice FPGA bitstream that follows,
  (c) what bulk endpoint addresses (0x01, 0x82, etc) the device exposes
      AFTER firmware load. Look for hardcoded UCHAR/uint8 constants
      near WinUsb_QueryPipe and WinUsb_ReadPipe calls in
      WindowsUsbDevice methods, or in the device constructor.
Output endpoint addresses as a table: name, address, direction,
transfer-type, max-packet-size.
```

### Prompt 5 -- Sample-stream framing

```
Strings reference FpgaConstants::SamplesPerPacketMultiple_WithStats and
"BulkReadStream_Read_Ep{:0x}". Find Logic2FpgaDevice::FakeReadThread and
LogicAnalyzerDevice::StartReadStream, decompile them, and explain the
packet framing on the bulk-IN data endpoint. We need to know how to tell
a "sample data" packet apart from a "stats" packet, what the timestamp
header looks like, and whether RLE/transition-only encoding is in use
(the strings reference "ChunkedArray<unsigned __int64>" which is
suspicious of transition timestamps).
```

## Anticipated obstacles and workarounds

- **Crypto chip auth (`CryptoChipVerify` / `GetPublicKey`):** likely a
  challenge-response with an ATSHA204A or ATECC508A over I2C. If the
  device refuses to stream until challenge succeeds, two options:
  (a) replay a recorded successful response (per-device, not portable;
  per-session may work since we own this device), or (b) skip features
  that require it (basic digital capture probably works without crypto;
  analog/MSO might not). Decide after Prompt 3 reveals where in the open
  sequence the verify happens.
- **PACE-wrapped functions:** if the dispatcher in Prompt 2 turns out to
  be wrapped, walk callers further -- the wrap is per-function, not
  per-translation-unit. Or read the device-side strings carefully:
  many `*_CommandHandler` names are descriptive enough to guess
  ordering (e.g. `Batch_CommandHandler` is probably command 0x00 since
  batching is the meta-command).
- **C++ vtable noise:** Ghidra may auto-name everything `FUN_180xxxxx`;
  use `rename` aggressively via the MCP to make progress visible.

## After prompts 1-5

By the time those five prompts are answered we should have enough to
write the first real version of `driver.SaleaeDevice.open()` +
`_send_command()`. Stage 6+ work (resume from here):

6. Implement `driver.open()` -> bring device up to "ready to capture" state.
7. Smoke test: `device_info()` round-trip via the MCP.
8. Implement `start_capture` / `read_samples` / `stop_capture` against
   the framing we recovered.
9. Add tests against an in-process mock device (FakeBridge style).
10. Document the protocol in a public `PROTOCOL.md` and decide whether
    to upstream the findings to a community Saleae driver repo
    (sigrok already has partial support for the FX2 family; this work
    adds FX3 / Pro family which sigrok doesn't have).
