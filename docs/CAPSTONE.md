# Capstone raw disassembly

The `capstone` provider is a small, read-only, headless decoder for raw bytes
and file regions. It is useful for shellcode, firmware, memory extracts, and
other inputs that do not need a database-backed analysis engine.

## Install and register

Install Capstone into the same Python interpreter used by the MCP registration:

```powershell
python install.py --tools capstone --scope user --clients claude,codex
```

Restart each client after registration so it reloads the provider catalog.

## Raw ARM Cortex-M file

Open a firmware image and declare the load address and instruction mode:

```json
{
  "provider": "capstone",
  "target_path": "C:\\samples\\firmware.bin",
  "mode": "headless",
  "options": {
    "architecture": "arm",
    "mode": ["thumb", "mclass"],
    "endian": "little",
    "base_address": "0x08000000"
  }
}
```

Pass the returned `session_id` to `invoke`:

```json
{
  "session_id": "<session-id>",
  "operation": "analysis.disassemble",
  "arguments": {
    "address": "0x08000100",
    "size": 256,
    "count": 64
  }
}
```

`address` is translated to a file offset using `base_address`. Use
`file_offset` instead when the file layout is not a flat memory image. The two
selectors are mutually exclusive. Reads and disassembly are bounded to 1 MiB
per call; instruction output is bounded to 10,000 entries.

## Inline bytes

A target file is optional. Open a session with the architecture options above,
then supply compact or separated hexadecimal bytes:

```json
{
  "session_id": "<session-id>",
  "operation": "analysis.disassemble",
  "arguments": {
    "data": "00 b5 01 20 00 bd",
    "address": "0x08000000"
  }
}
```

Use `capstone.architectures.list` to inspect the architectures and named modes
available in the installed Capstone build. Architecture, mode, endianness,
engine version, input digest, decoded-byte count, and undecoded-byte count are
returned with every result.

## Capability boundary

Capstone decodes instructions but does not load executable formats, discover
functions, build control flow, resolve cross-references, decompile, or maintain
annotations. It therefore exposes `open`, `close`, `target.info`,
`analysis.disassemble`, and—on file-backed sessions—`memory.read`. Use Ghidra,
IDA, Binary Ninja, or radare2 when database-backed analysis is required.
