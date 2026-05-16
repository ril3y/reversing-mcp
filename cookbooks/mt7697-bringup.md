# MT7697 firmware bring-up — example composition

A worked example of using the **generic** Unicorn bridge to start
emulating a MediaTek MT7697 firmware image. The bridge itself knows
nothing about MT7697 — flash layout, vector table location, MMIO ranges,
and everything else below is composed from the generic primitives
(`map_region`, `load_bytes`, `add_hook`, `run_until`). The same recipe
shape works for any Cortex-M target; only the addresses change.

> **Do not** add a `boot_mt7697` or `init_cortex_m` endpoint to the
> bridge. Each step below is an MCP tool call; reordering or substituting
> any of them is a normal user action, not a code change.

## Target

- Firmware blob: `X:\Projects\reversing\pwn2own-amazon.rep\w25q32jv_dump.bin`
  (32 Mbit SPI-NOR flash dump, memory-mapped at `0x10000000`)
- CPU: Cortex-M4 (ARMv7-M, Thumb)
- Suspected reset vector: `0x10000081` (Thumb bit set)
- SRAM: `0x20000000`, 256 KB
- Peripherals: somewhere in `0x40000000` – `0x80000000` (Cortex-M PPB +
  vendor MMIO; specifics unknown until first crash dictates)

## 0. Launch the bridge

```bash
python unicorn/bridge.py --arch thumb --port 13790
```

One terminal, one bridge, one arch. No firmware path on argv — that's
loaded over MCP next.

## 1. Map flash and SRAM

```jsonc
// MCP tool: map_region
{"start": "0x10000000", "size": "0x00400000", "perms": "rx"}   // 4 MiB flash, RX
{"start": "0x20000000", "size": "0x00040000", "perms": "rw"}   // 256 KiB SRAM, RW
{"start": "0x00000000", "size": "0x00010000", "perms": "rwx"}  // bootrom / vector alias (some Cortex-M parts alias here)
```

`map_region` is pure: it lays out address ranges with permissions. It
does not know "flash" from "RAM"; the user knows.

## 2. Load the flash image

```jsonc
// MCP tool: load_file
{"addr": "0x10000000", "path": "X:\\Projects\\reversing\\pwn2own-amazon.rep\\w25q32jv_dump.bin"}
```

The bridge `read()`s the file on the host and `mem_write`s it into the
already-mapped region. If the region was never mapped, this fails with
a clear error — by design.

## 3. Broad MMIO stub for the entire peripheral window

Before we know which peripherals matter, return `0xFFFFFFFF` for every
read in the Cortex-M peripheral window. That makes "is-ready" polls
loop-exit-true, "is-error" flags set, and every unknown register read
non-zero — which is usually enough to limp past the boot loop and reach
real code.

```jsonc
// MCP tool: add_hook
{
  "type": "mem_read",
  "range": "0x40000000-0x80000000",
  "action": "stub",
  "value": "0xFFFFFFFF"
}
```

Internally the bridge uses `Uc.mmio_map` over the page-aligned span. The
read callback ignores the offset and returns the configured constant
truncated to the access size. Writes inside the stubbed region are
silently dropped.

## 4. Set the PC and run

```jsonc
// MCP tool: write_reg
{"name": "sp", "value": "0x20040000"}              // top of SRAM (M-profile stack grows down)
{"name": "pc", "value": "0x10000081"}              // reset vector, low bit = Thumb (bridge strips/encodes)

// MCP tool: run_until
{"max_instructions": 200000, "timeout_ms": 5000}
```

The bridge encodes the Thumb-state bit on `emu_start` automatically when
`--arch thumb`; user-facing PC values are the plain address.

Likely outcomes:

| `stopped_reason`     | Meaning                                        |
|----------------------|------------------------------------------------|
| `instruction_budget` | Budget exhausted — maybe stuck in a poll loop  |
| `timeout_or_normal`  | Wall-clock cap hit                             |
| `crash`              | UcError; `error`, `last_pc`, `recent_pcs` set  |
| `reached_pc`         | We supplied a target PC; we got there          |

## 5. Inspect and narrow

Whatever stopped us, dump state:

```jsonc
// MCP tool: info        -> {arch, regions, pc, recent_pcs, instructions_run, ...}
// MCP tool: list_hooks
// MCP tool: read_reg    {"name": "lr"}
// MCP tool: disasm      {"addr": "<pc-16>", "size": "0x40"}
// MCP tool: read_mem    {"addr": "<sp>", "size": "0x80"}
```

Typical patterns and the narrower stub each one motivates:

- **Spinning on `0x40000FFC`** — likely a "device ready" bit. Replace
  the broad stub with `0xFFFFFFFF` for that page only, and `0x00000000`
  elsewhere in `0x40000000-0x4000F000`:

  ```jsonc
  // remove the broad hook
  {"id": <broad_hook_id>}                          // -> remove_hook

  // page-specific stub
  {"type": "mem_read", "range": "0x40000000-0x40000FFF", "action": "stub", "value": "0x00000000"}
  {"type": "mem_read", "range": "0x40000FFC-0x40000FFF", "action": "stub", "value": "0xFFFFFFFF"}
  ```

- **Hitting an SVCall handler we don't care about** — function-skip via
  `code+stub`. Reads LR, writes `return_value` into r0, jumps to LR:

  ```jsonc
  {"type": "code", "range": "0x10001234", "action": "stub", "return_value": "0x0"}
  ```

- **Calling a hardware-init routine that won't return** — break before
  it instead and route around it manually:

  ```jsonc
  {"type": "code", "range": "0x10005000", "action": "break"}
  ```

- **Lost track of where it is** — turn on block tracing for the whole
  flash window:

  ```jsonc
  {"type": "block", "range": "0x10000000-0x10400000", "action": "trace"}
  ```

  then `info` periodically to read the block-trace ring.

## 6. Snapshot before risky steps

Before any speculative stub or write that might wedge state:

```jsonc
// MCP tool: snapshot {"name": "pre_isr_dispatch"}
// ... do the experiment ...
// MCP tool: restore  {"name": "pre_isr_dispatch"}
```

Snapshots capture every non-MMIO mapped region (flash bytes, SRAM
contents) plus the register file. They do **not** capture hooks or the
region map — those are harness, not state.

## Why this is a recipe and not a feature

Nothing in the bridge knows that `0x10000000` is "flash" or that
`0x40000000` is "peripherals" or that `0x20040000` is the right initial
SP for this part. A different target — an STM32, a Renesas RA, a Telink
TLSR — uses the same six tool calls with different constants. That's
the design.

If you find yourself wanting to add a `bridge.py` endpoint named after
this target, write a wrapper script that issues these MCP calls
instead.
