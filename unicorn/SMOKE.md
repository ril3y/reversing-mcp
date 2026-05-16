# Unicorn bridge — live smoke test

A tiny end-to-end check that the bridge launches, maps memory, executes
Thumb instructions, and reports stop reasons correctly. Run on Windows
11 with `unicorn 2.1.4` + `capstone 5.0.6`.

## Setup

```bash
pip install unicorn      # installs 2.1.4
# capstone already present from prior tooling
python unicorn/bridge.py --arch thumb --port 13790 &
```

Output:

```
[unicorn-bridge] arch=thumb port=13790 pid=<pid>
[unicorn-bridge] registered: /home/<user>/.unicorn_mcp/<pid>.json
```

## Program

Four Thumb-16 instructions, hand-encoded:

```
0320     movs r0, #3
0421     movs r1, #4
4018     adds r0, r0, r1
00be     bkpt #0
```

Hex blob: `03200421401800be`

## Session

### /ping

```bash
curl -s http://127.0.0.1:13790/ping
```

```json
{"status": "ok", "arch": "thumb"}
```

### /map_region

```bash
curl -s -X POST http://127.0.0.1:13790/map_region \
  -H "Content-Type: application/json" \
  -d '{"start":"0x0","size":"0x1000","perms":"rwx"}'
```

```json
{"ok": true, "start": "0x0", "size": "0x1000", "perms": "rwx"}
```

### /load_bytes

```bash
curl -s -X POST http://127.0.0.1:13790/load_bytes \
  -H "Content-Type: application/json" \
  -d '{"addr":"0x0","hex":"03200421401800be"}'
```

```json
{"ok": true, "written": 8}
```

### /disasm (sanity check — capstone-Thumb)

```bash
curl -s -X POST http://127.0.0.1:13790/disasm \
  -H "Content-Type: application/json" \
  -d '{"addr":"0x0","size":"0x8"}'
```

```json
{"insns": [
  {"addr": "0x0", "mnemonic": "movs", "op_str": "r0, #3",      "bytes": "0320"},
  {"addr": "0x2", "mnemonic": "movs", "op_str": "r1, #4",      "bytes": "0421"},
  {"addr": "0x4", "mnemonic": "adds", "op_str": "r0, r0, r1",  "bytes": "4018"},
  {"addr": "0x6", "mnemonic": "bkpt", "op_str": "#0",          "bytes": "00be"}
]}
```

### /write_reg pc=0

```bash
curl -s -X POST http://127.0.0.1:13790/write_reg \
  -H "Content-Type: application/json" \
  -d '{"name":"pc","value":"0x0"}'
```

```json
{"ok": true, "name": "pc", "value": "0x0"}
```

### /step count=3

```bash
curl -s -X POST http://127.0.0.1:13790/step \
  -H "Content-Type: application/json" \
  -d '{"count":3}'
```

```json
{"pc": "0x6", "instructions_run": 3}
```

PC is now sitting on the `bkpt`. Three Thumb instructions executed (each 2 bytes; PC: 0 → 2 → 4 → 6).

### /read_reg r0  — the headline check

```bash
curl -s -X POST http://127.0.0.1:13790/read_reg \
  -H "Content-Type: application/json" \
  -d '{"name":"r0"}'
```

```json
{"name": "r0", "value": "0x7"}
```

**r0 == 7** — `movs r0,#3` + `movs r1,#4` + `adds r0,r0,r1` evaluated correctly.

### Bonus: /run_until past the BKPT (crash forensics)

After resetting PC=0 and running with a 10-instruction budget:

```bash
curl -s -X POST http://127.0.0.1:13790/run_until \
  -H "Content-Type: application/json" \
  -d '{"max_instructions":10}'
```

```json
{
  "stopped_reason": "crash",
  "pc": "0x6",
  "instructions_run": 4,
  "last_pc": "0x6",
  "recent_pcs": ["0x0", "0x2", "0x4", "0x0", "0x2", "0x4", "0x6"],
  "error": "Unhandled CPU exception (UC_ERR_EXCEPTION)"
}
```

`stopped_reason: "crash"` with `last_pc=0x6`, and `error: "Unhandled CPU exception (UC_ERR_EXCEPTION)"` — the BKPT raised UC_ERR_EXCEPTION as expected. The recent-PCs ring buffer captured the full instruction trail.

### /snapshot + /list_snapshots

```bash
curl -s -X POST http://127.0.0.1:13790/snapshot -d '{"name":"pre"}'
# {"ok": true, "captured_bytes": 4096, "captured_regions": 1}

curl -s http://127.0.0.1:13790/list_snapshots
# [{"name": "pre", "captured_regions": 1, "captured_bytes": 4096}]
```

### Shutdown

```bash
# Ctrl+C in the foreground (atexit unregisters)
# or kill -TERM <pid> (SIGTERM handler unregisters)
# Note: on Windows, Stop-Process is SIGKILL-equivalent; the registration
# file must be removed manually in that case (the next `discover_instances`
# call also prunes it once the PID is reused or absent).
```

## Result

| Check                         | Outcome |
|-------------------------------|---------|
| `/ping` returns `{arch}`      | OK      |
| `/map_region`                 | OK      |
| `/load_bytes` writes 8 B      | OK      |
| `/disasm` (capstone-Thumb)    | OK      |
| `/step` runs 3 Thumb insns    | OK      |
| **`r0 == 7`**                 | **OK**  |
| `/run_until` past BKPT        | `stopped_reason="crash"`, `error="UC_ERR_EXCEPTION"`, `last_pc=0x6` |
| `/snapshot` captures region   | OK      |
