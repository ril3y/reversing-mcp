# Android bundles, Bluetooth LE, and protocol tools

These operations use the same `open_session` → `invoke` → `close_session`
convention as the native providers.

## APK, XAPK, and bundled JavaScript

Open an APK or XAPK with `provider="jadx"`. An XAPK's primary APK is selected
for JADX while all root and nested members remain addressable. Nested paths use
`outer.apk!/path/inside.apk` notation.

Useful operations are:

| Operation | Important arguments |
|---|---|
| `artifact.entries.list` | `prefix`, `suffix`, `limit`, `nested` |
| `artifact.files.extract` | `path` or `paths`; optional `output_directory`, `overwrite` |
| `source.search` | `query`, optional `paths`, `regex`, `case_sensitive`, `context_chars`, `limit` |
| `source.pretty` | `path` plus `module_id`, `function`, `line`, or `offset` |
| `android.framework.detect` | none |
| `android.uniapp.inspect` | none |

Search reports the exact nested path, one-based line and column, character
range, matched text, and bounded context. A source view uses an installed
`prettier` command (or `PRETTIER_COMMAND`) when available and falls back to the
built-in non-executing formatter. JavaScript is parsed as text and never run.

DCloud detection recognizes `assets/apps/<app-id>/www`, reads JSON page
manifests when present, finds page registrations in `app-service.js`, and lists
webpack IDs or source-location hints such as `utils/BLE.ts`. Detection evidence
and class-search results are returned separately.

Extraction is safe against traversal paths. Omitting `output_directory` puts
selected files under a session-owned temporary directory that is deleted on
close. An explicit output directory makes the result persistent and refuses to
overwrite existing files unless `overwrite=true`.

## Bluetooth LE

Open `provider="bluetooth_le"`. `target_path` may be a BLE address or left
empty until `ble.connect`.

| Operation | Purpose |
|---|---|
| `ble.scan` | Discover devices and advertisements for a bounded timeout |
| `ble.connect` / `ble.disconnect` | Manage one owned GATT connection |
| `ble.services.list` | List services, characteristics, descriptors, and properties |
| `ble.subscribe` / `ble.unsubscribe` | Capture characteristic notifications |
| `ble.read` / `ble.write` | Exchange explicit byte sequences |
| `ble.transcript.get` | Page timestamped scan, lifecycle, RX, and TX events |
| `ble.transcript.save` | Explicitly save JSON or JSONL to a chosen path |
| `ble.transcript.clear` | Clear the in-memory capture |

Byte inputs accept compact or separated hex, byte lists, or bytes. Every data
event includes an absolute UTC timestamp, monotonic elapsed milliseconds, hex,
base64, size, direction, and characteristic. Closing disconnects the peripheral;
it does not save a transcript implicitly.

## Checksums, Modbus RTU, and register maps

Open `provider="protocol"` for offline work, or invoke the same operations on a
Bluetooth session:

- `protocol.checksum.detect` tests Modbus, ARC, CCITT-FALSE, X25, CRC-8,
  sum-8, LRC-8, and XOR-8 against one or more complete frames.
- `protocol.checksum.verify` checks a selected algorithm and byte order.
- `protocol.modbus.decode` validates an RTU CRC and decodes common read/write
  requests, responses, registers, bits, and exception frames. Use `direction`
  when a short frame is structurally ambiguous.
- `protocol.registers.decode` applies a caller-supplied register map with
  addresses, integer/float/string/BCD types, byte and word order, scaling,
  offsets, and units.

These helpers validate a hypothesis against supplied bytes; they do not by
themselves establish that a device implements Modbus or that a register-map
meaning is correct.

## REA interoperability

REA's Android adapter and this repository's JADX provider use different bridge
protocols. Keep their environment variables separate:

- `JADX_MCP_BRIDGE_JAR` selects this repository's `jadxmcp` bridge.
- `REA_JADX_MCP_JAR` must select the upstream
  `jadx-headless-mcp-0.7.1-all.jar` expected by REA. Do not point it at this
  repository's bridge JAR.
- `REA_ADB_PATH` selects an absolute path to `adb` for REA device workflows.
- `JAVA_HOME` must select a full JDK, not a JRE, for REA's Android source
  bridge.

Both MCP registrations can coexist because each server receives its own
environment. Validate REA's side with
`rea doctor --client <client> --provider jadx --json` after registration.
