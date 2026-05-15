# reversing-mcp

MCP servers that give Claude Code direct access to IDA Pro and Ghidra. Disassemble, decompile, rename, comment, search, and navigate binaries without leaving your terminal.

## Quick Start (Claude Code)

### 1. Install Python dependencies

```bash
pip install mcp httpx
```

### 2. Add to your MCP config

**One-liner** (adds both servers to your global Claude Code config):

```bash
claude mcp add -s user ghidra -- python3 /path/to/reversing-mcp/ghidra/mcp_server.py && \
claude mcp add -s user ida -- python3 /path/to/reversing-mcp/ida/mcp_server.py
```

Or manually add to `~/.claude/.mcp.json`:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python3",
      "args": ["/path/to/reversing-mcp/ghidra/mcp_server.py"]
    },
    "ida": {
      "command": "python3",
      "args": ["/path/to/reversing-mcp/ida/mcp_server.py"]
    }
  }
}
```

Replace `/path/to/reversing-mcp` with the actual clone path. You only need the servers for tools you use.

### 3. Install the in-tool bridge

You need a bridge running inside each RE tool so the MCP server can talk to it.

#### Ghidra (Extension — recommended)

The extension auto-starts the bridge when you open a program. No manual script launching needed.

```bash
cd ghidra/ghidra-mcp-bridge
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew
```

Then in Ghidra: **File > Install Extensions > +** and select the ZIP from `ghidra/ghidra-mcp-bridge/dist/`. Restart Ghidra.

#### Ghidra (Script — alternative)

If you prefer not to install an extension, copy `ghidra/bridge.java` to your `ghidra_scripts/` directory and run it from the Script Manager. The script blocks with a dialog — click "No" to stop the server.

#### IDA Pro

```bash
# Symlink plugin into IDA (starts automatically on load)
ln -sf "$(pwd)/ida/plugin.py" ~/.idapro/plugins/ida_mcp_plugin.py
```

### 4. Use it

Open a binary in Ghidra or IDA, then ask Claude Code to analyze it:

```
> decompile the function at 0x80001000
> what does main() do?
> find all callers of send_packet
> rename 0x80004500 to parse_header
```

## Architecture

```
Claude Code  ←stdio→  mcp_server.py  ←HTTP→  bridge inside RE tool
                           │
                      common.py (shared discovery)
```

Each RE tool runs an HTTP server that registers itself in `~/.<tool>_mcp/` (e.g., `~/.ghidra_mcp/`, `~/.ida_mcp/`). The MCP servers discover running instances automatically. Multiple instances of the same tool (different binaries) are supported — use the `program`/`idb` parameter to target a specific one.

```
reversing-mcp/
├── common.py                       Shared instance discovery + HTTP proxy
├── ghidra/
│   ├── bridge.java                 GhidraScript bridge (runs inside Ghidra)
│   ├── GhidraMcpPlugin.java       ProgramPlugin bridge (auto-starts)
│   ├── ghidra-mcp-bridge/          Ghidra extension (Gradle project for the plugin)
│   └── mcp_server.py              MCP stdio server for Claude Code
├── ida/
│   ├── plugin.py                   IDA plugin (runs inside IDA)
│   └── mcp_server.py              MCP stdio server for Claude Code
```

## Available Tools

Both servers expose the same core set of tools:

| Tool | Description |
|------|-------------|
| `list_instances` | List active tool instances and loaded binaries |
| `idb_info` | Program info (function count, segments, processor, bitness) |
| `get_function` | Get function by address or name |
| `disassemble` | Disassemble a function or address range |
| `decompile` | Decompile to C pseudocode (Ghidra decompiler / Hex-Rays) |
| `xrefs_to` | Cross-references to an address |
| `xrefs_from` | Cross-references from an address |
| `get_callers` | Functions that call a given function |
| `get_callees` | Functions called by a given function |
| `search_functions` | Search function names by substring |
| `search_strings` | Search strings by substring |
| `get_segments` | List memory segments |
| `get_bytes` | Read raw bytes at an address |
| `rename` | Rename a function or address |
| `add_comment` | Add a comment at an address |
| `create_function` | Create a function at an address |
| `delete_function` | Delete a function |

IDA additionally has `make_code` and `find_micromips_prologues`.

## Multi-Instance Support

If you have multiple binaries open (e.g., two Ghidra windows), pass the program name to target a specific one:

```
> decompile main in firmware.bin
> list all ghidra instances
```

The MCP server resolves instances by substring match on the program/IDB name.

## Troubleshooting

**"No Ghidra/IDA instances found"** — The bridge isn't running. For Ghidra, make sure the extension is installed and a program is open. For IDA, check the plugin loaded (Output window should show the MCP port).

**Check active instances manually:**

```bash
python3 ghidra/mcp_server.py --list
python3 ida/mcp_server.py --list
```

**Registration files are stale** — If a tool crashed, stale files in `~/.ghidra_mcp/` or `~/.ida_mcp/` get auto-cleaned on next discovery (dead PIDs are pruned).

## Adding a New Tool

1. Create `toolname/` directory
2. Write the in-tool bridge (starts HTTP server, registers in `~/.toolname_mcp/`)
3. Write `mcp_server.py` using `common.py` for discovery
4. `claude mcp add toolname -- python3 /path/to/reversing-mcp/toolname/mcp_server.py`
