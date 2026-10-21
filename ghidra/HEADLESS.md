# Ghidra provider lifecycle

The Ghidra provider implements protocol version `1.0` in two modes:

- `gui`: the extension attaches to a program owned by the user. It supports
  analysis, mutations, and explicit save, but remote close is rejected.
- `headless`: `create_session` or `open_session` launches `analyzeHeadless`
  with `scripts/ghidra_mcp_bridge.java` as a blocking post-script. The bridge
  owns the process,
  records successful mutations in the owned transaction and exits through
  `close_session`.

`create_session` imports and analyzes a binary to completion, then reopens the
saved program as a live session. This two-phase launch is required because a
Ghidra import post-script runs before the newly imported program is savable.
By default,
projects are created below `~/.ghidra_mcp/projects`; callers may select a project
directory and name. `open_session` reopens a named program from an existing
project. `GHIDRA_INSTALL_DIR` locates the launcher, or callers can pass the
`analyze_headless` path explicitly.

The built extension and the script bridge expose the same analysis and mutation
endpoints: info, segments, functions, disassembly, decompilation, xrefs, call
graph, function/string search, bytes, rename, comments, and function create/delete.
Both bind only to loopback.

## Known limits

- The Java bridge does not embed Python, so `script.python` is explicitly
  unsupported. Headless Ghidra scripts can still be supplied outside the live
  MCP session through normal `analyzeHeadless` workflows.
- Closing is restricted to MCP-owned headless sessions. A GUI program remains
  under the user's control.
- Ghidra wraps the live post-script in an outer transaction. `save_session`
  therefore reports `deferred_until_close=true`; durable persistence happens
  when `close_session(save=true)` returns control to `analyzeHeadless`. A killed
  process can lose all changes from that live session.
- `close_session(save=false)` is rejected because the post-script API cannot
  selectively discard its outer transaction without also risking the existing
  project program.
- `create_session` creates a new project name by default. Pass a stable project
  name when later reopening the database matters.
