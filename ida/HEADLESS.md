# Headless IDA sessions

The IDA bridge can own a persistent text-mode (`idat64`) session. It uses the
same HTTP endpoints as the GUI plugin, so analysis, names, comments, types,
function edits, and the scratch notebook behave the same in both modes.

From the unified MCP client, use:

- `create_session` with `target_path` and an optional new `database_path` to
  create an IDA database.
- `reopen_session` with an existing `.i64` or `.idb` as `database_path`.

Headless sessions default to `autosave_policy="after_mutation"`. You can also
call `save_session` explicitly and should finish with
`close_session(save=true)`. Closing asks IDA to save and exit normally; the
launcher does not terminate the process.

Start the local spawn service with:

```powershell
python ida\spawn_server.py --headless --ida-path "C:\Program Files\IDA Pro 8.4\idat64.exe"
```

Remote exposure is opt-in. On a remote IDA host, set `--bind` for the spawn
service and `--bridge-bind` for launched bridges to a trusted interface. There
is no authentication layer, and remote bridges cannot enable `run_python`.

## IDAPython

`run_python` is disabled by default. Enable it per launched session with
`allow_python=true`. Script execution is additionally refused unless the IDA
bridge is bound to loopback. Successful scripts save by default because an
arbitrary script may have changed the database.

There is no safe way to interrupt arbitrary in-process IDAPython. A client
timeout does not imply that IDA stopped the script; wait for it to finish or
recover from the last saved database checkpoint.
