# JADX provider lifecycle

JADX is a managed-code, headless provider under protocol version `1.0`.
`create_session` and `open_session` both start an owned local JVM for an
APK, AAB, JAR, or DEX. No JADX GUI needs to be open. The bridge jar is resolved
from `JADX_MCP_BRIDGE_JAR` or the local Gradle build output.

The provider exposes class/method inventory, Java decompilation, source-string
search, incoming usages, and APK/JAR resource inventory. The `target.info`
operation identifies the input kind and whether it is Android-oriented.

## Deliberate capability limits

- JADX sessions are read-only and do not have an IDB/Ghidra-project equivalent.
  `lifecycle.save` is reported as unsupported rather than pretending a no-op is
  persistence.
- Only an MCP-owned bridge can be closed remotely.
- `script.python` is unsupported because the JVM bridge does not embed a
  Python runtime. Host-side scripts can call MCP operations, but are not run
  inside JADX.
- Resource inventory returns archive paths and sizes. It does not claim to
  decode binary Android XML or ARSC resources.
- Decompilation and xrefs are static analysis results, not runtime evidence.
