# Flutter and Dart AOT

The `flutter` provider gives the unified server a headless Flutter workflow for
APK, XAPK, APKS, AAB, and ZIP containers. Package inspection is built in and
does not depend on JADX. Dart AOT reconstruction is a separate, replaceable
analyzer layer because no analyzer can reproduce the original Dart source.

## Open and inspect a package

Open the package directly:

```text
open_session(
  provider="flutter",
  target_path="C:\\samples\\app.xapk",
  mode="headless"
)
```

The baseline operations are always available:

| Operation | Result |
|---|---|
| `target.info` | Package size, SHA-256, format, and Flutter summary |
| `android.framework.detect` | Every registered Android framework detector |
| `flutter.inspect` | Packaging markers, inferred build mode, ABIs, and evidence |
| `flutter.variants.list` | Per-ABI AOT, engine, and deferred loading units |
| `flutter.native.targets` | Native engine and Dart AOT members |
| `flutter.assets.list` | Flutter asset inventory with prefix/suffix filters |
| `flutter.assets.search` | Bounded search over textual Flutter assets |
| `flutter.plugins.list` | DEX class and native-library plugin candidates |
| `flutter.channels.list` | Searchable static platform-channel string candidates |
| `artifact.entries.list` | Root and nested archive inventory |
| `artifact.files.extract` | Safe extraction of selected package members |

Plugin and channel results are candidates from static package evidence. They do
not prove registration or runtime use, and generated or dynamic names may be
absent. Use the optional `query` argument to focus either result set.

`android.framework.detect` is a detector registry rather than a DCloud alias.
It currently reports Flutter and uni-app/DCloud independently, so adding another
framework does not require changing the JADX provider.

## Dart AOT analyzer

The analyzer interface is `AotAnalyzer`;
[Blutter](https://github.com/worawit/blutter) is the first adapter. Configure it
with either the `BLUTTER_COMMAND` environment variable or the
`blutter_command` session option. The value may be a command string or a JSON
array, which is preferable when paths contain spaces:

```powershell
$env:BLUTTER_COMMAND = '["C:\\Python311\\python.exe","D:\\tools\\blutter\\blutter.py"]'
```

The command receives two appended arguments: a directory containing
`libapp.so` and `libflutter.so`, then an empty output directory. Upstream
`blutter.py` can automatically clone Dart sources and build a matching runtime.
The provider blocks that script by default. Prefer a reviewed wrapper that
refuses acquisition, or deliberately pass `allow_toolchain_build=true` for the
analysis request. The same opt-in can be set globally with
`REVERSING_MCP_ALLOW_AOT_TOOLCHAIN_BUILD=1` on a trusted analysis host.

Run `flutter.aot.analyze`, optionally with `abi` and `timeout`. Successful output
is normalized and enables:

- `flutter.aot.status`
- `flutter.objects.search`
- `flutter.libraries.list`
- `functions.list` and `functions.get`
- `search.functions` and `search.strings`
- `analysis.disassemble`

Raw analyzer files remain alongside the normalized index. Results are cached by
the hashes of `libapp.so` and `libflutter.so`, ABI, analyzer identity, and schema
version. Set `REVERSING_MCP_FLUTTER_CACHE` to change the cache root. Closing a
session removes temporary package extraction but preserves this cache.

Blutter currently supports Android arm64 snapshots. An APK that contains only
`armeabi-v7a` can still use all package, asset, plugin, channel, extraction, and
native-analysis operations, but the Blutter adapter returns
`unsupported_flutter_abi` instead of fabricating AOT results. A future analyzer
can implement `AotAnalyzer` for other snapshots without changing the provider.

## Boundaries

- AOT output is reconstructed machine-code evidence, not original Dart source.
- Inlining, tree shaking, specialization, and compiler-generated code affect
  function boundaries and names.
- Obfuscated applications retain structure but may not retain meaningful names.
- Debug/JIT packages and release/profile AOT packages have different artifacts.
- AAB deferred components can contain multiple `libapp.so-N.part.so` loading
  units; they are inventoried separately and are not silently merged.
- Runtime claims still require runtime evidence. Use the Frida provider for
  guarded instrumentation of an authorized target.

After updating the checkout, restart Claude Code and Codex so the already
registered `reversing-mcp` command loads the new provider. Re-registration is
not required when the command and environment are unchanged.
