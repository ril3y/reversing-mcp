# frida MCP

Dynamic instrumentation. Unlike the other MCPs in this repo, there's no
in-tool bridge to build — `frida-python` is the client library, and the
MCP server uses it directly.

## Setup

### Host (where Claude Code runs)

```bash
pip install frida frida-tools     # or: python install.py --tools frida
```

That's it for the host. The MCP server connects to a Frida server running on
whichever target you instrument.

### Target

| Target               | Frida server                                                |
|----------------------|-------------------------------------------------------------|
| Local Windows/Mac/Linux | built into the host install — no extra setup            |
| Android (rooted)     | `frida-server-<ver>-android-arm64` pushed to /data/local/tmp |
| Android (non-rooted) | `frida-gadget` injected into the APK via `objection patchapk` or rebuild |
| iOS (jailbroken)     | Cydia: `re.frida.server`                                    |
| iOS (non-jailbroken) | `frida-gadget` embedded into a re-signed IPA                |

Quick Android-rooted recipe:

```bash
# On host:
wget https://github.com/frida/frida/releases/download/<ver>/frida-server-<ver>-android-arm64.xz
unxz frida-server-<ver>-android-arm64.xz
adb push frida-server-<ver>-android-arm64 /data/local/tmp/frida-server
adb shell "su -c 'chmod +x /data/local/tmp/frida-server && /data/local/tmp/frida-server &'"

# Verify:
frida-ps -U                       # should list device processes
```

## Tool surface

The MCP exposes session-oriented tools. Typical flow:

1. **`list_devices()`** — confirm host + device are reachable
2. **`list_processes(device_id='usb')`** or **`list_applications`** — find the target
3. **`attach(target, device_id)`** — returns `session_id` (or **`spawn(...)` → resume**)
4. **`load_script(session_id, source)`** — inject your Frida JS, returns `script_id`
5. **`drain_messages(script_id)`** — pull buffered `send(...)` payloads back
6. **`call_rpc(script_id, 'methodName', [args...])`** — invoke `rpc.exports.methodName`
7. **`detach(session_id)`** when done

Convenience tools that skip the boilerplate JS:

- `enum_modules(session_id)`
- `enum_exports(session_id, module)`
- `enum_imports(session_id, module)`
- `find_export(session_id, module, symbol)`
- `read_memory(session_id, address, size)`

## Cookbook: dumping `RegisterNatives` arguments

The motivating use case for this MCP — finding which Java methods are
wired to which native function pointers inside an obfuscated JNI_OnLoad:

```javascript
// Pass this string as `source` to load_script.
const RegisterNatives = Module.findExportByName('libart.so', '_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi');
Interceptor.attach(RegisterNatives, {
  onEnter(args) {
    const env = args[0];
    const cls = args[1];
    const methods = args[2];     // const JNINativeMethod*
    const count = args[3].toInt32();
    for (let i = 0; i < count; i++) {
      const m = methods.add(i * 24);    // {name*, sig*, fnPtr*} = 24 bytes
      send({
        name: m.readPointer().readCString(),
        sig: m.add(8).readPointer().readCString(),
        fnPtr: m.add(16).readPointer().toString(),
      });
    }
  },
});
```

Then `drain_messages(script_id)` to pull the table.
