# Frida runtime notes

Frida provides dynamic instrumentation for local processes and mobile targets.
All client traffic enters through the repository's unified MCP server.

## Host setup

Install the Python client libraries in the interpreter used by
`python -m reversing_mcp`:

```shell
python -m pip install frida frida-tools
```

The installer can perform the same dependency step:

```shell
python install.py --tools frida --scope user --clients claude
```

## Target setup

| Target | Runtime requirement |
|---|---|
| Local Windows, macOS, or Linux | Included with the host installation |
| Rooted Android | Matching `frida-server` in `/data/local/tmp` |
| Non-rooted Android | `frida-gadget` embedded in a rebuilt APK |
| Jailbroken iOS | `re.frida.server` package |
| Non-jailbroken iOS | `frida-gadget` embedded in a re-signed IPA |

Example for a rooted Android device:

```shell
wget https://github.com/frida/frida/releases/download/<ver>/frida-server-<ver>-android-arm64.xz
unxz frida-server-<ver>-android-arm64.xz
adb push frida-server-<ver>-android-arm64 /data/local/tmp/frida-server
adb shell "su -c 'chmod +x /data/local/tmp/frida-server && /data/local/tmp/frida-server &'"
frida-ps -U
```

Keep the host package and target server on compatible versions.

## Typical instrumentation lifecycle

A Frida provider follows the shared session conventions:

1. Discover devices and processes.
2. Attach to or spawn an authorized target.
3. Load JavaScript instrumentation.
4. Drain buffered `send(...)` messages or call exported RPC methods.
5. Detach cleanly.

Provider-specific actions should remain namespaced operations behind the
unified `invoke` tool. They should not create a second MCP surface.

## Example: observe `RegisterNatives`

This script records Java method names, signatures, and native function pointers
registered by an Android runtime. Pass it to the provider's script-loading
operation and drain the resulting `send(...)` messages.

```javascript
const registerNatives = Module.findExportByName(
  "libart.so",
  "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi"
);

Interceptor.attach(registerNatives, {
  onEnter(args) {
    const methods = args[2];
    const count = args[3].toInt32();
    for (let i = 0; i < count; i++) {
      const method = methods.add(i * 24);
      send({
        name: method.readPointer().readCString(),
        signature: method.add(8).readPointer().readCString(),
        function: method.add(16).readPointer().toString(),
      });
    }
  },
});
```

Only instrument software and devices you are authorized to inspect. Frida
scripts execute inside the target process and can change its behavior.
