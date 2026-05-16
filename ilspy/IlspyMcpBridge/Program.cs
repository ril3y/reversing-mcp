// Entry point: load a .NET assembly via ICSharpCode.Decompiler, host an
// HttpListener-based JSON API, and register in ~/.ilspy_mcp/<pid>.json so
// ilspy/mcp_server.py can discover it.
//
//   dotnet run -- <path-to-assembly.dll> [--port=N]
//   ./ilspy-mcp-bridge <path-to-assembly.dll>

using System.Net;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Disassembler;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;

namespace IlspyMcp;

public static class Program
{
    private const int BasePort = 13637;
    private const int MaxPort = 13700;

    private static readonly string RegDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ilspy_mcp");

    public static async Task<int> Main(string[] args)
    {
        string? input = null;
        int forcedPort = 0;
        foreach (var a in args)
        {
            if (a.StartsWith("--port=")) forcedPort = int.Parse(a["--port=".Length..]);
            else if (!a.StartsWith("--")) input = a;
        }

        if (input == null || !File.Exists(input))
        {
            Console.Error.WriteLine("usage: ilspy-mcp-bridge <assembly.dll> [--port=N]");
            return 2;
        }

        Console.Error.WriteLine($"[ilspy-mcp] Loading {Path.GetFullPath(input)} ...");
        var service = new IlspyService(input);
        Console.Error.WriteLine($"[ilspy-mcp] Loaded {service.TypeCount} types, {service.MethodCount} methods.");

        int port = forcedPort > 0 ? forcedPort : FindFreePort();
        var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        string regFile = Register(port, input);
        Console.Error.WriteLine($"[ilspy-mcp] Listening on http://127.0.0.1:{port}");
        Console.Error.WriteLine($"[ilspy-mcp] Registration: {regFile}");

        AppDomain.CurrentDomain.ProcessExit += (_, _) =>
        {
            try { File.Delete(regFile); } catch { /* best effort */ }
            try { listener.Stop(); } catch { }
        };
        Console.CancelKeyPress += (_, e) =>
        {
            try { File.Delete(regFile); } catch { }
            try { listener.Stop(); } catch { }
            e.Cancel = false;
        };

        var router = new Router(service);
        while (listener.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = await listener.GetContextAsync(); }
            catch (HttpListenerException) { break; }
            catch (ObjectDisposedException) { break; }

            _ = Task.Run(() => router.HandleAsync(ctx));
        }
        return 0;
    }

    private static int FindFreePort()
    {
        for (int p = BasePort; p < MaxPort; p++)
        {
            try
            {
                var l = new HttpListener();
                l.Prefixes.Add($"http://127.0.0.1:{p}/");
                l.Start();
                l.Stop();
                return p;
            }
            catch (HttpListenerException) { /* in use */ }
        }
        throw new IOException($"No free port in {BasePort}..{MaxPort}");
    }

    private static string Register(int port, string inputPath)
    {
        Directory.CreateDirectory(RegDir);
        int pid = Environment.ProcessId;
        var info = new JsonObject
        {
            ["pid"] = pid,
            ["port"] = port,
            ["assembly"] = Path.GetFileName(inputPath),
            ["assembly_path"] = Path.GetFullPath(inputPath),
        };
        string path = Path.Combine(RegDir, $"{pid}.json");
        File.WriteAllText(path, info.ToJsonString());
        return path;
    }
}

// ----------------------------------------------------------------------------
// Service: thin wrapper around ICSharpCode.Decompiler bookkeeping
// ----------------------------------------------------------------------------

internal sealed class IlspyService
{
    public string AssemblyPath { get; }
    public string AssemblyFileName => Path.GetFileName(AssemblyPath);

    private readonly object _lock = new();
    private readonly CSharpDecompiler _decompiler;
    private readonly PEFile _module;

    public IlspyService(string path)
    {
        AssemblyPath = Path.GetFullPath(path);
        _module = new PEFile(AssemblyPath);
        var resolver = new UniversalAssemblyResolver(AssemblyPath, throwOnError: false,
            _module.DetectTargetFrameworkId());
        var settings = new DecompilerSettings { ShowXmlDocumentation = false };
        _decompiler = new CSharpDecompiler(AssemblyPath, resolver, settings);
    }

    public int TypeCount
    {
        get
        {
            lock (_lock)
            {
                int n = 0;
                foreach (var _ in _decompiler.TypeSystem.MainModule.TypeDefinitions) n++;
                return n;
            }
        }
    }

    public int MethodCount
    {
        get
        {
            lock (_lock)
            {
                int n = 0;
                foreach (var t in _decompiler.TypeSystem.MainModule.TypeDefinitions)
                {
                    foreach (var _ in t.Methods) n++;
                }
                return n;
            }
        }
    }

    public IEnumerable<string> ReferencedAssemblies()
    {
        lock (_lock)
        {
            foreach (var r in _module.AssemblyReferences)
            {
                yield return $"{r.Name}, Version={r.Version}";
            }
        }
    }

    public IEnumerable<ITypeDefinition> Types()
    {
        lock (_lock)
        {
            return _decompiler.TypeSystem.MainModule.TypeDefinitions.ToList();
        }
    }

    public ITypeDefinition? FindType(string name)
    {
        lock (_lock)
        {
            // exact full-name match first
            foreach (var t in _decompiler.TypeSystem.MainModule.TypeDefinitions)
            {
                if (t.FullName == name || t.ReflectionName == name) return t;
            }
            // substring fallback
            string low = name.ToLowerInvariant();
            foreach (var t in _decompiler.TypeSystem.MainModule.TypeDefinitions)
            {
                if (t.FullName.ToLowerInvariant().Contains(low)) return t;
            }
            return null;
        }
    }

    public IMethod? FindMethod(ITypeDefinition type, string method)
    {
        lock (_lock)
        {
            // Exact full-signature match
            foreach (var m in type.Methods)
            {
                if (m.ToString() == method) return m;
            }
            // Name match (first overload wins)
            foreach (var m in type.Methods)
            {
                if (m.Name == method) return m;
            }
            return null;
        }
    }

    public string DecompileType(ITypeDefinition type)
    {
        lock (_lock)
        {
            return _decompiler.DecompileTypeAsString(new FullTypeName(type.ReflectionName));
        }
    }

    public string DecompileMethod(IMethod method)
    {
        lock (_lock)
        {
            return _decompiler.DecompileAsString(method.MetadataToken);
        }
    }

    public string DisassembleMethodIL(IMethod method)
    {
        lock (_lock)
        {
            var output = new PlainTextOutput();
            var disasm = new ReflectionDisassembler(output, CancellationToken.None);
            disasm.DisassembleMethod(_module, (MethodDefinitionHandle)method.MetadataToken);
            return output.ToString() ?? string.Empty;
        }
    }

    /**
     * Decompile every type and search the C# source for the pattern.  First
     * call is expensive (decompiles the whole assembly); subsequent calls
     * hit ICSharpCode.Decompiler's internal cache.  Matches jadx-side shape
     * so the two servers can be used interchangeably.
     */
    public List<(string Type, int Line, string Snippet)> SearchStringsInSource(string pattern, int limit)
    {
        var hits = new List<(string, int, string)>();
        if (string.IsNullOrEmpty(pattern)) return hits;
        lock (_lock)
        {
            foreach (var t in _decompiler.TypeSystem.MainModule.TypeDefinitions)
            {
                string src;
                try { src = _decompiler.DecompileTypeAsString(new FullTypeName(t.ReflectionName)); }
                catch { continue; }

                int idx = 0;
                while (true)
                {
                    int hit = src.IndexOf(pattern, idx, StringComparison.Ordinal);
                    if (hit < 0) break;
                    hits.Add((t.FullName, LineOf(src, hit), Snippet(src, hit, pattern.Length)));
                    if (hits.Count >= limit) return hits;
                    idx = hit + pattern.Length;
                }
            }
        }
        return hits;
    }

    private static int LineOf(string s, int off)
    {
        int line = 1;
        int end = Math.Min(off, s.Length);
        for (int i = 0; i < end; i++) if (s[i] == '\n') line++;
        return line;
    }

    private static string Snippet(string s, int hit, int hitLen)
    {
        int lineStart = s.LastIndexOf('\n', hit) + 1;
        int lineEnd = s.IndexOf('\n', hit + hitLen);
        if (lineEnd < 0) lineEnd = s.Length;
        string line = s[lineStart..lineEnd];
        if (line.Length > 240)
        {
            int rel = hit - lineStart;
            int from = Math.Max(0, rel - 80);
            int to = Math.Min(line.Length, rel + 160);
            line = "..." + line[from..to] + "...";
        }
        return line;
    }
}

// ----------------------------------------------------------------------------
// Router: maps URL paths to service calls; returns JSON.
// ----------------------------------------------------------------------------

internal sealed class Router
{
    private readonly IlspyService _svc;

    public Router(IlspyService svc) { _svc = svc; }

    public async Task HandleAsync(HttpListenerContext ctx)
    {
        string path = ctx.Request.Url?.AbsolutePath ?? "/";
        try
        {
            string body = await ReadBodyAsync(ctx.Request);
            JsonObject input = TryParseObject(body);
            JsonObject result = Route(path, input);
            await WriteAsync(ctx.Response, 200, result.ToJsonString());
        }
        catch (BadRequestException br)
        {
            await WriteAsync(ctx.Response, 400, ErrorJson(br.Message));
        }
        catch (Exception ex)
        {
            await WriteAsync(ctx.Response, 500, ErrorJson($"{ex.GetType().Name}: {ex.Message}"));
        }
    }

    private JsonObject Route(string path, JsonObject body)
    {
        switch (path)
        {
            case "/ping":
                return new JsonObject { ["status"] = "ok", ["assembly"] = _svc.AssemblyFileName };

            case "/info":
                return new JsonObject
                {
                    ["assembly"] = _svc.AssemblyFileName,
                    ["path"] = _svc.AssemblyPath,
                    ["types"] = _svc.TypeCount,
                    ["methods"] = _svc.MethodCount,
                };

            case "/list_assemblies":
                {
                    var arr = new JsonArray();
                    foreach (var r in _svc.ReferencedAssemblies()) arr.Add(r);
                    return new JsonObject { ["references"] = arr };
                }

            case "/list_types":
                {
                    string prefix = Str(body, "prefix") ?? "";
                    int limit = Int(body, "limit") ?? 200;
                    var arr = new JsonArray();
                    foreach (var t in _svc.Types())
                    {
                        if (prefix.Length == 0 || t.FullName.StartsWith(prefix))
                        {
                            arr.Add(new JsonObject { ["name"] = t.FullName });
                            if (arr.Count >= limit) break;
                        }
                    }
                    return new JsonObject { ["types"] = arr, ["count"] = arr.Count };
                }

            case "/search_types":
                {
                    string pat = Require(body, "pattern");
                    int limit = Int(body, "limit") ?? 100;
                    string low = pat.ToLowerInvariant();
                    var arr = new JsonArray();
                    foreach (var t in _svc.Types())
                    {
                        if (t.FullName.ToLowerInvariant().Contains(low))
                        {
                            arr.Add(new JsonObject { ["name"] = t.FullName });
                            if (arr.Count >= limit) break;
                        }
                    }
                    return new JsonObject { ["types"] = arr };
                }

            case "/decompile_type":
                {
                    var t = RequireType(body, "name");
                    return new JsonObject
                    {
                        ["name"] = t.FullName,
                        ["source"] = _svc.DecompileType(t),
                    };
                }

            case "/list_methods":
                {
                    var t = RequireType(body, "type");
                    var arr = new JsonArray();
                    foreach (var m in t.Methods)
                    {
                        arr.Add(new JsonObject
                        {
                            ["name"] = m.Name,
                            ["signature"] = m.ToString(),
                        });
                    }
                    return new JsonObject { ["methods"] = arr };
                }

            case "/decompile_method":
                {
                    var t = RequireType(body, "type");
                    string method = Require(body, "method");
                    var m = _svc.FindMethod(t, method) ?? throw new BadRequestException($"Method not found: {method}");
                    return new JsonObject
                    {
                        ["type"] = t.FullName,
                        ["method"] = m.Name,
                        ["signature"] = m.ToString(),
                        ["source"] = _svc.DecompileMethod(m),
                    };
                }

            case "/get_il":
                {
                    var t = RequireType(body, "type");
                    string method = Require(body, "method");
                    var m = _svc.FindMethod(t, method) ?? throw new BadRequestException($"Method not found: {method}");
                    return new JsonObject
                    {
                        ["type"] = t.FullName,
                        ["method"] = m.Name,
                        ["signature"] = m.ToString(),
                        ["il"] = _svc.DisassembleMethodIL(m),
                    };
                }

            case "/search_strings":
                {
                    string pat = Require(body, "pattern");
                    int limit = Int(body, "limit") ?? 100;
                    var arr = new JsonArray();
                    foreach (var (type, line, snippet) in _svc.SearchStringsInSource(pat, limit))
                    {
                        arr.Add(new JsonObject
                        {
                            ["type"] = type,
                            ["line"] = line,
                            ["snippet"] = snippet,
                        });
                    }
                    return new JsonObject { ["hits"] = arr };
                }

            default:
                throw new BadRequestException($"Unknown endpoint: {path}");
        }
    }

    // ------ argument helpers ------

    private ITypeDefinition RequireType(JsonObject body, string key)
    {
        string name = Require(body, key);
        return _svc.FindType(name) ?? throw new BadRequestException($"Type not found: {name}");
    }

    private static string Require(JsonObject body, string key)
    {
        var v = Str(body, key);
        if (string.IsNullOrEmpty(v)) throw new BadRequestException($"Provide '{key}'");
        return v;
    }

    private static string? Str(JsonObject body, string key)
        => body.TryGetPropertyValue(key, out var v) ? v?.ToString() : null;

    private static int? Int(JsonObject body, string key)
        => body.TryGetPropertyValue(key, out var v) && v != null && int.TryParse(v.ToString(), out var n) ? n : null;

    // ------ wire helpers ------

    private static async Task<string> ReadBodyAsync(HttpListenerRequest req)
    {
        if (!req.HasEntityBody) return string.Empty;
        using var sr = new StreamReader(req.InputStream, req.ContentEncoding ?? Encoding.UTF8);
        return await sr.ReadToEndAsync();
    }

    private static JsonObject TryParseObject(string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return new JsonObject();
        try
        {
            var node = JsonNode.Parse(body);
            return node as JsonObject ?? new JsonObject();
        }
        catch (JsonException) { return new JsonObject(); }
    }

    private static async Task WriteAsync(HttpListenerResponse resp, int status, string json)
    {
        resp.StatusCode = status;
        resp.ContentType = "application/json";
        byte[] bytes = Encoding.UTF8.GetBytes(json);
        resp.ContentLength64 = bytes.Length;
        await resp.OutputStream.WriteAsync(bytes);
        resp.Close();
    }

    private static string ErrorJson(string msg)
    {
        return new JsonObject { ["error"] = msg }.ToJsonString();
    }
}

internal sealed class BadRequestException : Exception
{
    public BadRequestException(string message) : base(message) { }
}
