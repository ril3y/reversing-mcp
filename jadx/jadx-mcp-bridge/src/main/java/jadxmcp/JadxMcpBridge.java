// Entry point: load an APK/JAR/DEX into jadx, start an HTTP server, register
// in ~/.jadx_mcp/<pid>.json so jadx/mcp_server.py can discover it.
//
//   java -jar jadx-mcp-bridge.jar <input-file> [--port=N]
package jadxmcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.api.JavaNode;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public final class JadxMcpBridge {

    static final int BASE_PORT = 13537;
    static final int MAX_PORT = 13600;
    static final String REG_DIR =
        System.getProperty("user.home") + File.separator + ".jadx_mcp";

    public static void main(String[] args) throws Exception {
        File input = null;
        int forcedPort = 0;
        for (String a : args) {
            if (a.startsWith("--port=")) {
                forcedPort = Integer.parseInt(a.substring("--port=".length()));
            } else if (!a.startsWith("--")) {
                input = new File(a);
            }
        }
        if (input == null || !input.isFile()) {
            System.err.println("usage: java -jar jadx-mcp-bridge.jar <apk|jar|dex> [--port=N]");
            System.exit(2);
            return;
        }

        System.err.println("[jadx-mcp] Loading " + input.getAbsolutePath() + " ...");
        JadxService service = new JadxService(input);
        System.err.println("[jadx-mcp] Loaded " + service.classCount() + " classes.");

        int port = forcedPort > 0 ? forcedPort : findFreePort();
        HttpServer server = HttpServer.create(
            new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);

        AtomicInteger threadNum = new AtomicInteger(1);
        server.setExecutor(Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "jadx-mcp-" + threadNum.getAndIncrement());
            t.setDaemon(true);
            return t;
        }));

        Router router = new Router(service);
        server.createContext("/", router);
        server.start();

        Path regFile = register(port, input);
        System.err.println("[jadx-mcp] Listening on http://127.0.0.1:" + port);
        System.err.println("[jadx-mcp] Registration: " + regFile);

        // Clean up the registration file on JVM exit so stale entries don't linger.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try { Files.deleteIfExists(regFile); } catch (Exception ignored) {}
            server.stop(0);
        }, "jadx-mcp-shutdown"));
    }

    private static int findFreePort() throws IOException {
        for (int p = BASE_PORT; p < MAX_PORT; p++) {
            try (ServerSocket s = new ServerSocket(p, 1, InetAddress.getLoopbackAddress())) {
                return p;
            } catch (IOException ignored) {}
        }
        throw new IOException("No free port in " + BASE_PORT + ".." + MAX_PORT);
    }

    private static Path register(int port, File input) throws IOException {
        Path dir = Paths.get(REG_DIR);
        Files.createDirectories(dir);
        long pid = ProcessHandle.current().pid();
        String json = Json.object(
            Json.num("pid", pid),
            Json.num("port", port),
            Json.str("jar", input.getName()),
            Json.str("jar_path", input.getAbsolutePath())
        );
        Path reg = dir.resolve(pid + ".json");
        Files.writeString(reg, json);
        return reg;
    }

    // ----------------------------------------------------------------------
    // HTTP dispatch
    // ----------------------------------------------------------------------

    static final class Router implements HttpHandler {
        private final JadxService svc;

        Router(JadxService svc) {
            this.svc = svc;
        }

        @Override
        public void handle(HttpExchange ex) throws IOException {
            String path = ex.getRequestURI().getPath();
            try {
                String resp = route(path, ex);
                send(ex, 200, resp);
            } catch (BadRequest br) {
                send(ex, 400, Json.error(br.getMessage()));
            } catch (Throwable t) {
                send(ex, 500, Json.error(t.getClass().getSimpleName() + ": " + t.getMessage()));
            }
        }

        private String route(String path, HttpExchange ex) throws IOException {
            Map<String, String> body = readBody(ex);

            switch (path) {
                case "/ping":
                    return Json.object(Json.str("status", "ok"),
                                       Json.str("jar", svc.getInputFile().getName()));
                case "/info":
                    return Json.object(
                        Json.str("jar", svc.getInputFile().getName()),
                        Json.str("path", svc.getInputFile().getAbsolutePath()),
                        Json.num("classes", svc.classCount()),
                        Json.num("methods", svc.methodCount())
                    );
                case "/list_classes":
                    return listClasses(body);
                case "/search_classes":
                    return searchClasses(body);
                case "/get_class":
                    return getClass(body);
                case "/decompile_class":
                    return decompileClass(body);
                case "/list_methods":
                    return listMethods(body);
                case "/decompile_method":
                    return decompileMethod(body);
                case "/search_strings":
                    return searchStrings(body);
                case "/xrefs_to":
                    return xrefsTo(body);
                default:
                    throw new BadRequest("Unknown endpoint: " + path);
            }
        }

        // ------ endpoint handlers ------

        private String listClasses(Map<String, String> body) {
            String prefix = body.getOrDefault("prefix", "");
            int limit = parseInt(body.get("limit"), 200);
            List<String> items = new ArrayList<>();
            for (JavaClass c : svc.listClasses(prefix, limit)) {
                items.add(Json.object(Json.str("name", c.getFullName())));
            }
            return Json.object(Json.raw("classes", Json.array(items)),
                               Json.num("count", items.size()));
        }

        private String searchClasses(Map<String, String> body) {
            String pat = body.getOrDefault("pattern", "");
            int limit = parseInt(body.get("limit"), 100);
            if (pat.isEmpty()) throw new BadRequest("Provide 'pattern'");
            List<String> items = new ArrayList<>();
            for (JavaClass c : svc.searchClasses(pat, limit)) {
                items.add(Json.object(Json.str("name", c.getFullName())));
            }
            return Json.object(Json.raw("classes", Json.array(items)));
        }

        private String getClass(Map<String, String> body) {
            JavaClass c = resolveClass(body);
            List<String> methods = new ArrayList<>();
            for (JavaMethod m : c.getMethods()) {
                methods.add(Json.object(
                    Json.str("name", m.getName()),
                    Json.str("short_id", m.getMethodNode().getMethodInfo().getShortId()),
                    Json.num("line", svc.lineForOffset(c, m.getDefPos()))
                ));
            }
            return Json.object(
                Json.str("name", c.getFullName()),
                Json.raw("methods", Json.array(methods)),
                Json.num("method_count", methods.size())
            );
        }

        private String decompileClass(Map<String, String> body) {
            JavaClass c = resolveClass(body);
            return Json.object(
                Json.str("name", c.getFullName()),
                Json.str("source", svc.decompileClass(c))
            );
        }

        private String listMethods(Map<String, String> body) {
            JavaClass c = resolveClass(body);
            List<String> methods = new ArrayList<>();
            for (JavaMethod m : c.getMethods()) {
                methods.add(Json.object(
                    Json.str("name", m.getName()),
                    Json.str("short_id", m.getMethodNode().getMethodInfo().getShortId())
                ));
            }
            return Json.object(Json.raw("methods", Json.array(methods)));
        }

        private String decompileMethod(Map<String, String> body) {
            JavaClass c = resolveClass(body);
            String method = body.get("method");
            if (method == null || method.isEmpty()) throw new BadRequest("Provide 'method'");
            JavaMethod m = svc.findMethod(c, method);
            if (m == null) throw new BadRequest("Method not found: " + method);
            return Json.object(
                Json.str("class", c.getFullName()),
                Json.str("method", m.getName()),
                Json.str("short_id", m.getMethodNode().getMethodInfo().getShortId()),
                Json.str("source", svc.decompileMethod(c, m))
            );
        }

        private String searchStrings(Map<String, String> body) {
            String pat = body.getOrDefault("pattern", "");
            int limit = parseInt(body.get("limit"), 100);
            if (pat.isEmpty()) throw new BadRequest("Provide 'pattern'");
            List<String> items = new ArrayList<>();
            for (JadxService.StringHit h : svc.searchStrings(pat, limit)) {
                items.add(Json.object(
                    Json.str("class", h.className),
                    Json.num("line", h.line),
                    Json.str("snippet", h.snippet)
                ));
            }
            return Json.object(Json.raw("hits", Json.array(items)));
        }

        private String xrefsTo(Map<String, String> body) {
            JavaClass c = resolveClass(body);
            String method = body.get("method");
            List<JavaNode> uses;
            if (method != null && !method.isEmpty()) {
                JavaMethod m = svc.findMethod(c, method);
                if (m == null) throw new BadRequest("Method not found: " + method);
                uses = svc.usesOfMethod(m);
            } else {
                uses = svc.usesOfClass(c);
            }
            List<String> items = new ArrayList<>();
            for (JavaNode n : uses) {
                JavaClass top = n.getTopParentClass();
                items.add(Json.object(
                    Json.str("from_class", top == null ? "?" : top.getFullName()),
                    Json.str("name", n.getName())
                ));
            }
            return Json.object(Json.raw("refs", Json.array(items)));
        }

        // ------ helpers ------

        private JavaClass resolveClass(Map<String, String> body) {
            String name = body.get("class");
            if (name == null || name.isEmpty()) name = body.get("name");
            if (name == null || name.isEmpty()) throw new BadRequest("Provide 'class' or 'name'");
            JavaClass c = svc.findClass(name);
            if (c == null) throw new BadRequest("Class not found: " + name);
            return c;
        }

        private static int parseInt(String s, int dflt) {
            if (s == null || s.isEmpty()) return dflt;
            try { return Integer.parseInt(s.trim()); }
            catch (NumberFormatException e) { return dflt; }
        }

        private static Map<String, String> readBody(HttpExchange ex) throws IOException {
            try (InputStream is = ex.getRequestBody()) {
                byte[] data = is.readAllBytes();
                if (data.length == 0) return Json.parseFlat("");
                return Json.parseFlat(new String(data, StandardCharsets.UTF_8));
            }
        }

        private static void send(HttpExchange ex, int code, String json) throws IOException {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(code, bytes.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(bytes);
            }
        }
    }

    static final class BadRequest extends RuntimeException {
        BadRequest(String msg) { super(msg); }
    }
}
