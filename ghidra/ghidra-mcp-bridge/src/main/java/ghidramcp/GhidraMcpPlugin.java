// Ghidra ProgramPlugin that auto-starts an HTTP MCP bridge when a program is
// opened.  The bridge exposes a JSON-over-HTTP API so that Claude Code (via
// the MCP server in mcp_server.py) can query and mutate the active program.
//
// Install: Drop this file into a Ghidra module's src/main/java tree, or
//          compile it as a standalone extension.
//
// @author Claude Code

package ghidramcp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import javax.swing.SwingUtilities;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = MiscellaneousPluginPackage.NAME,
    category = "MCP",
    shortDescription = "MCP Bridge for Claude Code",
    description = "Starts an HTTP server that exposes the Ghidra API as " +
                  "JSON endpoints so that Claude Code can query and mutate " +
                  "the active program via the MCP protocol."
)
//@formatter:on
public class GhidraMcpPlugin extends ProgramPlugin {

    private static final String REGISTRATION_DIR =
        System.getProperty("user.home") + File.separator + ".ghidra_mcp";
    private static final int BASE_PORT = 13437;
    private static final int MAX_PORT = 13500;

    private HttpServer server;
    private ExecutorService serverExecutor;
    private int serverPort;
    private DecompInterface decompiler;
    private Program activeProgram;

    public GhidraMcpPlugin(PluginTool tool) {
        super(tool);
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    // Use programOpened/programClosed rather than programActivated/Deactivated.
    // The latter fires for every focus change (including tool rebuilds when
    // plugins are added/removed via Configure → OK), which led to the server
    // bouncing within a single second the first time the plugin was enabled.
    // Open/Closed only fire on actual program lifecycle events.

    @Override
    protected void programOpened(Program program) {
        activeProgram = program;
        startServer();
    }

    @Override
    protected void programClosed(Program program) {
        stopServer();
        activeProgram = null;
    }

    // If the plugin is enabled mid-session (the common case the first time
    // a user installs it), neither programOpened nor programActivated fires
    // for the program that's already loaded — we'd miss it. Catch up at init
    // by polling the tool's ProgramManager for any currently-open program.
    @Override
    protected void init() {
        super.init();
        ghidra.app.services.ProgramManager pm =
            tool.getService(ghidra.app.services.ProgramManager.class);
        if (pm != null) {
            Program existing = pm.getCurrentProgram();
            if (existing != null && activeProgram == null) {
                activeProgram = existing;
                startServer();
            }
        }
    }

    @Override
    protected void dispose() {
        stopServer();
        super.dispose();
    }

    // ------------------------------------------------------------------
    // Server start / stop
    // ------------------------------------------------------------------

    private void startServer() {
        if (server != null) {
            stopServer();
        }
        if (activeProgram == null) {
            return;
        }

        try {
            // Initialise decompiler on the Swing thread (Ghidra API requirement)
            decompiler = new DecompInterface();
            DecompileOptions opts = new DecompileOptions();
            decompiler.setOptions(opts);
            if (!decompiler.openProgram(activeProgram)) {
                Msg.warn(this, "[MCP] Failed to init decompiler: " +
                    decompiler.getLastMessage());
            }

            serverPort = findFreePort();
            server = HttpServer.create(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), serverPort), 0);

            // Daemon thread factory so the pool cannot prevent JVM exit
            AtomicInteger threadNum = new AtomicInteger(1);
            ThreadFactory daemonFactory = r -> {
                Thread t = new Thread(r,
                    "MCP-HTTP-" + threadNum.getAndIncrement());
                t.setDaemon(true);
                return t;
            };
            serverExecutor = Executors.newFixedThreadPool(4, daemonFactory);
            server.setExecutor(serverExecutor);

            // Register endpoints
            server.createContext("/ping", wrap(this::handlePing));
            server.createContext("/info", wrap(this::handleInfo));
            server.createContext("/segments", wrap(this::handleSegments));
            server.createContext("/decompile", wrap(this::handleDecompile));
            server.createContext("/disassemble", wrap(this::handleDisassemble));
            server.createContext("/function", wrap(this::handleFunction));
            server.createContext("/search_functions", wrap(this::handleSearchFunctions));
            server.createContext("/rename", wrap(this::handleRename));
            server.createContext("/comment", wrap(this::handleComment));

            server.start();

            register();
            Msg.info(this,
                "[MCP] Server started on http://127.0.0.1:" + serverPort);
        } catch (Exception e) {
            Msg.error(this, "[MCP] Failed to start server", e);
        }
    }

    private void stopServer() {
        if (server != null) {
            server.stop(0);
            server = null;
            Msg.info(this, "[MCP] Server stopped");
        }
        if (serverExecutor != null) {
            serverExecutor.shutdownNow();
            serverExecutor = null;
        }
        if (decompiler != null) {
            decompiler.dispose();
            decompiler = null;
        }
        unregister();
    }

    // ------------------------------------------------------------------
    // Port discovery
    // ------------------------------------------------------------------

    private int findFreePort() throws IOException {
        for (int port = BASE_PORT; port < MAX_PORT; port++) {
            try (ServerSocket ss = new ServerSocket(port, 1,
                    InetAddress.getLoopbackAddress())) {
                return port;
            } catch (IOException ignored) {
                // port in use, try next
            }
        }
        throw new IOException(
            "No free port in range " + BASE_PORT + "-" + MAX_PORT);
    }

    // ------------------------------------------------------------------
    // Registration file (~/.ghidra_mcp/<pid>.json)
    // ------------------------------------------------------------------

    private void register() {
        try {
            Path dir = Paths.get(REGISTRATION_DIR);
            Files.createDirectories(dir);

            long pid = ProcessHandle.current().pid();
            String programPath = activeProgram.getExecutablePath();

            String json = "{\n" +
                "  \"pid\": " + pid + ",\n" +
                "  \"port\": " + serverPort + ",\n" +
                "  \"program\": \"" + escapeJson(activeProgram.getName()) + "\",\n" +
                "  \"program_path\": \"" + escapeJson(programPath) + "\"\n" +
                "}";

            Path regFile = dir.resolve(pid + ".json");
            Files.write(regFile, json.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            Msg.error(this, "[MCP] Registration failed", e);
        }
    }

    private void unregister() {
        try {
            long pid = ProcessHandle.current().pid();
            Path regFile = Paths.get(REGISTRATION_DIR, pid + ".json");
            Files.deleteIfExists(regFile);
        } catch (Exception ignored) {
            // best-effort
        }
    }

    // ------------------------------------------------------------------
    // JSON helpers  (no external libs)
    // ------------------------------------------------------------------

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String jp(String key, String value) {
        return "\"" + key + "\": \"" + escapeJson(value) + "\"";
    }

    private static String jp(String key, long value) {
        return "\"" + key + "\": " + value;
    }

    private static String jp(String key, boolean value) {
        return "\"" + key + "\": " + value;
    }

    private static String formatAddr(Address addr) {
        return String.format("0x%08X", addr.getOffset());
    }

    // ------------------------------------------------------------------
    // Simple JSON body parser (flat string/number/boolean values only)
    // ------------------------------------------------------------------

    private static Map<String, String> parseJsonBody(HttpExchange exchange)
            throws IOException {
        Map<String, String> result = new LinkedHashMap<>();
        if (!"POST".equals(exchange.getRequestMethod())) {
            return result;
        }
        byte[] data;
        try (InputStream is = exchange.getRequestBody()) {
            data = is.readAllBytes();
        }
        if (data.length == 0) {
            return result;
        }
        String body = new String(data, StandardCharsets.UTF_8).trim();
        if (!body.startsWith("{")) {
            return result;
        }
        body = body.substring(1, body.lastIndexOf('}'));

        int i = 0;
        while (i < body.length()) {
            int keyStart = body.indexOf('"', i);
            if (keyStart < 0) break;
            int keyEnd = body.indexOf('"', keyStart + 1);
            if (keyEnd < 0) break;
            String key = body.substring(keyStart + 1, keyEnd);

            int colon = body.indexOf(':', keyEnd + 1);
            if (colon < 0) break;

            int valStart = colon + 1;
            while (valStart < body.length() && body.charAt(valStart) == ' ') {
                valStart++;
            }
            if (valStart >= body.length()) break;

            String value;
            if (body.charAt(valStart) == '"') {
                int valEnd = findClosingQuote(body, valStart + 1);
                value = body.substring(valStart + 1, valEnd)
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\")
                    .replace("\\n", "\n")
                    .replace("\\r", "\r")
                    .replace("\\t", "\t");
                i = valEnd + 1;
            } else {
                int valEnd = valStart;
                while (valEnd < body.length() &&
                       body.charAt(valEnd) != ',' &&
                       body.charAt(valEnd) != '}') {
                    valEnd++;
                }
                value = body.substring(valStart, valEnd).trim();
                i = valEnd;
            }
            result.put(key, value);
            while (i < body.length() &&
                   (body.charAt(i) == ',' || body.charAt(i) == ' ')) {
                i++;
            }
        }
        return result;
    }

    private static int findClosingQuote(String s, int from) {
        for (int i = from; i < s.length(); i++) {
            if (s.charAt(i) == '"' && (i == 0 || s.charAt(i - 1) != '\\')) {
                return i;
            }
        }
        return s.length();
    }

    // ------------------------------------------------------------------
    // HTTP response helpers
    // ------------------------------------------------------------------

    private static void respond(HttpExchange ex, String json) throws IOException {
        respond(ex, json, 200);
    }

    private static void respond(HttpExchange ex, String json, int status)
            throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void respondError(HttpExchange ex, String msg, int status)
            throws IOException {
        respond(ex, "{" + jp("error", msg) + "}", status);
    }

    // ------------------------------------------------------------------
    // Address parsing
    // ------------------------------------------------------------------

    private Address parseAddress(String addrStr) {
        if (addrStr == null || addrStr.isEmpty()) {
            return null;
        }
        addrStr = addrStr.trim();
        if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
            addrStr = addrStr.substring(2);
        }
        try {
            return activeProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(addrStr);
        } catch (Exception e) {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // Swing thread helper
    //
    // All Ghidra domain-object access from the HTTP worker threads MUST
    // be dispatched to the Swing EDT.  This helper runs a Callable on
    // the EDT, blocks until it completes, and returns the result.
    // ------------------------------------------------------------------

    @FunctionalInterface
    private interface SwingCallable<T> {
        T call() throws Exception;
    }

    private <T> T onSwing(SwingCallable<T> callable) throws Exception {
        AtomicReference<T> resultRef = new AtomicReference<>();
        AtomicReference<Exception> errorRef = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                resultRef.set(callable.call());
            } catch (Exception e) {
                errorRef.set(e);
            }
        });
        Exception err = errorRef.get();
        if (err != null) {
            throw err;
        }
        return resultRef.get();
    }

    // ------------------------------------------------------------------
    // Handler wrapper — catches exceptions, delegates to the Swing EDT
    // ------------------------------------------------------------------

    @FunctionalInterface
    private interface EndpointHandler {
        void handle(HttpExchange exchange) throws Exception;
    }

    private HttpHandler wrap(EndpointHandler handler) {
        return exchange -> {
            try {
                handler.handle(exchange);
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                Msg.error(GhidraMcpPlugin.this, "[MCP] Handler error", cause);
                respondError(exchange,
                    cause.getClass().getSimpleName() + ": " + cause.getMessage(),
                    500);
            } catch (Exception e) {
                Msg.error(GhidraMcpPlugin.this, "[MCP] Handler error", e);
                respondError(exchange,
                    e.getClass().getSimpleName() + ": " + e.getMessage(), 500);
            }
        };
    }

    // ------------------------------------------------------------------
    // Function lookup helper (shared by several endpoints)
    // ------------------------------------------------------------------

    private Function findFunctionByName(String name) {
        Listing listing = activeProgram.getListing();

        // Exact match
        FunctionIterator funcs = listing.getFunctions(true);
        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (f.getName().equals(name)) {
                return f;
            }
        }

        // Substring match (case-insensitive)
        String lower = name.toLowerCase();
        funcs = listing.getFunctions(true);
        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (f.getName().toLowerCase().contains(lower)) {
                return f;
            }
        }

        // Symbol table wildcard
        SymbolTable st = activeProgram.getSymbolTable();
        SymbolIterator syms = st.getSymbolIterator("*" + name + "*", true);
        while (syms.hasNext()) {
            Symbol sym = syms.next();
            Function f = listing.getFunctionAt(sym.getAddress());
            if (f != null) {
                return f;
            }
        }
        return null;
    }

    private Function resolveFunction(Map<String, String> body) {
        String addrStr = body.get("address");
        String name = body.get("name");
        Listing listing = activeProgram.getListing();

        if (name != null && !name.isEmpty()) {
            return findFunctionByName(name);
        }
        if (addrStr != null && !addrStr.isEmpty()) {
            Address addr = parseAddress(addrStr);
            if (addr != null) {
                Function f = listing.getFunctionAt(addr);
                if (f == null) {
                    f = listing.getFunctionContaining(addr);
                }
                return f;
            }
        }
        return null;
    }

    // ==================================================================
    //  Endpoint implementations
    // ==================================================================

    // GET /ping -----------------------------------------------------------

    private void handlePing(HttpExchange ex) throws Exception {
        String json = onSwing(() ->
            "{" + jp("status", "ok") + ", " +
                jp("program", activeProgram.getName()) + "}"
        );
        respond(ex, json);
    }

    // GET /info -----------------------------------------------------------

    private void handleInfo(HttpExchange ex) throws Exception {
        String json = onSwing(() -> {
            Listing listing = activeProgram.getListing();
            int funcCount = 0;
            FunctionIterator fi = listing.getFunctions(true);
            while (fi.hasNext()) { fi.next(); funcCount++; }

            int segCount = 0;
            for (MemoryBlock ignored : activeProgram.getMemory().getBlocks()) {
                segCount++;
            }

            String processor =
                activeProgram.getLanguage().getProcessor().toString();
            int bits = activeProgram.getDefaultPointerSize() * 8;

            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append(jp("file", activeProgram.getName())).append(", ");
            sb.append(jp("path", activeProgram.getExecutablePath())).append(", ");
            sb.append(jp("functions", funcCount)).append(", ");
            sb.append(jp("segments", segCount)).append(", ");
            sb.append(jp("processor", processor)).append(", ");
            sb.append(jp("bits", bits));
            sb.append("}");
            return sb.toString();
        });
        respond(ex, json);
    }

    // GET /segments -------------------------------------------------------

    private void handleSegments(HttpExchange ex) throws Exception {
        String json = onSwing(() -> {
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            boolean first = true;
            for (MemoryBlock block : activeProgram.getMemory().getBlocks()) {
                if (!first) sb.append(", ");
                first = false;

                String perms = "";
                if (block.isRead()) perms += "R";
                if (block.isWrite()) perms += "W";
                if (block.isExecute()) perms += "X";

                sb.append("{");
                sb.append(jp("name", block.getName())).append(", ");
                sb.append(jp("start", formatAddr(block.getStart()))).append(", ");
                sb.append(jp("end", formatAddr(block.getEnd()))).append(", ");
                sb.append(jp("size", block.getSize())).append(", ");
                sb.append(jp("perms", perms));
                sb.append("}");
            }
            sb.append("]");
            return sb.toString();
        });
        respond(ex, json);
    }

    // POST /decompile -----------------------------------------------------

    private void handleDecompile(HttpExchange ex) throws Exception {
        Map<String, String> body = parseJsonBody(ex);
        String json = onSwing(() -> {
            Function func = resolveFunction(body);
            if (func == null) {
                return "{" + jp("error", "Function not found") + "}";
            }
            if (decompiler == null) {
                return "{" + jp("error", "Decompiler not initialised") + "}";
            }
            synchronized (decompiler) {
                DecompileResults results = decompiler.decompileFunction(
                    func, 60, TaskMonitor.DUMMY);
                if (results == null || !results.decompileCompleted()) {
                    String err = (results != null)
                        ? results.getErrorMessage()
                        : "Decompilation returned null";
                    return "{" + jp("error",
                        "Decompilation failed: " + err) + "}";
                }
                String code = results.getDecompiledFunction().getC();
                if (code == null || code.isEmpty()) {
                    return "{" + jp("error",
                        "Decompilation produced no output") + "}";
                }
                StringBuilder sb = new StringBuilder();
                sb.append("{");
                sb.append(jp("pseudocode", code)).append(", ");
                sb.append(jp("address",
                    formatAddr(func.getEntryPoint())));
                sb.append("}");
                return sb.toString();
            }
        });
        respond(ex, json);
    }

    // POST /disassemble ---------------------------------------------------

    private void handleDisassemble(HttpExchange ex) throws Exception {
        Map<String, String> body = parseJsonBody(ex);
        String json = onSwing(() -> {
            Function func = resolveFunction(body);
            if (func == null) {
                return "{" + jp("error", "Function not found") + "}";
            }
            Listing listing = activeProgram.getListing();
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append(jp("name", func.getName())).append(", ");
            sb.append(jp("start",
                formatAddr(func.getEntryPoint()))).append(", ");
            sb.append(jp("end",
                formatAddr(func.getBody().getMaxAddress()))).append(", ");
            sb.append("\"lines\": [");

            boolean first = true;
            InstructionIterator instrs =
                listing.getInstructions(func.getBody(), true);
            while (instrs.hasNext()) {
                Instruction instr = instrs.next();
                if (!first) sb.append(", ");
                first = false;
                sb.append("{");
                sb.append(jp("address",
                    formatAddr(instr.getAddress()))).append(", ");
                sb.append(jp("disasm", instr.toString()));
                sb.append("}");
            }
            sb.append("]}");
            return sb.toString();
        });
        respond(ex, json);
    }

    // POST /function ------------------------------------------------------

    private void handleFunction(HttpExchange ex) throws Exception {
        Map<String, String> body = parseJsonBody(ex);
        String addrStr = body.get("address");
        String name = body.get("name");

        if ((addrStr == null || addrStr.isEmpty()) &&
            (name == null || name.isEmpty())) {
            respondError(ex, "Provide 'address' or 'name'", 400);
            return;
        }

        String json = onSwing(() -> {
            Function func = resolveFunction(body);
            if (func == null) {
                return "{" + jp("error", "No function found") + "}";
            }
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append(jp("name", func.getName())).append(", ");
            sb.append(jp("start",
                formatAddr(func.getEntryPoint()))).append(", ");
            sb.append(jp("end",
                formatAddr(func.getBody().getMaxAddress()))).append(", ");
            sb.append(jp("size", func.getBody().getNumAddresses()));
            sb.append("}");
            return sb.toString();
        });
        respond(ex, json);
    }

    // POST /search_functions ----------------------------------------------

    private void handleSearchFunctions(HttpExchange ex) throws Exception {
        Map<String, String> body = parseJsonBody(ex);
        String pattern = body.get("pattern");
        if (pattern == null || pattern.isEmpty()) {
            respondError(ex, "Provide 'pattern'", 400);
            return;
        }

        String json = onSwing(() -> {
            String patLower = pattern.toLowerCase();
            List<String> results = new ArrayList<>();
            int count = 0;
            FunctionIterator funcs =
                activeProgram.getListing().getFunctions(true);
            while (funcs.hasNext() && count < 100) {
                Function func = funcs.next();
                if (func.getName().toLowerCase().contains(patLower)) {
                    StringBuilder entry = new StringBuilder();
                    entry.append("{");
                    entry.append(jp("address",
                        formatAddr(func.getEntryPoint()))).append(", ");
                    entry.append(jp("name", func.getName())).append(", ");
                    entry.append(jp("size",
                        func.getBody().getNumAddresses()));
                    entry.append("}");
                    results.add(entry.toString());
                    count++;
                }
            }
            return "{\"functions\": [" +
                String.join(", ", results) + "]}";
        });
        respond(ex, json);
    }

    // POST /rename --------------------------------------------------------

    private void handleRename(HttpExchange ex) throws Exception {
        Map<String, String> body = parseJsonBody(ex);
        String addrStr = body.get("address");
        String newName = body.get("name");

        if (addrStr == null || newName == null ||
            addrStr.isEmpty() || newName.isEmpty()) {
            respondError(ex, "Provide 'address' and 'name'", 400);
            return;
        }

        String json = onSwing(() -> {
            Address addr = parseAddress(addrStr);
            if (addr == null) {
                return "{" + jp("error", "Invalid address") + "}";
            }

            SymbolTable symTable = activeProgram.getSymbolTable();
            Symbol existing = symTable.getPrimarySymbol(addr);
            String oldName = (existing != null)
                ? existing.getName() : formatAddr(addr);

            boolean success = false;
            int txId = activeProgram.startTransaction("MCP Rename");
            try {
                if (existing != null) {
                    existing.setName(newName, SourceType.USER_DEFINED);
                    success = true;
                } else {
                    Symbol created = symTable.createLabel(
                        addr, newName, SourceType.USER_DEFINED);
                    success = (created != null);
                }
            } catch (Exception e) {
                Msg.error(GhidraMcpPlugin.this,
                    "[MCP] Rename failed at " + formatAddr(addr), e);
            } finally {
                activeProgram.endTransaction(txId, success);
            }

            if (success) {
                Msg.info(GhidraMcpPlugin.this,
                    "[MCP] RENAME " + formatAddr(addr) + ": " +
                    oldName + " -> " + newName);
            }

            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append(jp("success", success)).append(", ");
            sb.append(jp("address", formatAddr(addr))).append(", ");
            sb.append(jp("old_name", oldName)).append(", ");
            sb.append(jp("name", newName));
            sb.append("}");
            return sb.toString();
        });
        respond(ex, json);
    }

    // POST /comment -------------------------------------------------------

    private void handleComment(HttpExchange ex) throws Exception {
        Map<String, String> body = parseJsonBody(ex);
        String addrStr = body.get("address");
        String comment = body.get("comment");
        String typeStr = body.get("type");

        if (addrStr == null || addrStr.isEmpty()) {
            respondError(ex, "Provide 'address' and 'comment'", 400);
            return;
        }

        String json = onSwing(() -> {
            Address addr = parseAddress(addrStr);
            if (addr == null) {
                return "{" + jp("error", "Invalid address") + "}";
            }

            int commentType;
            if ("plate".equalsIgnoreCase(typeStr)) {
                commentType = CodeUnit.PLATE_COMMENT;
            } else {
                commentType = CodeUnit.EOL_COMMENT;
            }

            boolean success = false;
            int txId = activeProgram.startTransaction("MCP Comment");
            try {
                activeProgram.getListing().setComment(
                    addr, commentType,
                    comment != null ? comment : "");
                success = true;
            } catch (Exception e) {
                Msg.error(GhidraMcpPlugin.this,
                    "[MCP] Comment failed at " + formatAddr(addr), e);
            } finally {
                activeProgram.endTransaction(txId, success);
            }

            if (success) {
                Msg.info(GhidraMcpPlugin.this,
                    "[MCP] COMMENT " + formatAddr(addr) + ": " +
                    (comment != null
                        ? comment.substring(0,
                            Math.min(comment.length(), 80))
                        : ""));
            }

            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append(jp("success", success)).append(", ");
            sb.append(jp("address", formatAddr(addr)));
            sb.append("}");
            return sb.toString();
        });
        respond(ex, json);
    }
}
