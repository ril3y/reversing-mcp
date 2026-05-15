// GhidraScript that starts an embedded HTTP server for MCP integration.
//
// Install: Place in your ghidra_scripts directory and run from Script Manager.
// Each Ghidra instance gets its own port and registers in ~/.ghidra_mcp/.
//
// The script keeps running (blocks via askYesNo) so the HTTP server stays alive.
// Click "No" on the dialog to stop the server.
//
// @category MCP
// @author Claude Code

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.Executors;

public class ghidra_mcp_bridge extends GhidraScript {

    private static final String REGISTRATION_DIR = System.getProperty("user.home") + "/.ghidra_mcp";
    private static final int BASE_PORT = 13437;
    private static final int MAX_PORT = 13500;

    private HttpServer server;
    private DecompInterface decompiler;
    private int serverPort;

    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            println("[MCP] No program loaded. Open a binary first.");
            return;
        }

        // Initialize decompiler
        decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        if (!decompiler.openProgram(currentProgram)) {
            println("[MCP] WARNING: Failed to initialize decompiler: " + decompiler.getLastMessage());
        }

        // Find free port and start server
        serverPort = findFreePort();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", serverPort), 0);
        server.setExecutor(Executors.newFixedThreadPool(4));

        // Register all endpoints
        server.createContext("/ping", new PingHandler());
        server.createContext("/info", new InfoHandler());
        server.createContext("/segments", new SegmentsHandler());
        server.createContext("/function", new FunctionHandler());
        server.createContext("/disassemble", new DisassembleHandler());
        server.createContext("/decompile", new DecompileHandler());
        server.createContext("/xrefs_to", new XrefsToHandler());
        server.createContext("/xrefs_from", new XrefsFromHandler());
        server.createContext("/callers", new CallersHandler());
        server.createContext("/callees", new CalleesHandler());
        server.createContext("/search_functions", new SearchFunctionsHandler());
        server.createContext("/search_strings", new SearchStringsHandler());
        server.createContext("/bytes", new BytesHandler());
        server.createContext("/rename", new RenameHandler());
        server.createContext("/comment", new CommentHandler());
        server.createContext("/create_function", new CreateFunctionHandler());
        server.createContext("/delete_function", new DeleteFunctionHandler());

        server.start();
        String regPath = register(serverPort);

        println("[MCP] Server started on http://127.0.0.1:" + serverPort);
        println("[MCP] Program: " + currentProgram.getName());
        println("[MCP] Registration: " + regPath);

        try {
            // Block until user dismisses
            boolean keepRunning = askYesNo("Ghidra MCP Server",
                "MCP server running on port " + serverPort + ".\n" +
                "Program: " + currentProgram.getName() + "\n\n" +
                "Click 'No' to stop the server.");

            // If they click Yes, show another dialog (loop)
            while (keepRunning) {
                keepRunning = askYesNo("Ghidra MCP Server",
                    "MCP server still running on port " + serverPort + ".\n" +
                    "Click 'No' to stop the server.");
            }
        } finally {
            // Cleanup
            server.stop(0);
            unregister();
            if (decompiler != null) {
                decompiler.dispose();
            }
            println("[MCP] Server stopped");
        }
    }

    // -----------------------------------------------------------------------
    // Port discovery
    // -----------------------------------------------------------------------

    private int findFreePort() throws Exception {
        for (int port = BASE_PORT; port < MAX_PORT; port++) {
            try (ServerSocket ss = new ServerSocket(port, 1,
                    java.net.InetAddress.getByName("127.0.0.1"))) {
                return port;
            } catch (IOException e) {
                continue;
            }
        }
        throw new RuntimeException("No free ports in range " + BASE_PORT + "-" + MAX_PORT);
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    private String register(int port) throws IOException {
        Path dir = Paths.get(REGISTRATION_DIR);
        Files.createDirectories(dir);

        long pid = ProcessHandle.current().pid();
        String programPath = currentProgram.getExecutablePath();

        String json = "{\n" +
            "  \"pid\": " + pid + ",\n" +
            "  \"port\": " + port + ",\n" +
            "  \"program\": \"" + escapeJson(currentProgram.getName()) + "\",\n" +
            "  \"program_path\": \"" + escapeJson(programPath) + "\"\n" +
            "}";

        Path regFile = dir.resolve(pid + ".json");
        Files.write(regFile, json.getBytes(StandardCharsets.UTF_8));
        return regFile.toString();
    }

    private void unregister() {
        try {
            long pid = ProcessHandle.current().pid();
            Path regFile = Paths.get(REGISTRATION_DIR, pid + ".json");
            Files.deleteIfExists(regFile);
        } catch (Exception e) {
            // ignore
        }
    }

    // -----------------------------------------------------------------------
    // JSON helpers
    // -----------------------------------------------------------------------

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String jsonPair(String key, String value) {
        return "\"" + key + "\": \"" + escapeJson(value) + "\"";
    }

    private String jsonPair(String key, long value) {
        return "\"" + key + "\": " + value;
    }

    private String jsonPair(String key, boolean value) {
        return "\"" + key + "\": " + value;
    }

    private Map<String, String> parseJsonBody(HttpExchange exchange) throws IOException {
        Map<String, String> result = new LinkedHashMap<>();
        if (!"POST".equals(exchange.getRequestMethod())) return result;

        InputStream is = exchange.getRequestBody();
        byte[] data = is.readAllBytes();
        if (data.length == 0) return result;

        String body = new String(data, StandardCharsets.UTF_8).trim();
        if (!body.startsWith("{")) return result;

        // Simple JSON parser for flat objects with string/number/boolean values
        body = body.substring(1, body.lastIndexOf('}'));
        // Split by commas, but be careful with quoted strings
        int i = 0;
        while (i < body.length()) {
            // Find key
            int keyStart = body.indexOf('"', i);
            if (keyStart < 0) break;
            int keyEnd = body.indexOf('"', keyStart + 1);
            if (keyEnd < 0) break;
            String key = body.substring(keyStart + 1, keyEnd);

            // Find colon
            int colon = body.indexOf(':', keyEnd + 1);
            if (colon < 0) break;

            // Find value - skip whitespace
            int valStart = colon + 1;
            while (valStart < body.length() && body.charAt(valStart) == ' ') valStart++;

            String value;
            if (valStart >= body.length()) break;

            if (body.charAt(valStart) == '"') {
                // String value
                int valEnd = findClosingQuote(body, valStart + 1);
                value = body.substring(valStart + 1, valEnd);
                // Unescape
                value = value.replace("\\\"", "\"").replace("\\\\", "\\")
                             .replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t");
                i = valEnd + 1;
            } else {
                // Number or boolean
                int valEnd = valStart;
                while (valEnd < body.length() && body.charAt(valEnd) != ',' && body.charAt(valEnd) != '}') valEnd++;
                value = body.substring(valStart, valEnd).trim();
                i = valEnd;
            }

            result.put(key, value);

            // Skip comma
            while (i < body.length() && (body.charAt(i) == ',' || body.charAt(i) == ' ')) i++;
        }

        return result;
    }

    private int findClosingQuote(String s, int from) {
        for (int i = from; i < s.length(); i++) {
            if (s.charAt(i) == '"' && (i == 0 || s.charAt(i - 1) != '\\')) {
                return i;
            }
        }
        return s.length();
    }

    // -----------------------------------------------------------------------
    // HTTP response helpers
    // -----------------------------------------------------------------------

    private void respond(HttpExchange exchange, String json) throws IOException {
        respond(exchange, json, 200);
    }

    private void respond(HttpExchange exchange, String json, int status) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }

    private void respondError(HttpExchange exchange, String msg, int status) throws IOException {
        respond(exchange, "{" + jsonPair("error", msg) + "}", status);
    }

    // -----------------------------------------------------------------------
    // Address parsing
    // -----------------------------------------------------------------------

    private Address parseAddress(String addrStr) {
        if (addrStr == null || addrStr.isEmpty()) return null;
        addrStr = addrStr.trim();
        if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
            addrStr = addrStr.substring(2);
        }
        try {
            return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addrStr);
        } catch (Exception e) {
            return null;
        }
    }

    private String formatAddress(Address addr) {
        return String.format("0x%08X", addr.getOffset());
    }

    // -----------------------------------------------------------------------
    // Core API methods
    // -----------------------------------------------------------------------

    private String getProgramInfo() {
        Listing listing = currentProgram.getListing();
        FunctionIterator funcs = listing.getFunctions(true);
        int funcCount = 0;
        while (funcs.hasNext()) {
            funcs.next();
            funcCount++;
        }

        int segCount = 0;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            segCount++;
        }

        String processor = currentProgram.getLanguage().getProcessor().toString();
        int bits = currentProgram.getDefaultPointerSize() * 8;

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(jsonPair("file", currentProgram.getName())).append(", ");
        sb.append(jsonPair("path", currentProgram.getExecutablePath())).append(", ");
        sb.append(jsonPair("functions", funcCount)).append(", ");
        sb.append(jsonPair("segments", segCount)).append(", ");
        sb.append(jsonPair("processor", processor)).append(", ");
        sb.append(jsonPair("bits", bits));
        sb.append("}");
        return sb.toString();
    }

    private String getSegmentsList() {
        StringBuilder sb = new StringBuilder();
        sb.append("[");
        boolean first = true;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!first) sb.append(", ");
            first = false;

            String perms = "";
            if (block.isRead()) perms += "R";
            if (block.isWrite()) perms += "W";
            if (block.isExecute()) perms += "X";

            long size = block.getSize();

            sb.append("{");
            sb.append(jsonPair("name", block.getName())).append(", ");
            sb.append(jsonPair("start", formatAddress(block.getStart()))).append(", ");
            sb.append(jsonPair("end", formatAddress(block.getEnd()))).append(", ");
            sb.append(jsonPair("size", size)).append(", ");
            sb.append(jsonPair("perms", perms));
            sb.append("}");
        }
        sb.append("]");
        return sb.toString();
    }

    private Function findFunctionByName(String name) {
        Listing listing = currentProgram.getListing();

        // Exact match first
        FunctionIterator funcs = listing.getFunctions(true);
        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (f.getName().equals(name)) return f;
        }

        // Substring match (case-insensitive)
        String nameLower = name.toLowerCase();
        funcs = listing.getFunctions(true);
        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (f.getName().toLowerCase().contains(nameLower)) return f;
        }

        // Check symbol table
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator symbols = symTable.getSymbolIterator("*" + name + "*", true);
        while (symbols.hasNext()) {
            Symbol sym = symbols.next();
            Function f = listing.getFunctionAt(sym.getAddress());
            if (f != null) return f;
        }

        return null;
    }

    private String functionToJson(Function func) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(jsonPair("name", func.getName())).append(", ");
        sb.append(jsonPair("start", formatAddress(func.getEntryPoint()))).append(", ");
        sb.append(jsonPair("end", formatAddress(func.getBody().getMaxAddress()))).append(", ");
        sb.append(jsonPair("size", func.getBody().getNumAddresses()));
        sb.append("}");
        return sb.toString();
    }

    private String disassembleFunction(Function func) {
        Listing listing = currentProgram.getListing();
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(jsonPair("name", func.getName())).append(", ");
        sb.append(jsonPair("start", formatAddress(func.getEntryPoint()))).append(", ");
        sb.append(jsonPair("end", formatAddress(func.getBody().getMaxAddress()))).append(", ");
        sb.append(jsonPair("size", func.getBody().getNumAddresses())).append(", ");
        sb.append("\"lines\": [");

        boolean first = true;
        InstructionIterator instructions = listing.getInstructions(func.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (!first) sb.append(", ");
            first = false;

            byte[] bytes = new byte[instr.getLength()];
            try {
                currentProgram.getMemory().getBytes(instr.getAddress(), bytes);
            } catch (Exception e) {
                bytes = new byte[0];
            }

            sb.append("{");
            sb.append(jsonPair("address", formatAddress(instr.getAddress()))).append(", ");
            sb.append(jsonPair("disasm", instr.toString())).append(", ");
            sb.append(jsonPair("bytes", bytesToHex(bytes)));
            sb.append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    private String disassembleRange(Address start, Address end) {
        Listing listing = currentProgram.getListing();
        AddressSet range = new AddressSet(start, end);
        StringBuilder sb = new StringBuilder();
        sb.append("{\"lines\": [");

        boolean first = true;
        InstructionIterator instructions = listing.getInstructions(range, true);
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            if (!first) sb.append(", ");
            first = false;

            byte[] bytes = new byte[instr.getLength()];
            try {
                currentProgram.getMemory().getBytes(instr.getAddress(), bytes);
            } catch (Exception e) {
                bytes = new byte[0];
            }

            sb.append("{");
            sb.append(jsonPair("address", formatAddress(instr.getAddress()))).append(", ");
            sb.append(jsonPair("disasm", instr.toString())).append(", ");
            sb.append(jsonPair("bytes", bytesToHex(bytes)));
            sb.append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    private String decompileFunction(Function func) {
        synchronized (decompiler) {
            DecompileResults results = decompiler.decompileFunction(func, 60, monitor);
            if (results == null || !results.decompileCompleted()) {
                String errMsg = (results != null) ? results.getErrorMessage() : "Decompilation returned null";
                return "{" + jsonPair("error", "Decompilation failed: " + errMsg) + "}";
            }

            String decompiledCode = results.getDecompiledFunction().getC();
            if (decompiledCode == null || decompiledCode.isEmpty()) {
                return "{" + jsonPair("error", "Decompilation produced no output") + "}";
            }

            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append(jsonPair("pseudocode", decompiledCode)).append(", ");
            sb.append(jsonPair("address", formatAddress(func.getEntryPoint())));
            sb.append("}");
            return sb.toString();
        }
    }

    private String getXrefsTo(Address addr) {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Reference[] refs = refMgr.getReferencesTo(addr);

        StringBuilder sb = new StringBuilder();
        sb.append("{\"refs\": [");
        boolean first = true;
        for (Reference ref : refs) {
            if (!first) sb.append(", ");
            first = false;

            String funcName = "";
            Function func = currentProgram.getListing().getFunctionContaining(ref.getFromAddress());
            if (func != null) {
                funcName = func.getName();
            }

            sb.append("{");
            sb.append(jsonPair("from", formatAddress(ref.getFromAddress()))).append(", ");
            sb.append(jsonPair("from_func", funcName)).append(", ");
            sb.append(jsonPair("type", ref.getReferenceType().getValue())).append(", ");
            sb.append(jsonPair("type_name", ref.getReferenceType().getName()));
            sb.append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private String getXrefsFrom(Address addr) {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Reference[] refs = refMgr.getReferencesFrom(addr);

        StringBuilder sb = new StringBuilder();
        sb.append("{\"refs\": [");
        boolean first = true;
        for (Reference ref : refs) {
            if (!first) sb.append(", ");
            first = false;

            Address toAddr = ref.getToAddress();
            String name = "";
            Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(toAddr);
            if (sym != null) {
                name = sym.getName();
            }

            sb.append("{");
            sb.append(jsonPair("to", formatAddress(toAddr))).append(", ");
            sb.append(jsonPair("name", name)).append(", ");
            sb.append(jsonPair("type", ref.getReferenceType().getValue())).append(", ");
            sb.append(jsonPair("type_name", ref.getReferenceType().getName()));
            sb.append("}");
        }
        sb.append("]}");
        return sb.toString();
    }

    private String getCallers(Function func) {
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        Set<String> seen = new LinkedHashSet<>();
        List<String> callerEntries = new ArrayList<>();

        Reference[] refs = refMgr.getReferencesTo(func.getEntryPoint());
        for (Reference ref : refs) {
            if (!ref.getReferenceType().isCall() && !ref.getReferenceType().isJump()) continue;

            Function callerFunc = currentProgram.getListing().getFunctionContaining(ref.getFromAddress());
            if (callerFunc != null && !callerFunc.getEntryPoint().equals(func.getEntryPoint())) {
                String key = formatAddress(callerFunc.getEntryPoint());
                if (seen.add(key)) {
                    StringBuilder entry = new StringBuilder();
                    entry.append("{");
                    entry.append(jsonPair("address", key)).append(", ");
                    entry.append(jsonPair("name", callerFunc.getName())).append(", ");
                    entry.append(jsonPair("call_site", formatAddress(ref.getFromAddress())));
                    entry.append("}");
                    callerEntries.add(entry.toString());
                }
            }
        }

        return "{\"callers\": [" + String.join(", ", callerEntries) + "]}";
    }

    private String getCallees(Function func) {
        Set<String> seen = new LinkedHashSet<>();
        List<String> calleeEntries = new ArrayList<>();

        Listing listing = currentProgram.getListing();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        InstructionIterator instructions = listing.getInstructions(func.getBody(), true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            Reference[] refs = refMgr.getReferencesFrom(instr.getAddress());
            for (Reference ref : refs) {
                if (!ref.getReferenceType().isCall() && !ref.getReferenceType().isJump()) continue;

                Function target = listing.getFunctionAt(ref.getToAddress());
                if (target == null) {
                    target = listing.getFunctionContaining(ref.getToAddress());
                }
                if (target != null && !target.getEntryPoint().equals(func.getEntryPoint())) {
                    String key = formatAddress(target.getEntryPoint());
                    if (seen.add(key)) {
                        StringBuilder entry = new StringBuilder();
                        entry.append("{");
                        entry.append(jsonPair("address", key)).append(", ");
                        entry.append(jsonPair("name", target.getName()));
                        entry.append("}");
                        calleeEntries.add(entry.toString());
                    }
                }
            }
        }

        return "{\"callees\": [" + String.join(", ", calleeEntries) + "]}";
    }

    private String searchFunctions(String pattern) {
        String patternLower = pattern.toLowerCase();
        List<String> results = new ArrayList<>();
        int count = 0;

        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        while (funcs.hasNext() && count < 100) {
            Function func = funcs.next();
            if (func.getName().toLowerCase().contains(patternLower)) {
                StringBuilder entry = new StringBuilder();
                entry.append("{");
                entry.append(jsonPair("address", formatAddress(func.getEntryPoint()))).append(", ");
                entry.append(jsonPair("name", func.getName())).append(", ");
                entry.append(jsonPair("size", func.getBody().getNumAddresses()));
                entry.append("}");
                results.add(entry.toString());
                count++;
            }
        }

        return "{\"functions\": [" + String.join(", ", results) + "]}";
    }

    private String searchStrings(String pattern) {
        String patternLower = pattern.toLowerCase();
        List<String> results = new ArrayList<>();
        int count = 0;

        // Iterate defined data looking for strings
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && count < 100) {
            Data data = dataIter.next();
            if (data.hasStringValue()) {
                String value = data.getDefaultValueRepresentation();
                // Strip surrounding quotes if present
                if (value != null && value.startsWith("\"") && value.endsWith("\"")) {
                    value = value.substring(1, value.length() - 1);
                }
                if (value != null && value.toLowerCase().contains(patternLower)) {
                    StringBuilder entry = new StringBuilder();
                    entry.append("{");
                    entry.append(jsonPair("address", formatAddress(data.getAddress()))).append(", ");
                    entry.append(jsonPair("value", value)).append(", ");
                    entry.append(jsonPair("length", data.getLength()));
                    entry.append("}");
                    results.add(entry.toString());
                    count++;
                }
            }
        }

        return "{\"strings\": [" + String.join(", ", results) + "]}";
    }

    private String readBytes(Address addr, int size) {
        size = Math.min(size, 4096);
        byte[] bytes = new byte[size];
        try {
            int read = currentProgram.getMemory().getBytes(addr, bytes);
            if (read < size) {
                byte[] trimmed = new byte[read];
                System.arraycopy(bytes, 0, trimmed, 0, read);
                bytes = trimmed;
            }
        } catch (Exception e) {
            return "{" + jsonPair("error", "Cannot read bytes at address: " + e.getMessage()) + "}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(jsonPair("address", formatAddress(addr))).append(", ");
        sb.append(jsonPair("size", bytes.length)).append(", ");
        sb.append(jsonPair("hex", bytesToHex(bytes)));
        sb.append("}");
        return sb.toString();
    }

    private String renameAddress(Address addr, String newName) {
        SymbolTable symTable = currentProgram.getSymbolTable();
        Symbol existing = symTable.getPrimarySymbol(addr);
        String oldName = (existing != null) ? existing.getName() : formatAddress(addr);

        boolean success = false;
        int txId = currentProgram.startTransaction("MCP Rename");
        try {
            if (existing != null) {
                existing.setName(newName, SourceType.USER_DEFINED);
                success = true;
            } else {
                Symbol newSym = symTable.createLabel(addr, newName, SourceType.USER_DEFINED);
                success = (newSym != null);
            }
        } catch (Exception e) {
            println("[MCP] RENAME FAILED " + formatAddress(addr) + ": " + e.getMessage());
        } finally {
            currentProgram.endTransaction(txId, success);
        }

        if (success) {
            println("[MCP] RENAME " + formatAddress(addr) + ": " + oldName + " -> " + newName);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(jsonPair("success", success)).append(", ");
        sb.append(jsonPair("address", formatAddress(addr))).append(", ");
        sb.append(jsonPair("name", newName));
        sb.append("}");
        return sb.toString();
    }

    private String addComment(Address addr, String comment, boolean repeatable) {
        boolean success = false;
        int txId = currentProgram.startTransaction("MCP Comment");
        try {
            if (repeatable) {
                currentProgram.getListing().setComment(addr,
                    CodeUnit.REPEATABLE_COMMENT, comment);
            } else {
                currentProgram.getListing().setComment(addr,
                    CodeUnit.EOL_COMMENT, comment);
            }
            success = true;
        } catch (Exception e) {
            println("[MCP] COMMENT FAILED " + formatAddress(addr) + ": " + e.getMessage());
        } finally {
            currentProgram.endTransaction(txId, success);
        }

        String ctype = repeatable ? "repeatable" : "regular";
        if (success) {
            println("[MCP] COMMENT " + formatAddress(addr) + " (" + ctype + "): " +
                    comment.substring(0, Math.min(comment.length(), 80)));
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(jsonPair("success", success)).append(", ");
        sb.append(jsonPair("address", formatAddress(addr)));
        sb.append("}");
        return sb.toString();
    }

    private String createFunction(Address addr, Address end) {
        boolean success = false;
        int txId = currentProgram.startTransaction("MCP Create Function");
        Function func = null;
        try {
            if (end != null) {
                AddressSet body = new AddressSet(addr, end);
                func = currentProgram.getListing().createFunction(null, addr, body,
                    SourceType.USER_DEFINED);
            } else {
                ghidra.app.cmd.function.CreateFunctionCmd cmd =
                    new ghidra.app.cmd.function.CreateFunctionCmd(addr);
                cmd.applyTo(currentProgram, monitor);
                func = currentProgram.getListing().getFunctionAt(addr);
            }
            success = (func != null);
        } catch (Exception e) {
            println("[MCP] CREATE FUNC FAILED " + formatAddress(addr) + ": " + e.getMessage());
        } finally {
            currentProgram.endTransaction(txId, success);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(jsonPair("success", success)).append(", ");
        sb.append(jsonPair("address", formatAddress(addr)));
        if (func != null) {
            sb.append(", ");
            sb.append(jsonPair("name", func.getName())).append(", ");
            sb.append(jsonPair("size", func.getBody().getNumAddresses()));
        }
        if (!success) {
            sb.append(", ");
            sb.append(jsonPair("error", "create_function failed"));
        }
        sb.append("}");
        return sb.toString();
    }

    private String deleteFunction(Address addr) {
        Function func = currentProgram.getListing().getFunctionAt(addr);
        if (func == null) {
            return "{" + jsonPair("success", false) + ", " +
                   jsonPair("address", formatAddress(addr)) + ", " +
                   jsonPair("error", "No function at address") + "}";
        }

        String name = func.getName();
        boolean success = false;
        int txId = currentProgram.startTransaction("MCP Delete Function");
        try {
            success = currentProgram.getListing().removeFunction(addr);
        } catch (Exception e) {
            println("[MCP] DELETE FUNC FAILED " + formatAddress(addr) + ": " + e.getMessage());
        } finally {
            currentProgram.endTransaction(txId, success);
        }

        if (success) {
            println("[MCP] DELETE FUNC " + formatAddress(addr) + " (" + name + ")");
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append(jsonPair("success", success)).append(", ");
        sb.append(jsonPair("address", formatAddress(addr)));
        sb.append("}");
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // HTTP Handlers
    // -----------------------------------------------------------------------

    private abstract class BaseHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                handleRequest(exchange);
            } catch (Exception e) {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                println("[MCP] ERROR: " + sw.toString());
                respondError(exchange, e.getClass().getSimpleName() + ": " + e.getMessage(), 500);
            }
        }

        abstract void handleRequest(HttpExchange exchange) throws Exception;
    }

    private class PingHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            respond(exchange, "{" + jsonPair("status", "ok") + ", " +
                    jsonPair("program", currentProgram.getName()) + "}");
        }
    }

    private class InfoHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            respond(exchange, getProgramInfo());
        }
    }

    private class SegmentsHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            respond(exchange, getSegmentsList());
        }
    }

    private class FunctionHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");
            String name = body.get("name");

            Function func = null;
            if (addrStr != null && !addrStr.isEmpty()) {
                Address addr = parseAddress(addrStr);
                if (addr != null) {
                    func = currentProgram.getListing().getFunctionAt(addr);
                    if (func == null) {
                        func = currentProgram.getListing().getFunctionContaining(addr);
                    }
                }
            } else if (name != null && !name.isEmpty()) {
                func = findFunctionByName(name);
            } else {
                respondError(exchange, "Provide 'address' or 'name'", 400);
                return;
            }

            if (func == null) {
                respond(exchange, "{" + jsonPair("error", "No function found") + "}");
            } else {
                respond(exchange, functionToJson(func));
            }
        }
    }

    private class DisassembleHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");
            String name = body.get("name");
            String startStr = body.get("start");
            String endStr = body.get("end");

            if (startStr != null && endStr != null) {
                Address start = parseAddress(startStr);
                Address end = parseAddress(endStr);
                if (start != null && end != null) {
                    respond(exchange, disassembleRange(start, end));
                } else {
                    respondError(exchange, "Invalid start/end address", 400);
                }
                return;
            }

            Function func = null;
            if (name != null && !name.isEmpty()) {
                func = findFunctionByName(name);
                if (func == null) {
                    respond(exchange, "{" + jsonPair("error", "Function '" + name + "' not found") + "}");
                    return;
                }
            } else if (addrStr != null && !addrStr.isEmpty()) {
                Address addr = parseAddress(addrStr);
                if (addr != null) {
                    func = currentProgram.getListing().getFunctionAt(addr);
                    if (func == null) {
                        func = currentProgram.getListing().getFunctionContaining(addr);
                    }
                }
            }

            if (func == null) {
                respond(exchange, "{" + jsonPair("error", "No function at address") + "}");
            } else {
                respond(exchange, disassembleFunction(func));
            }
        }
    }

    private class DecompileHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");
            String name = body.get("name");

            Function func = null;
            if (name != null && !name.isEmpty()) {
                func = findFunctionByName(name);
                if (func == null) {
                    respond(exchange, "{" + jsonPair("error", "Function '" + name + "' not found") + "}");
                    return;
                }
            } else if (addrStr != null && !addrStr.isEmpty()) {
                Address addr = parseAddress(addrStr);
                if (addr != null) {
                    func = currentProgram.getListing().getFunctionAt(addr);
                    if (func == null) {
                        func = currentProgram.getListing().getFunctionContaining(addr);
                    }
                }
            } else {
                respondError(exchange, "Provide 'address' or 'name'", 400);
                return;
            }

            if (func == null) {
                respond(exchange, "{" + jsonPair("error", "No function at address") + "}");
            } else {
                respond(exchange, decompileFunction(func));
            }
        }
    }

    private class XrefsToHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");
            String name = body.get("name");

            Address addr = null;
            if (name != null && !name.isEmpty()) {
                Function func = findFunctionByName(name);
                if (func == null) {
                    respond(exchange, "{" + jsonPair("error", "Function '" + name + "' not found") + "}");
                    return;
                }
                addr = func.getEntryPoint();
            } else if (addrStr != null && !addrStr.isEmpty()) {
                addr = parseAddress(addrStr);
            }

            if (addr == null) {
                respondError(exchange, "Provide 'address' or 'name'", 400);
                return;
            }

            respond(exchange, getXrefsTo(addr));
        }
    }

    private class XrefsFromHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");

            if (addrStr == null || addrStr.isEmpty()) {
                respondError(exchange, "Provide 'address'", 400);
                return;
            }

            Address addr = parseAddress(addrStr);
            if (addr == null) {
                respondError(exchange, "Invalid address", 400);
                return;
            }

            respond(exchange, getXrefsFrom(addr));
        }
    }

    private class CallersHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");
            String name = body.get("name");

            Function func = null;
            if (name != null && !name.isEmpty()) {
                func = findFunctionByName(name);
            } else if (addrStr != null && !addrStr.isEmpty()) {
                Address addr = parseAddress(addrStr);
                if (addr != null) {
                    func = currentProgram.getListing().getFunctionAt(addr);
                    if (func == null) {
                        func = currentProgram.getListing().getFunctionContaining(addr);
                    }
                }
            }

            if (func == null) {
                respond(exchange, "{" + jsonPair("error", "Function not found") + "}");
                return;
            }

            respond(exchange, getCallers(func));
        }
    }

    private class CalleesHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");
            String name = body.get("name");

            Function func = null;
            if (name != null && !name.isEmpty()) {
                func = findFunctionByName(name);
            } else if (addrStr != null && !addrStr.isEmpty()) {
                Address addr = parseAddress(addrStr);
                if (addr != null) {
                    func = currentProgram.getListing().getFunctionAt(addr);
                    if (func == null) {
                        func = currentProgram.getListing().getFunctionContaining(addr);
                    }
                }
            }

            if (func == null) {
                respond(exchange, "{" + jsonPair("error", "Function not found") + "}");
                return;
            }

            respond(exchange, getCallees(func));
        }
    }

    private class SearchFunctionsHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String pattern = body.get("pattern");
            if (pattern == null || pattern.isEmpty()) {
                respondError(exchange, "Provide 'pattern'", 400);
                return;
            }
            respond(exchange, searchFunctions(pattern));
        }
    }

    private class SearchStringsHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String pattern = body.get("pattern");
            if (pattern == null || pattern.isEmpty()) {
                respondError(exchange, "Provide 'pattern'", 400);
                return;
            }
            respond(exchange, searchStrings(pattern));
        }
    }

    private class BytesHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");
            String sizeStr = body.get("size");

            if (addrStr == null || addrStr.isEmpty()) {
                respondError(exchange, "Provide 'address'", 400);
                return;
            }

            Address addr = parseAddress(addrStr);
            if (addr == null) {
                respondError(exchange, "Invalid address", 400);
                return;
            }

            int size = 256;
            if (sizeStr != null && !sizeStr.isEmpty()) {
                try {
                    size = Integer.parseInt(sizeStr);
                } catch (NumberFormatException e) {
                    // use default
                }
            }

            respond(exchange, readBytes(addr, size));
        }
    }

    private class RenameHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");
            String name = body.get("name");

            if (addrStr == null || name == null || addrStr.isEmpty() || name.isEmpty()) {
                respondError(exchange, "Provide 'address' and 'name'", 400);
                return;
            }

            Address addr = parseAddress(addrStr);
            if (addr == null) {
                respondError(exchange, "Invalid address", 400);
                return;
            }

            respond(exchange, renameAddress(addr, name));
        }
    }

    private class CommentHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");
            String comment = body.get("comment");
            String repeatableStr = body.get("repeatable");

            if (addrStr == null || addrStr.isEmpty()) {
                respondError(exchange, "Provide 'address' and 'comment'", 400);
                return;
            }

            Address addr = parseAddress(addrStr);
            if (addr == null) {
                respondError(exchange, "Invalid address", 400);
                return;
            }

            boolean repeatable = "true".equalsIgnoreCase(repeatableStr);
            respond(exchange, addComment(addr, comment != null ? comment : "", repeatable));
        }
    }

    private class CreateFunctionHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");
            String endStr = body.get("end");

            if (addrStr == null || addrStr.isEmpty()) {
                respondError(exchange, "Provide 'address'", 400);
                return;
            }

            Address addr = parseAddress(addrStr);
            if (addr == null) {
                respondError(exchange, "Invalid address", 400);
                return;
            }

            Address end = (endStr != null && !endStr.isEmpty()) ? parseAddress(endStr) : null;
            respond(exchange, createFunction(addr, end));
        }
    }

    private class DeleteFunctionHandler extends BaseHandler {
        void handleRequest(HttpExchange exchange) throws Exception {
            Map<String, String> body = parseJsonBody(exchange);
            String addrStr = body.get("address");

            if (addrStr == null || addrStr.isEmpty()) {
                respondError(exchange, "Provide 'address'", 400);
                return;
            }

            Address addr = parseAddress(addrStr);
            if (addr == null) {
                respondError(exchange, "Invalid address", 400);
                return;
            }

            respond(exchange, deleteFunction(addr));
        }
    }
}
