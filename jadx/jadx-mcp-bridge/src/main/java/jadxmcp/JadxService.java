// Wraps jadx-core: loads an APK/JAR once and serves read-only queries.
//
// The jadx-core API gives us lazy per-class decompilation; getCode() triggers
// the decompilation pass for a class and the result is cached internally.
package jadxmcp;

import jadx.api.JadxArgs;
import jadx.api.JadxDecompiler;
import jadx.api.JavaClass;
import jadx.api.JavaMethod;
import jadx.api.JavaNode;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class JadxService {

    private final JadxDecompiler decompiler;
    private final File inputFile;

    JadxService(File inputFile) {
        this.inputFile = inputFile;
        JadxArgs args = new JadxArgs();
        args.setInputFile(inputFile);
        args.setShowInconsistentCode(true);
        args.setSkipResources(true);          // we don't need res/ for code queries
        args.setSkipSources(false);
        this.decompiler = new JadxDecompiler(args);
        this.decompiler.load();
    }

    File getInputFile() {
        return inputFile;
    }

    // --- Info --------------------------------------------------------------

    synchronized int classCount() {
        return decompiler.getClasses().size();
    }

    synchronized int methodCount() {
        int n = 0;
        for (JavaClass c : decompiler.getClasses()) {
            n += c.getMethods().size();
        }
        return n;
    }

    // --- Class lookup ------------------------------------------------------

    /** Exact full-name match first, then case-insensitive substring. */
    synchronized JavaClass findClass(String name) {
        if (name == null || name.isEmpty()) return null;
        // jadx public API: linear scan is fine — classes list is the index.
        for (JavaClass c : decompiler.getClasses()) {
            if (c.getFullName().equals(name)) return c;
        }
        String low = name.toLowerCase();
        for (JavaClass c : decompiler.getClasses()) {
            if (c.getFullName().toLowerCase().contains(low)) return c;
        }
        return null;
    }

    synchronized List<JavaClass> listClasses(String prefix, int limit) {
        List<JavaClass> out = new ArrayList<>();
        boolean noPrefix = prefix == null || prefix.isEmpty();
        for (JavaClass c : decompiler.getClasses()) {
            if (noPrefix || c.getFullName().startsWith(prefix)) {
                out.add(c);
                if (out.size() >= limit) break;
            }
        }
        return out;
    }

    synchronized List<JavaClass> searchClasses(String pattern, int limit) {
        if (pattern == null || pattern.isEmpty()) return Collections.emptyList();
        String low = pattern.toLowerCase();
        List<JavaClass> out = new ArrayList<>();
        for (JavaClass c : decompiler.getClasses()) {
            if (c.getFullName().toLowerCase().contains(low)) {
                out.add(c);
                if (out.size() >= limit) break;
            }
        }
        return out;
    }

    // --- Decompile ---------------------------------------------------------

    synchronized String decompileClass(JavaClass c) {
        return c.getCode();
    }

    /** Locate a method by name or shortId (e.g., "foo(II)V"). */
    synchronized JavaMethod findMethod(JavaClass c, String method) {
        if (method == null || method.isEmpty()) return null;
        // shortId match wins (lets caller disambiguate overloads)
        for (JavaMethod m : c.getMethods()) {
            if (m.getMethodNode().getMethodInfo().getShortId().equals(method)) return m;
        }
        for (JavaMethod m : c.getMethods()) {
            if (m.getName().equals(method)) return m;
        }
        return null;
    }

    /** Extract a single method's source by slicing the class at its def-pos byte offset. */
    synchronized String decompileMethod(JavaClass c, JavaMethod m) {
        String source = c.getCode();
        int defPos = m.getDefPos();                 // 0-based byte offset; 0 if unknown
        if (defPos <= 0 || defPos >= source.length()) {
            return source;
        }
        // Back up to the start of the method's signature line so we include
        // modifiers / return type, not just the body.
        int start = defPos;
        while (start > 0 && source.charAt(start - 1) != '\n') start--;

        // Find next line where brace depth returns to the depth at method start.
        // We expect "...signature... {" near `start`; track {/} from there.
        int depth = 0;
        boolean enteredBody = false;
        int i = start;
        while (i < source.length()) {
            char ch = source.charAt(i);
            if (ch == '{') { depth++; enteredBody = true; }
            else if (ch == '}') {
                depth--;
                if (enteredBody && depth == 0) {
                    int end = i + 1;
                    if (end < source.length() && source.charAt(end) == '\n') end++;
                    return source.substring(start, end);
                }
            }
            i++;
        }
        return source.substring(start);
    }

    /** 1-based line number for a class-source byte offset (e.g. from JavaMethod.getDefPos). */
    synchronized int lineForOffset(JavaClass c, int offset) {
        return lineOfOffset(c.getCode(), offset);
    }

    // --- Xrefs -------------------------------------------------------------

    synchronized List<JavaNode> usesOfClass(JavaClass c) {
        return new ArrayList<>(c.getUseIn());
    }

    synchronized List<JavaNode> usesOfMethod(JavaMethod m) {
        return new ArrayList<>(m.getUseIn());
    }

    // --- String search (decompiled-source scan, cached by jadx) -----------

    /**
     * Scan every class's decompiled source for the pattern.  First call is
     * expensive (forces decompilation of all classes); subsequent calls hit
     * jadx's internal cache.
     */
    synchronized List<StringHit> searchStrings(String pattern, int limit) {
        if (pattern == null || pattern.isEmpty()) return Collections.emptyList();
        List<StringHit> out = new ArrayList<>();
        for (JavaClass c : decompiler.getClasses()) {
            String code = c.getCode();
            int idx = 0;
            while (true) {
                int hit = code.indexOf(pattern, idx);
                if (hit < 0) break;
                out.add(new StringHit(c.getFullName(), lineOfOffset(code, hit), snippet(code, hit, pattern.length())));
                if (out.size() >= limit) return out;
                idx = hit + pattern.length();
            }
        }
        return out;
    }

    private static int lineOfOffset(String s, int off) {
        int line = 1;
        for (int i = 0; i < off && i < s.length(); i++) {
            if (s.charAt(i) == '\n') line++;
        }
        return line;
    }

    private static String snippet(String s, int hit, int hitLen) {
        int lineStart = s.lastIndexOf('\n', hit) + 1;
        int lineEnd = s.indexOf('\n', hit + hitLen);
        if (lineEnd < 0) lineEnd = s.length();
        String line = s.substring(lineStart, lineEnd);
        if (line.length() > 240) {
            int relHit = hit - lineStart;
            int from = Math.max(0, relHit - 80);
            int to = Math.min(line.length(), relHit + 160);
            line = "..." + line.substring(from, to) + "...";
        }
        return line;
    }

    static final class StringHit {
        final String className;
        final int line;
        final String snippet;
        StringHit(String className, int line, String snippet) {
            this.className = className;
            this.line = line;
            this.snippet = snippet;
        }
    }
}
