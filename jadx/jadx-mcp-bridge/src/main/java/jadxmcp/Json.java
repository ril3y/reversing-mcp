// Minimal hand-rolled JSON writer + flat-object reader.  Keeps the bridge
// dependency-free (no Jackson/Gson) since the MCP wire format is small.
package jadxmcp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class Json {

    private Json() {}

    // --- Writer ------------------------------------------------------------

    static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    static String str(String key, String value) {
        return "\"" + key + "\":\"" + esc(value) + "\"";
    }

    static String num(String key, long value) {
        return "\"" + key + "\":" + value;
    }

    static String bool(String key, boolean value) {
        return "\"" + key + "\":" + value;
    }

    static String raw(String key, String json) {
        return "\"" + key + "\":" + json;
    }

    static String object(String... kvPairs) {
        StringBuilder sb = new StringBuilder("{");
        for (int i = 0; i < kvPairs.length; i++) {
            if (i > 0) sb.append(",");
            sb.append(kvPairs[i]);
        }
        return sb.append("}").toString();
    }

    static String array(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(items.get(i));
        }
        return sb.append("]").toString();
    }

    static String error(String message) {
        return object(str("error", message));
    }

    // --- Reader (flat string/number/boolean objects only) ------------------

    static Map<String, String> parseFlat(String body) {
        Map<String, String> out = new LinkedHashMap<>();
        if (body == null) return out;
        String s = body.trim();
        if (s.isEmpty() || s.charAt(0) != '{') return out;
        int end = s.lastIndexOf('}');
        if (end < 1) return out;
        s = s.substring(1, end);

        int i = 0;
        while (i < s.length()) {
            int ks = s.indexOf('"', i);
            if (ks < 0) break;
            int ke = findClosingQuote(s, ks + 1);
            if (ke < 0) break;
            String key = unescape(s.substring(ks + 1, ke));

            int colon = s.indexOf(':', ke + 1);
            if (colon < 0) break;
            int vs = colon + 1;
            while (vs < s.length() && Character.isWhitespace(s.charAt(vs))) vs++;
            if (vs >= s.length()) break;

            String value;
            if (s.charAt(vs) == '"') {
                int ve = findClosingQuote(s, vs + 1);
                if (ve < 0) break;
                value = unescape(s.substring(vs + 1, ve));
                i = ve + 1;
            } else {
                int ve = vs;
                while (ve < s.length() && s.charAt(ve) != ',' && s.charAt(ve) != '}') ve++;
                value = s.substring(vs, ve).trim();
                i = ve;
            }
            out.put(key, value);
            while (i < s.length() && (s.charAt(i) == ',' || Character.isWhitespace(s.charAt(i)))) i++;
        }
        return out;
    }

    private static int findClosingQuote(String s, int from) {
        for (int i = from; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') { i++; continue; }
            if (c == '"') return i;
        }
        return -1;
    }

    private static String unescape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                switch (n) {
                    case '"':  sb.append('"');  break;
                    case '\\': sb.append('\\'); break;
                    case 'n':  sb.append('\n'); break;
                    case 'r':  sb.append('\r'); break;
                    case 't':  sb.append('\t'); break;
                    default:   sb.append(n);
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
