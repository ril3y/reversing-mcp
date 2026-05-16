package jadxmcp;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonTest {

    @Test
    void escapesControlChars() {
        assertEquals("a\\nb\\tc\\\"d", Json.esc("a\nb\tc\"d"));
    }

    @Test
    void writesObject() {
        String s = Json.object(Json.str("k", "v"), Json.num("n", 7));
        assertEquals("{\"k\":\"v\",\"n\":7}", s);
    }

    @Test
    void parsesFlatStringObject() {
        Map<String, String> m = Json.parseFlat("{\"a\":\"hello\",\"b\":\"world\"}");
        assertEquals("hello", m.get("a"));
        assertEquals("world", m.get("b"));
    }

    @Test
    void parsesNumbersAsStrings() {
        Map<String, String> m = Json.parseFlat("{\"limit\":42}");
        assertEquals("42", m.get("limit"));
    }

    @Test
    void handlesEscapedQuoteInString() {
        Map<String, String> m = Json.parseFlat("{\"k\":\"a\\\"b\"}");
        assertEquals("a\"b", m.get("k"));
    }

    @Test
    void emptyOnGarbage() {
        assertTrue(Json.parseFlat("").isEmpty());
        assertTrue(Json.parseFlat("not json").isEmpty());
        assertTrue(Json.parseFlat("[]").isEmpty());
    }
}
