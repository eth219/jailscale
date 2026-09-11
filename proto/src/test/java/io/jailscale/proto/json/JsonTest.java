package io.jailscale.proto.json;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JsonTest {

    @Test
    void parsesAllValueTypes() {
        Object v = Json.parse(" {\"a\": [1, -2.5, 3e2, true, false, null, \"s\\n\\u00e9\\\"\"], \"b\": {}, \"c\": []} ");
        assertTrue(v instanceof Map);
        Map<?, ?> m = (Map<?, ?>) v;
        List<?> a = (List<?>) m.get("a");
        assertEquals(1L, a.get(0));
        assertEquals(-2.5, a.get(1));
        assertEquals(300.0, a.get(2));
        assertEquals(Boolean.TRUE, a.get(3));
        assertEquals(Boolean.FALSE, a.get(4));
        assertNull(a.get(5));
        assertEquals("s\n\u00e9\"", a.get(6));
        assertEquals(Map.of(), m.get("b"));
        assertEquals(List.of(), m.get("c"));
    }

    @Test
    void writeThenParseRoundTrips() {
        String json = JsonObject.builder()
            .put("t", "Hello").put("proto", 1).put("neg", -7L).put("flag", true)
            .put("nested", JsonObject.builder().put("x", "y\"z").build())
            .put("list", List.of("a", 2L))
            .putBytes("bin", new byte[] {0, 1, 2, (byte) 0xff})
            .put("absent", (String) null)
            .toJson();
        assertEquals("{\"t\":\"Hello\",\"proto\":1,\"neg\":-7,\"flag\":true,\"nested\":{\"x\":\"y\\\"z\"},"
            + "\"list\":[\"a\",2],\"bin\":\"AAEC_w\"}", json);
        JsonObject o = Json.parseObject(json);
        assertEquals("Hello", o.string("t"));
        assertEquals(1, o.integer("proto"));
        assertEquals(-7L, o.lng("neg"));
        assertTrue(o.bool("flag"));
        assertEquals("y\"z", o.object("nested").string("x"));
        assertEquals(List.of("a", 2L), o.array("list"));
        assertEquals(4, o.bytes("bin").length);
        assertEquals((byte) 0xff, o.bytes("bin")[3]);
        assertEquals("dflt", o.optString("absent", "dflt"));
        assertEquals(json, o.toString());
    }

    @Test
    void controlCharactersAndUnicodeAreEscaped() {
        assertEquals("\"\\u0001\\t\\\\\\/x\"".replace("\\/", "/"), Json.write("\u0001\t\\/x"));
        assertEquals("\"\uD55C\uAE00\"", Json.write("\uD55C\uAE00"));
        assertEquals("\uD55C\uAE00", Json.parse("\"\\ud55c\\uae00\""));
    }

    @Test
    void rejectsMalformedInput() {
        for (String bad : new String[] {"", "{", "[1,]", "{\"a\":}", "{a:1}", "\"unterminated", "01", "1.", "-",
            "tru", "nul", "{\"a\":1}x", "\"\\x\"", "\"\t\"", "[1 2]", "{\"a\" 1}"}) {
            assertThrows(JsonException.class, () -> Json.parse(bad), bad);
        }
        assertThrows(JsonException.class, () -> Json.parseObject("[1]"));
        assertThrows(JsonException.class, () -> Json.write(Double.NaN));
    }

    @Test
    void rejectsDeepNesting() {
        String deep = "[".repeat(100) + "]".repeat(100);
        assertThrows(JsonException.class, () -> Json.parse(deep));
    }

    @Test
    void typedAccessorsFailLoudly() {
        JsonObject o = Json.parseObject("{\"s\":\"x\",\"n\":1.5,\"big\":4294967296,\"b\":true,\"z\":null}");
        assertThrows(JsonException.class, () -> o.lng("s"));
        assertThrows(JsonException.class, () -> o.lng("n"));
        assertThrows(JsonException.class, () -> o.integer("big"));
        assertEquals(4294967296L, o.lng("big"));
        assertThrows(JsonException.class, () -> o.string("b"));
        assertThrows(JsonException.class, () -> o.string("z"));
        assertThrows(JsonException.class, () -> o.string("missing"));
        assertNull(o.optLong("z"));
        assertTrue(o.has("s"));
        assertTrue(!o.has("z"));
    }
}
