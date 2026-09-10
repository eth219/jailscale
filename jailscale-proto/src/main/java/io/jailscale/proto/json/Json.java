package io.jailscale.proto.json;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small RFC 8259 parser and writer with no reflection (DESIGN.md §4).
 *
 * <p>Values map to plain Java: object → {@link LinkedHashMap}, array → {@link ArrayList},
 * string → {@link String}, integer → {@link Long}, other numbers → {@link Double},
 * true/false → {@link Boolean}, null → {@code null}. Use {@link JsonObject} for typed access.
 *
 * <p>Limits: 64 levels of nesting, and the caller bounds the input size (the wire layer caps
 * a control frame at a Noise message).
 */
public final class Json {

    private static final int MAX_DEPTH = 64;

    private Json() {}

    public static Object parse(String text) {
        Parser p = new Parser(text);
        p.skipWs();
        Object v = p.value(0);
        p.skipWs();
        if (p.pos != text.length()) {
            throw p.error("trailing characters");
        }
        return v;
    }

    public static Object parse(byte[] utf8) {
        return parse(new String(utf8, StandardCharsets.UTF_8));
    }

    public static JsonObject parseObject(String text) {
        Object v = parse(text);
        if (!(v instanceof Map<?, ?> m)) {
            throw new JsonException("expected a JSON object");
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> map = (Map<String, Object>) m;
        return new JsonObject(map);
    }

    public static JsonObject parseObject(byte[] utf8) {
        return parseObject(new String(utf8, StandardCharsets.UTF_8));
    }

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder(64);
        write(sb, value, 0);
        return sb.toString();
    }

    public static byte[] writeUtf8(Object value) {
        return write(value).getBytes(StandardCharsets.UTF_8);
    }

    static void write(StringBuilder sb, Object v, int depth) {
        if (depth > MAX_DEPTH) {
            throw new JsonException("nesting too deep");
        }
        switch (v) {
            case null -> sb.append("null");
            case JsonObject o -> write(sb, o.asMap(), depth);
            case Map<?, ?> m -> {
                sb.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> e : m.entrySet()) {
                    if (!first) {
                        sb.append(',');
                    }
                    first = false;
                    writeString(sb, String.valueOf(e.getKey()));
                    sb.append(':');
                    write(sb, e.getValue(), depth + 1);
                }
                sb.append('}');
            }
            case List<?> l -> {
                sb.append('[');
                boolean first = true;
                for (Object o : l) {
                    if (!first) {
                        sb.append(',');
                    }
                    first = false;
                    write(sb, o, depth + 1);
                }
                sb.append(']');
            }
            case String s -> writeString(sb, s);
            case Boolean b -> sb.append(b.booleanValue());
            case Integer i -> sb.append(i.intValue());
            case Long l -> sb.append(l.longValue());
            case Double d -> {
                if (d.isNaN() || d.isInfinite()) {
                    throw new JsonException("non-finite number");
                }
                sb.append(d.doubleValue());
            }
            case Number n -> sb.append(n);
            default -> throw new JsonException("unsupported value type " + v.getClass().getName());
        }
    }

    static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            this.s = s;
        }

        JsonException error(String msg) {
            return new JsonException(msg + " at offset " + pos);
        }

        void skipWs() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        Object value(int depth) {
            if (depth > MAX_DEPTH) {
                throw error("nesting too deep");
            }
            if (pos >= s.length()) {
                throw error("unexpected end");
            }
            char c = s.charAt(pos);
            switch (c) {
                case '{':
                    return object(depth);
                case '[':
                    return array(depth);
                case '"':
                    return string();
                case 't':
                    literal("true");
                    return Boolean.TRUE;
                case 'f':
                    literal("false");
                    return Boolean.FALSE;
                case 'n':
                    literal("null");
                    return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return number();
                    }
                    throw error("unexpected character '" + c + "'");
            }
        }

        private Map<String, Object> object(int depth) {
            Map<String, Object> m = new LinkedHashMap<>();
            pos++; // {
            skipWs();
            if (peek() == '}') {
                pos++;
                return m;
            }
            while (true) {
                skipWs();
                if (peek() != '"') {
                    throw error("expected string key");
                }
                String k = string();
                skipWs();
                if (peek() != ':') {
                    throw error("expected ':'");
                }
                pos++;
                skipWs();
                m.put(k, value(depth + 1));
                skipWs();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == '}') {
                    pos++;
                    return m;
                } else {
                    throw error("expected ',' or '}'");
                }
            }
        }

        private List<Object> array(int depth) {
            List<Object> l = new ArrayList<>();
            pos++; // [
            skipWs();
            if (peek() == ']') {
                pos++;
                return l;
            }
            while (true) {
                skipWs();
                l.add(value(depth + 1));
                skipWs();
                char c = peek();
                if (c == ',') {
                    pos++;
                } else if (c == ']') {
                    pos++;
                    return l;
                } else {
                    throw error("expected ',' or ']'");
                }
            }
        }

        private String string() {
            pos++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= s.length()) {
                    throw error("unterminated string");
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (pos >= s.length()) {
                        throw error("unterminated escape");
                    }
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 > s.length()) {
                                throw error("bad \\u escape");
                            }
                            int cp;
                            try {
                                cp = Integer.parseInt(s, pos, pos + 4, 16);
                            } catch (NumberFormatException ex) {
                                throw error("bad \\u escape");
                            }
                            pos += 4;
                            sb.append((char) cp);
                        }
                        default -> throw error("bad escape '\\" + e + "'");
                    }
                } else if (c < 0x20) {
                    throw error("control character in string");
                } else {
                    sb.append(c);
                }
            }
        }

        private Number number() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            boolean integral = true;
            if (peek() == '0') {
                pos++;
            } else if (peek() >= '1' && peek() <= '9') {
                while (peek() >= '0' && peek() <= '9') {
                    pos++;
                }
            } else {
                throw error("bad number");
            }
            if (peek() == '.') {
                integral = false;
                pos++;
                if (!(peek() >= '0' && peek() <= '9')) {
                    throw error("bad number");
                }
                while (peek() >= '0' && peek() <= '9') {
                    pos++;
                }
            }
            if (peek() == 'e' || peek() == 'E') {
                integral = false;
                pos++;
                if (peek() == '+' || peek() == '-') {
                    pos++;
                }
                if (!(peek() >= '0' && peek() <= '9')) {
                    throw error("bad number");
                }
                while (peek() >= '0' && peek() <= '9') {
                    pos++;
                }
            }
            String t = s.substring(start, pos);
            try {
                if (integral) {
                    return Long.parseLong(t);
                }
                return Double.parseDouble(t);
            } catch (NumberFormatException ex) {
                // integer too large for long: fall back to double like most parsers do
                return Double.parseDouble(t);
            }
        }

        private void literal(String lit) {
            if (!s.startsWith(lit, pos)) {
                throw error("expected " + lit);
            }
            pos += lit.length();
        }

        private char peek() {
            return pos < s.length() ? s.charAt(pos) : '\0';
        }
    }
}
