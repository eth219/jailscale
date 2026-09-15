package io.jailscale.proto.json;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Typed, null-safe access to a parsed JSON object, plus a builder for writing one.
 * Getters without {@code opt} throw {@link JsonException} when the field is absent or of the
 * wrong type, which is what a wire-message decoder wants.
 */
public final class JsonObject {

    private final Map<String, Object> map;

    JsonObject(Map<String, Object> map) {
        this.map = map;
    }

    public static Builder builder() {
        return new Builder();
    }

    public boolean has(String key) {
        return map.containsKey(key) && map.get(key) != null;
    }

    /**
     * Wraps a map that is already parsed. The alternative callers reached for was
     * {@code Json.parseObject(Json.write(map))}, which is a StringBuilder, a String, a full
     * tokenize and a second map for a value that was in hand -- about twenty objects an event, on
     * every snapshot replay including the one at startup.
     */
    public static JsonObject of(Map<String, Object> map) {
        return new JsonObject(map);
    }

    public Map<String, Object> asMap() {
        return Collections.unmodifiableMap(map);
    }

    public String string(String key) {
        Object v = required(key);
        if (v instanceof String s) {
            return s;
        }
        throw wrongType(key, "string");
    }

    public String optString(String key, String dflt) {
        Object v = map.get(key);
        if (v == null) {
            return dflt;
        }
        if (v instanceof String s) {
            return s;
        }
        throw wrongType(key, "string");
    }

    public long lng(String key) {
        Object v = required(key);
        if (v instanceof Long l) {
            return l;
        }
        if (v instanceof Double d && d == Math.rint(d) && Math.abs(d) < 9.007199254740992E15) {
            return d.longValue();
        }
        throw wrongType(key, "integer");
    }

    public Long optLong(String key) {
        return map.get(key) == null ? null : lng(key);
    }

    public int integer(String key) {
        long l = lng(key);
        if (l < Integer.MIN_VALUE || l > Integer.MAX_VALUE) {
            throw wrongType(key, "32-bit integer");
        }
        return (int) l;
    }

    public int optInt(String key, int dflt) {
        return map.get(key) == null ? dflt : integer(key);
    }

    public boolean bool(String key) {
        Object v = required(key);
        if (v instanceof Boolean b) {
            return b;
        }
        throw wrongType(key, "boolean");
    }

    public boolean optBool(String key, boolean dflt) {
        return map.get(key) == null ? dflt : bool(key);
    }

    public JsonObject object(String key) {
        Object v = required(key);
        if (v instanceof Map<?, ?> m) {
            @SuppressWarnings("unchecked")
            Map<String, Object> mm = (Map<String, Object>) m;
            return new JsonObject(mm);
        }
        throw wrongType(key, "object");
    }

    public List<Object> array(String key) {
        Object v = required(key);
        if (v instanceof List<?> l) {
            @SuppressWarnings("unchecked")
            List<Object> ll = (List<Object>) l;
            return Collections.unmodifiableList(ll);
        }
        throw wrongType(key, "array");
    }

    public List<String> stringArray(String key) {
        List<String> out = new ArrayList<>();
        for (Object o : array(key)) {
            if (!(o instanceof String s)) {
                throw wrongType(key, "array of strings");
            }
            out.add(s);
        }
        return out;
    }

    /** Base64url (no padding) encoded bytes. */
    public byte[] bytes(String key) {
        try {
            return Base64.getUrlDecoder().decode(string(key));
        } catch (IllegalArgumentException e) {
            throw wrongType(key, "base64url");
        }
    }

    public byte[] optBytes(String key) {
        return map.get(key) == null ? null : bytes(key);
    }

    @Override
    public String toString() {
        return Json.write(map);
    }

    private Object required(String key) {
        Object v = map.get(key);
        if (v == null) {
            throw new JsonException("missing field '" + key + "'");
        }
        return v;
    }

    private JsonException wrongType(String key, String expected) {
        return new JsonException("field '" + key + "' is not a " + expected);
    }

    /** Insertion-ordered builder. Null values are omitted. */
    public static final class Builder {
        private final Map<String, Object> map = new LinkedHashMap<>();

        Builder() {}

        public Builder put(String key, String value) {
            if (value != null) {
                map.put(key, value);
            }
            return this;
        }

        public Builder put(String key, long value) {
            map.put(key, value);
            return this;
        }

        public Builder put(String key, Long value) {
            if (value != null) {
                map.put(key, value);
            }
            return this;
        }

        public Builder put(String key, Integer value) {
            if (value != null) {
                map.put(key, (long) value);
            }
            return this;
        }

        public Builder put(String key, boolean value) {
            map.put(key, value);
            return this;
        }

        public Builder put(String key, JsonObject value) {
            if (value != null) {
                map.put(key, value.map);
            }
            return this;
        }

        public Builder put(String key, List<?> value) {
            if (value != null) {
                map.put(key, value);
            }
            return this;
        }

        /** Stored as base64url without padding. */
        public Builder putBytes(String key, byte[] value) {
            if (value != null) {
                map.put(key, Base64.getUrlEncoder().withoutPadding().encodeToString(value));
            }
            return this;
        }

        public JsonObject build() {
            return new JsonObject(map);
        }

        public String toJson() {
            return Json.write(map);
        }
    }
}
