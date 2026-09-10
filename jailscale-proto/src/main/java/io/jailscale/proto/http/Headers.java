package io.jailscale.proto.http;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/** Case-insensitive, order-preserving HTTP header list. */
public final class Headers {

    private final List<String[]> entries = new ArrayList<>();

    public Headers add(String name, String value) {
        entries.add(new String[] {name, value});
        return this;
    }

    public Headers set(String name, String value) {
        remove(name);
        return add(name, value);
    }

    public void remove(String name) {
        entries.removeIf(e -> e[0].equalsIgnoreCase(name));
    }

    /** First value, or null. */
    public String get(String name) {
        for (String[] e : entries) {
            if (e[0].equalsIgnoreCase(name)) {
                return e[1];
            }
        }
        return null;
    }

    public List<String> all(String name) {
        List<String> out = new ArrayList<>();
        for (String[] e : entries) {
            if (e[0].equalsIgnoreCase(name)) {
                out.add(e[1]);
            }
        }
        return out;
    }

    public boolean contains(String name) {
        return get(name) != null;
    }

    /** True if a comma-separated header contains {@code token} (case-insensitive), e.g. Connection: Upgrade. */
    public boolean hasToken(String name, String token) {
        for (String v : all(name)) {
            for (String part : v.split(",")) {
                if (part.trim().toLowerCase(Locale.ROOT).equals(token.toLowerCase(Locale.ROOT))) {
                    return true;
                }
            }
        }
        return false;
    }

    public int size() {
        return entries.size();
    }

    public List<String[]> entries() {
        return Collections.unmodifiableList(entries);
    }
}
