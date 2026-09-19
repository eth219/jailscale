package io.jailscale.proto.http;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

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
        return values(name).findFirst().orElse(null);
    }

    public List<String> all(String name) {
        return values(name).toList();
    }

    private Stream<String> values(String name) {
        return entries.stream().filter(e -> e[0].equalsIgnoreCase(name)).map(e -> e[1]);
    }

    public boolean contains(String name) {
        return get(name) != null;
    }

    /** True if a comma-separated header contains {@code token} (case-insensitive), e.g. Connection: Upgrade. */
    public boolean hasToken(String name, String token) {
        String want = token.toLowerCase(Locale.ROOT);
        return values(name).flatMap(v -> Arrays.stream(v.split(",")))
            .anyMatch(part -> part.trim().toLowerCase(Locale.ROOT).equals(want));
    }

    public int size() {
        return entries.size();
    }

    public List<String[]> entries() {
        return Collections.unmodifiableList(entries);
    }
}
