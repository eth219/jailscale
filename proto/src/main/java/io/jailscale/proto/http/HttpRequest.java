package io.jailscale.proto.http;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** A parsed HTTP/1.1 request: method, target, headers and a fully buffered body. */
public record HttpRequest(String method, String target, String version, Headers headers, byte[] body) {

    /** Path part of the target, without the query string. */
    public String path() {
        int q = target.indexOf('?');
        return q < 0 ? target : target.substring(0, q);
    }

    /** Decoded query parameters (first value wins). */
    public Map<String, String> query() {
        int q = target.indexOf('?');
        return q < 0 ? Map.of() : parseForm(target.substring(q + 1));
    }

    /** {@code application/x-www-form-urlencoded} body fields. */
    public Map<String, String> form() {
        String ct = headers.get("Content-Type");
        if (ct == null || !ct.toLowerCase(java.util.Locale.ROOT).startsWith("application/x-www-form-urlencoded")) {
            return Map.of();
        }
        return parseForm(new String(body, StandardCharsets.UTF_8));
    }

    public boolean wantsUpgrade(String protocol) {
        return headers.hasToken("Connection", "upgrade") && protocol.equalsIgnoreCase(headers.get("Upgrade"));
    }

    static Map<String, String> parseForm(String s) {
        Map<String, String> m = new LinkedHashMap<>();
        for (String pair : s.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            m.putIfAbsent(URLDecoder.decode(k, StandardCharsets.UTF_8), URLDecoder.decode(v, StandardCharsets.UTF_8));
        }
        return m;
    }
}
