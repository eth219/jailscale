package io.jailscale.node;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

/**
 * The visitor gate (ARCHITECTURE.md §9.3): a link can require a visit token, carried once as
 * {@code ?jail=<token>} and then as a cookie. Only the first request head of a TLS connection is
 * inspected; the connection is then either relayed whole, redirected, or refused.
 */
final class Gate {

    static final String COOKIE = "jail";
    static final int MAX_HEAD = 16 * 1024;
    private static final SecureRandom RNG = new SecureRandom();

    private Gate() {}

    /** What to do with a connection after reading its first request head. */
    sealed interface Decision {
        /** Cookie valid: relay, starting with the bytes already read. */
        record Pass(byte[] head) implements Decision {}

        /** Query token valid: set the cookie and redirect to the same path without the token. */
        record SetCookie(String token, String location) implements Decision {}

        /** No valid token. */
        record Refuse() implements Decision {}
    }

    static String newToken() {
        byte[] b = new byte[16];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static String hash(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Reads the request head (through the blank line) and decides. {@code validHash} is the
     * stored token hash; {@code expired} short-circuits to Refuse.
     */
    static Decision decide(InputStream in, String validHash, boolean expired) throws IOException {
        byte[] head = readHead(in);
        if (head == null) {
            return new Decision.Refuse();
        }
        if (expired) {
            return new Decision.Refuse();
        }
        String text = new String(head, StandardCharsets.ISO_8859_1);
        int eol = text.indexOf("\r\n");
        String requestLine = eol < 0 ? text : text.substring(0, eol);
        String[] parts = requestLine.split(" ");
        String target = parts.length >= 2 ? parts[1] : "/";
        // cookie?
        for (String line : text.split("\r\n")) {
            int c = line.indexOf(':');
            if (c > 0 && line.substring(0, c).trim().toLowerCase(Locale.ROOT).equals("cookie")) {
                for (String kv : line.substring(c + 1).split(";")) {
                    String[] p = kv.trim().split("=", 2);
                    if (p.length == 2 && p[0].trim().equals(COOKIE) && hash(p[1].trim()).equals(validHash)) {
                        return new Decision.Pass(head);
                    }
                }
            }
        }
        // query token?
        int q = target.indexOf('?');
        if (q >= 0) {
            String path = target.substring(0, q);
            StringBuilder rest = new StringBuilder();
            String token = null;
            for (String kv : target.substring(q + 1).split("&")) {
                if (kv.startsWith(COOKIE + "=")) {
                    token = kv.substring(COOKIE.length() + 1);
                } else if (!kv.isEmpty()) {
                    rest.append(rest.length() == 0 ? "?" : "&").append(kv);
                }
            }
            if (token != null && hash(token).equals(validHash)) {
                return new Decision.SetCookie(token, (path.isEmpty() ? "/" : path) + rest);
            }
        }
        return new Decision.Refuse();
    }

    /** Bytes up to and including the first blank line, or null at EOF / over the limit. */
    static byte[] readHead(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(1024);
        int match = 0;
        int c;
        while ((c = in.read()) >= 0) {
            buf.write(c);
            if (buf.size() > MAX_HEAD) {
                return null;
            }
            // detect \r\n\r\n
            if ((match == 0 || match == 2) && c == '\r') {
                match++;
            } else if ((match == 1 || match == 3) && c == '\n') {
                match++;
                if (match == 4) {
                    return buf.toByteArray();
                }
            } else {
                match = c == '\r' ? 1 : 0;
            }
        }
        return null;
    }
}
