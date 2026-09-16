package io.jailscale.node;

import io.jailscale.proto.util.Sha256;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
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
    /** The request line of the one method whose answer carries no body, with its trailing space. */
    private static final byte[] HEAD_METHOD = "HEAD ".getBytes(StandardCharsets.ISO_8859_1);
    /** How many bytes {@link #isHead} needs before its answer means anything. */
    static final int METHOD_BYTES = HEAD_METHOD.length;

    private Gate() {}

    /**
     * What to do with a connection after reading its first request head. The two that are answered
     * here rather than relayed carry {@code headOnly}: the visitor path parses no request, so the
     * method the answer is framed by (RFC 9110 §9.3.2) has to come out of the head the gate read.
     */
    sealed interface Decision {
        /** Cookie valid: relay, starting with the bytes already read. */
        record Pass(byte[] head) implements Decision {}

        /** Query token valid: set the cookie and redirect to the same path without the token. */
        record SetCookie(String token, String location, boolean headOnly) implements Decision {}

        /** No valid token. */
        record Refuse(boolean headOnly) implements Decision {}
    }

    static String newToken() {
        byte[] b = new byte[16];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    static String hash(String token) {
        return Sha256.hex(token);
    }

    /**
     * Reads the request head (through the blank line) and decides. {@code validHash} is the
     * stored token hash; {@code expired} short-circuits to Refuse.
     */
    static Decision decide(InputStream in, String validHash, boolean expired) throws IOException {
        // The method has to survive the two ways readHead gives up: at EOF there was no request
        // line to read one from, but over the limit there was, and it was read before the header
        // that went past MAX_HEAD. Filled as the head is read, so both cases have it, and a head
        // shorter than the method leaves zeroes here, which are not a method either.
        byte[] prefix = new byte[METHOD_BYTES];
        byte[] head = readHead(in, prefix);
        boolean headOnly = isHead(prefix, prefix.length);
        if (head == null || expired) {
            return new Decision.Refuse(headOnly);
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
                return new Decision.SetCookie(token, (path.isEmpty() ? "/" : path) + rest, headOnly);
            }
        }
        return new Decision.Refuse(headOnly);
    }

    /**
     * Whether a request begins with {@code HEAD}, which is the whole of what the visitor path needs
     * from a request it otherwise never parses. A byte compare and not a parse, because method
     * tokens are case-sensitive (RFC 9110 §9.1) and because the callers have a raw buffer and a
     * length rather than anything parsed. {@code len} is how many bytes of {@code head} were read,
     * and fewer than the method is not the method: a caller that cannot count them may pass the
     * buffer's length instead only if it is one nothing else has written to, where the unread
     * bytes are zeroes and zeroes do not match either.
     */
    static boolean isHead(byte[] head, int len) {
        if (len < HEAD_METHOD.length) {
            return false;
        }
        for (int i = 0; i < HEAD_METHOD.length; i++) {
            if (head[i] != HEAD_METHOD[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Bytes up to and including the first blank line, or null at EOF / over the limit. {@code
     * prefix} is filled with the first bytes read, however it ends, so that a caller that gave up
     * on the head still has the method that started it.
     */
    static byte[] readHead(InputStream in, byte[] prefix) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(1024);
        int match = 0;
        int c;
        while ((c = in.read()) >= 0) {
            if (buf.size() < prefix.length) {
                prefix[buf.size()] = (byte) c;
            }
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
