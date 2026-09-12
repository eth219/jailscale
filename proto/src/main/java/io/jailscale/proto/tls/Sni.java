package io.jailscale.proto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Reads a TLS ClientHello off a raw socket without opening TLS and extracts the server_name
 * extension (ARCHITECTURE.md §8.1). The bytes consumed are returned so they can be replayed to
 * whoever terminates the connection.
 */
public final class Sni {

    /** A ClientHello larger than this is not from a browser we care about. */
    public static final int MAX_CLIENT_HELLO = 16 * 1024;
    /**
     * What a server_name may contain. Compiled once: this runs on the 443 accept path, once per
     * visitor connection and before anything has been authenticated, so a {@code String.matches}
     * here would compile the same pattern for every connection anyone makes.
     */
    private static final Pattern HOST = Pattern.compile("[a-z0-9.-]+");

    private Sni() {}

    /** The peeked bytes and the SNI (null if the hello carries none). */
    public record Peek(byte[] consumed, String serverName) {}

    /**
     * Reads exactly one TLS record from {@code in} and parses the ClientHello inside.
     * Throws {@link IOException} if the bytes are not a TLS handshake record.
     */
    public static Peek peek(InputStream in) throws IOException {
        byte[] header = readFully(in, 5);
        if (header == null) {
            throw new IOException("connection closed before ClientHello");
        }
        if ((header[0] & 0xff) != 0x16) {
            throw new IOException("not a TLS handshake record (first byte 0x" + Integer.toHexString(header[0] & 0xff) + ")");
        }
        int len = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
        if (len < 4 || len > MAX_CLIENT_HELLO) {
            throw new IOException("ClientHello record length " + len + " out of range");
        }
        byte[] body = readFully(in, len);
        if (body == null) {
            throw new IOException("truncated ClientHello");
        }
        byte[] consumed = new byte[5 + len];
        System.arraycopy(header, 0, consumed, 0, 5);
        System.arraycopy(body, 0, consumed, 5, len);
        return new Peek(consumed, parse(body));
    }

    /** Parses the handshake body of a ClientHello record and returns the SNI host, or null. */
    public static String parse(byte[] b) throws IOException {
        int p = 0;
        if (b.length < 4 || (b[0] & 0xff) != 0x01) {
            throw new IOException("not a ClientHello");
        }
        int hsLen = ((b[1] & 0xff) << 16) | ((b[2] & 0xff) << 8) | (b[3] & 0xff);
        if (hsLen > b.length - 4) {
            throw new IOException("ClientHello spans records; unsupported");
        }
        p = 4;
        p += 2 + 32; // client_version, random
        if (p >= b.length) {
            throw new IOException("short ClientHello");
        }
        int sidLen = b[p++] & 0xff;
        p += sidLen;
        if (p + 2 > b.length) {
            throw new IOException("short ClientHello");
        }
        int csLen = ((b[p] & 0xff) << 8) | (b[p + 1] & 0xff);
        p += 2 + csLen;
        if (p + 1 > b.length) {
            throw new IOException("short ClientHello");
        }
        int compLen = b[p++] & 0xff;
        p += compLen;
        if (p + 2 > b.length) {
            return null; // no extensions
        }
        int extLen = ((b[p] & 0xff) << 8) | (b[p + 1] & 0xff);
        p += 2;
        int end = Math.min(b.length, p + extLen);
        while (p + 4 <= end) {
            int type = ((b[p] & 0xff) << 8) | (b[p + 1] & 0xff);
            int len = ((b[p + 2] & 0xff) << 8) | (b[p + 3] & 0xff);
            p += 4;
            if (p + len > end) {
                throw new IOException("bad extension length");
            }
            if (type == 0) {
                int q = p + 2; // skip server_name_list length
                while (q + 3 <= p + len) {
                    int nameType = b[q] & 0xff;
                    int nameLen = ((b[q + 1] & 0xff) << 8) | (b[q + 2] & 0xff);
                    q += 3;
                    if (q + nameLen > p + len) {
                        throw new IOException("bad server_name length");
                    }
                    if (nameType == 0) {
                        String name = new String(b, q, nameLen, StandardCharsets.US_ASCII).toLowerCase(Locale.ROOT);
                        if (name.isEmpty() || name.length() > 253 || !HOST.matcher(name).matches()) {
                            throw new IOException("bad server_name");
                        }
                        return name;
                    }
                    q += nameLen;
                }
            }
            p += len;
        }
        return null;
    }

    /**
     * Exactly {@code n} bytes, or null if the stream ended before that. Both callers already know
     * which of the two lengths they asked for and say so in their own message, so a clean end and
     * a truncated one are the same answer here; this used to return one of two identical nulls to
     * suggest otherwise. {@code n} is bounded by the caller ({@link #MAX_CLIENT_HELLO}), so the
     * buffer is the right size from the start rather than grown and then copied out.
     */
    private static byte[] readFully(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r < 0) {
                return null;
            }
            off += r;
        }
        return buf;
    }
}
