package io.jailscale.proto.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Reads a TLS ClientHello off a raw socket without opening TLS and extracts the server_name
 * extension (ARCHITECTURE.md §8.1). The bytes consumed are returned so they can be replayed to
 * whoever terminates the connection.
 */
public final class Sni {

    /** A ClientHello larger than this is not from a browser we care about. */
    public static final int MAX_CLIENT_HELLO = 16 * 1024;

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
                        if (name.isEmpty() || name.length() > 253 || !name.matches("[a-z0-9.-]+")) {
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

    private static byte[] readFully(InputStream in, int n) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(n);
        byte[] tmp = new byte[Math.min(n, 4096)];
        while (buf.size() < n) {
            int r = in.read(tmp, 0, Math.min(tmp.length, n - buf.size()));
            if (r < 0) {
                return buf.size() == 0 ? null : null;
            }
            buf.write(tmp, 0, r);
        }
        return buf.toByteArray();
    }
}
