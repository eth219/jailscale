package io.jailscale.proto.tls;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
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

    /** application_layer_protocol_negotiation (RFC 7301). */
    private static final int EXT_ALPN = 16;

    /**
     * How many offered protocols are kept. A ClientHello may list as many as it likes and this
     * reads every one to walk the extension, but what the hub does with the list is ask whether
     * one constant is in it; keeping an unbounded list from an unauthenticated caller is a cost
     * with no use.
     */
    private static final int MAX_ALPN = 16;

    private Sni() {}

    /**
     * The peeked bytes, the SNI (null if the hello carries none) and the protocols the client
     * offered in ALPN (empty if it offered none).
     *
     * <p>ALPN is here because one protocol changes who answers the handshake rather than what is
     * carried inside it: {@code acme-tls/1} means an ACME server validating a name, and the hub
     * answers that itself with a certificate built for the purpose (RFC 8737) instead of relaying
     * it to the node that holds the name.
     */
    public record Peek(byte[] consumed, String serverName, List<String> alpn) {

        /** Whether the client offered {@code protocol}. */
        public boolean offers(String protocol) {
            return alpn.contains(protocol);
        }
    }

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
        Hello hello = parseHello(body);
        return new Peek(consumed, hello.serverName(), hello.alpn());
    }

    /** What a ClientHello carries that anything here reads. */
    public record Hello(String serverName, List<String> alpn) {}

    /** Parses the handshake body of a ClientHello record and returns the SNI host, or null. */
    public static String parse(byte[] b) throws IOException {
        return parseHello(b).serverName();
    }

    /** As above, with the ALPN list as well. */
    public static Hello parseHello(byte[] b) throws IOException {
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
            return new Hello(null, List.of()); // no extensions
        }
        int extLen = ((b[p] & 0xff) << 8) | (b[p + 1] & 0xff);
        p += 2;
        int end = Math.min(b.length, p + extLen);
        String serverName = null;
        List<String> alpn = new ArrayList<>(4);
        while (p + 4 <= end) {
            int type = ((b[p] & 0xff) << 8) | (b[p + 1] & 0xff);
            int len = ((b[p + 2] & 0xff) << 8) | (b[p + 3] & 0xff);
            p += 4;
            if (p + len > end) {
                throw new IOException("bad extension length");
            }
            if (type == 0 && serverName == null) {
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
                        serverName = name;
                        break;
                    }
                    q += nameLen;
                }
            } else if (type == EXT_ALPN) {
                // ProtocolNameList: two bytes of list length, then one-byte-prefixed names. Read
                // as ISO-8859-1 and compared whole, never parsed: a protocol name is an opaque
                // label and the only one this hub acts on is a constant.
                if (len < 2) {
                    throw new IOException("bad ALPN extension");
                }
                int listEnd = p + len;
                int q = p + 2;
                while (q + 1 <= listEnd) {
                    int nameLen = b[q] & 0xff;
                    q += 1;
                    if (nameLen == 0 || q + nameLen > listEnd) {
                        throw new IOException("bad ALPN protocol length");
                    }
                    if (alpn.size() < MAX_ALPN) {
                        alpn.add(new String(b, q, nameLen, StandardCharsets.ISO_8859_1));
                    }
                    q += nameLen;
                }
            }
            p += len;
        }
        return new Hello(serverName, List.copyOf(alpn));
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
