package io.jailscale.proto.net;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

/**
 * The PROXY protocol (HAProxy, v1 text and v2 binary) as sent by nginx {@code proxy_protocol on}
 * and HAProxy {@code send-proxy(-v2)} (ARCHITECTURE.md §8.5). Only the header is consumed; the bytes
 * after it are left in the stream untouched.
 */
public final class ProxyProtocol {

    /** The original client and the address it connected to; null fields for LOCAL/UNKNOWN. */
    public record Header(String srcIp, int srcPort, String dstIp, int dstPort) {
        public boolean known() {
            return srcIp != null;
        }
    }

    private static final byte[] V2_SIG = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
    private static final int V1_MAX = 107;

    private ProxyProtocol() {}

    /** Reads exactly one header. Throws on anything that is not a PROXY header. */
    public static Header read(InputStream in) throws IOException {
        int first = in.read();
        if (first < 0) {
            throw new EOFException("no PROXY header");
        }
        if (first == 'P') {
            return readV1(in);
        }
        if (first == 0x0D) {
            return readV2(in);
        }
        throw new IOException("expected a PROXY protocol header");
    }

    private static Header readV1(InputStream in) throws IOException {
        byte[] line = new byte[V1_MAX];
        line[0] = 'P';
        int n = 1;
        while (true) {
            int b = in.read();
            if (b < 0) {
                throw new EOFException("truncated PROXY v1 header");
            }
            if (n >= line.length) {
                throw new IOException("PROXY v1 header too long");
            }
            line[n++] = (byte) b;
            if (b == '\n') {
                break;
            }
        }
        if (n < 2 || line[n - 2] != '\r') {
            throw new IOException("PROXY v1 header without CRLF");
        }
        String s = new String(line, 0, n - 2, StandardCharsets.US_ASCII);
        String[] p = s.split(" ");
        if (p.length < 2 || !p[0].equals("PROXY")) {
            throw new IOException("bad PROXY v1 header");
        }
        if (p[1].equals("UNKNOWN")) {
            return new Header(null, 0, null, 0);
        }
        if (p.length != 6 || !(p[1].equals("TCP4") || p[1].equals("TCP6"))) {
            throw new IOException("bad PROXY v1 header");
        }
        boolean v6 = p[1].equals("TCP6");
        try {
            InetAddress src = literal(p[2], v6);
            InetAddress dst = literal(p[3], v6);
            return new Header(src.getHostAddress(), port(p[4]), dst.getHostAddress(), port(p[5]));
        } catch (IOException | IllegalArgumentException e) {
            throw new IOException("bad PROXY v1 address");
        }
    }

    private static final java.util.regex.Pattern V4 = java.util.regex.Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");
    private static final java.util.regex.Pattern V6 = java.util.regex.Pattern.compile("[0-9A-Fa-f:.]{2,45}");

    /**
     * Only address literals: a hostname here would make {@link InetAddress#getByName} do a DNS
     * lookup on the accept path, which an attacker could use to stall the hub (found by fuzzing).
     */
    private static InetAddress literal(String s, boolean v6) throws IOException {
        if (v6) {
            if (!V6.matcher(s).matches() || s.indexOf(':') < 0) {
                throw new IOException("not an IPv6 literal");
            }
        } else {
            java.util.regex.Matcher m = V4.matcher(s);
            if (!m.matches()) {
                throw new IOException("not an IPv4 literal");
            }
            for (int i = 1; i <= 4; i++) {
                if (Integer.parseInt(m.group(i)) > 255) {
                    throw new IOException("not an IPv4 literal");
                }
            }
        }
        return InetAddress.getByName(s);
    }

    private static int port(String s) throws IOException {
        int v;
        try {
            v = Integer.parseInt(s);
        } catch (NumberFormatException e) {
            throw new IOException("bad PROXY port");
        }
        if (v < 0 || v > 65535) {
            throw new IOException("bad PROXY port");
        }
        return v;
    }

    private static Header readV2(InputStream in) throws IOException {
        byte[] head = new byte[16];
        head[0] = 0x0D;
        readFully(in, head, 1, 15);
        for (int i = 0; i < V2_SIG.length; i++) {
            if (head[i] != V2_SIG[i]) {
                throw new IOException("bad PROXY v2 signature");
            }
        }
        int verCmd = head[12] & 0xff;
        int famProto = head[13] & 0xff;
        int len = ((head[14] & 0xff) << 8) | (head[15] & 0xff);
        if ((verCmd >> 4) != 2) {
            throw new IOException("bad PROXY v2 version");
        }
        byte[] body = new byte[len];
        readFully(in, body, 0, len);
        int cmd = verCmd & 0x0f;
        int family = famProto >> 4;
        if (cmd == 0) { // LOCAL: health checks from the proxy itself
            return new Header(null, 0, null, 0);
        }
        if (cmd != 1) {
            throw new IOException("bad PROXY v2 command");
        }
        try {
            if (family == 1 && len >= 12) {
                return new Header(InetAddress.getByAddress(slice(body, 0, 4)).getHostAddress(), u16(body, 8),
                    InetAddress.getByAddress(slice(body, 4, 4)).getHostAddress(), u16(body, 10));
            }
            if (family == 2 && len >= 36) {
                return new Header(InetAddress.getByAddress(slice(body, 0, 16)).getHostAddress(), u16(body, 32),
                    InetAddress.getByAddress(slice(body, 16, 16)).getHostAddress(), u16(body, 34));
            }
        } catch (IOException e) {
            throw new IOException("bad PROXY v2 address");
        }
        return new Header(null, 0, null, 0); // AF_UNSPEC / AF_UNIX: nothing usable
    }

    private static byte[] slice(byte[] b, int off, int len) {
        byte[] out = new byte[len];
        System.arraycopy(b, off, out, 0, len);
        return out;
    }

    private static int u16(byte[] b, int off) {
        return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
    }

    private static void readFully(InputStream in, byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            int n = in.read(b, off, len);
            if (n < 0) {
                throw new EOFException("truncated PROXY v2 header");
            }
            off += n;
            len -= n;
        }
    }

    /** The v1 line a node prepends for its local app (ARCHITECTURE.md §9.3). */
    public static String v1Line(String srcIp, int srcPort, String dstIp, int dstPort) {
        boolean v6 = srcIp.contains(":");
        return "PROXY " + (v6 ? "TCP6" : "TCP4") + " " + srcIp + " " + dstIp + " " + srcPort + " " + dstPort + "\r\n";
    }
}
