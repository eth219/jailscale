package io.jailscale.hub.dns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/** A stub resolver for what the self-checks ask public resolvers: TXT, A and AAAA over UDP. */
public final class DnsQuery {

    private static final SecureRandom RNG = new SecureRandom();

    /**
     * The resolvers the self-checks ask (ARCHITECTURE.md §7.2), in one place so the dns-01 check
     * and the address check cannot drift apart on which answers they trust or how long they wait.
     */
    public static final List<String> PUBLIC_RESOLVERS = List.of("1.1.1.1", "8.8.8.8");
    public static final int PUBLIC_TIMEOUT_MS = 5000;

    private DnsQuery() {}

    private static final int TYPE_A = 1;
    private static final int TYPE_TXT = 16;
    private static final int TYPE_AAAA = 28;
    private static final int RCODE_NXDOMAIN = 3;

    /** Sends a TXT query for {@code name} to {@code server} and returns the TXT strings (empty if none). */
    public static List<String> txt(String server, int port, String name, int timeoutMs) throws IOException {
        List<String> out = new ArrayList<>();
        for (byte[] rd : query(server, port, name, TYPE_TXT, timeoutMs)) {
            // TXT rdata is a sequence of length-prefixed character-strings; a long record is split
            // across several and means the concatenation.
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i < rd.length) {
                int l = rd[i++] & 0xff;
                if (i + l > rd.length) {
                    throw new IOException("truncated TXT record");
                }
                sb.append(new String(rd, i, l, StandardCharsets.US_ASCII));
                i += l;
            }
            out.add(sb.toString());
        }
        return out;
    }

    /**
     * Sends an A query for {@code name} and returns the addresses as dotted quads (empty if none).
     * Used by the address check to ask what the world is told this hub's name resolves to (§7.2).
     */
    public static List<String> a(String server, int port, String name, int timeoutMs) throws IOException {
        return addresses(query(server, port, name, TYPE_A, timeoutMs), 4);
    }

    /** Same for AAAA: the addresses in their canonical textual form (empty if none). */
    public static List<String> aaaa(String server, int port, String name, int timeoutMs) throws IOException {
        return addresses(query(server, port, name, TYPE_AAAA, timeoutMs), 16);
    }

    private static List<String> addresses(List<byte[]> rdatas, int length) throws IOException {
        List<String> out = new ArrayList<>();
        for (byte[] rd : rdatas) {
            if (rd.length != length) {
                throw new IOException("address record with " + rd.length + " bytes of rdata");
            }
            out.add(InetAddress.getByAddress(rd).getHostAddress());
        }
        return out;
    }

    private static List<byte[]> query(String server, int port, String name, int type, int timeoutMs) throws IOException {
        int id = RNG.nextInt(0x10000);
        ByteArrayOutputStream q = new ByteArrayOutputStream(64);
        q.write(id >>> 8);
        q.write(id);
        q.write(0x01); // RD
        q.write(0x00);
        q.write(0);
        q.write(1);
        for (int i = 0; i < 6; i++) {
            q.write(0);
        }
        q.writeBytes(DnsResponder.encodeName(name));
        q.write(0);
        q.write(type);
        q.write(0);
        q.write(1);  // IN
        byte[] query = q.toByteArray();
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(timeoutMs);
            s.send(new DatagramPacket(query, query.length, new InetSocketAddress(server, port)));
            byte[] buf = new byte[4096];
            DatagramPacket r = new DatagramPacket(buf, buf.length);
            s.receive(r);
            return parse(java.util.Arrays.copyOf(buf, r.getLength()), id, type);
        }
    }

    /**
     * The rdata of every answer of {@code type}, in order. Empty when the name does not exist
     * (NXDOMAIN): that is "no records", the same answer a name with records of another type gives,
     * and the caller decides what a missing record means. Every other error rcode is an error.
     *
     * <p>Every read is bounds-checked: the datagram is whatever a resolver, or anyone who can guess
     * a 16-bit id, chose to send, and a reply cut inside a name or a record header must be an
     * {@link IOException} the caller planned for, not an {@code ArrayIndexOutOfBoundsException}
     * that ends the thread.
     */
    static List<byte[]> parse(byte[] m, int expectedId, int type) throws IOException {
        if (m.length < 12 || (((m[0] & 0xff) << 8) | (m[1] & 0xff)) != expectedId) {
            throw new IOException("bad DNS response");
        }
        if ((m[2] & 0x02) != 0) {
            // TC: the answer did not fit in one datagram and what we have is a prefix. Nothing
            // this asks for should be that large; better an honest error than half a record set.
            throw new IOException("DNS answer truncated (TC)");
        }
        int rcode = m[3] & 0x0f;
        if (rcode == RCODE_NXDOMAIN) {
            return List.of();
        }
        if (rcode != 0) {
            throw new IOException("DNS rcode " + rcode);
        }
        int qd = ((m[4] & 0xff) << 8) | (m[5] & 0xff);
        int an = ((m[6] & 0xff) << 8) | (m[7] & 0xff);
        int p = 12;
        for (int i = 0; i < qd; i++) {
            p = skipName(m, p);
            need(m, p, 4);
            p += 4;
        }
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < an; i++) {
            p = skipName(m, p);
            need(m, p, 10);
            int answerType = ((m[p] & 0xff) << 8) | (m[p + 1] & 0xff);
            int rdlen = ((m[p + 8] & 0xff) << 8) | (m[p + 9] & 0xff);
            int rdStart = p + 10;
            need(m, rdStart, rdlen);
            if (answerType == type) {
                out.add(java.util.Arrays.copyOfRange(m, rdStart, rdStart + rdlen));
            }
            p = rdStart + rdlen;
        }
        return out;
    }

    /** The position after the name at {@code p}, without following compression pointers. */
    private static int skipName(byte[] m, int p) throws IOException {
        while (true) {
            need(m, p, 1);
            int l = m[p] & 0xff;
            if (l == 0) {
                return p + 1;
            }
            if ((l & 0xc0) == 0xc0) {
                need(m, p, 2);
                return p + 2;
            }
            p += 1 + l;
        }
    }

    private static void need(byte[] m, int p, int n) throws IOException {
        if (p < 0 || n < 0 || p + n > m.length) {
            throw new IOException("truncated DNS answer");
        }
    }
}
