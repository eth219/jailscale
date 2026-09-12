package io.jailscale.hub.dns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/** A stub resolver for what the self-check asks public resolvers: TXT and A over UDP. */
public final class DnsQuery {

    private static final SecureRandom RNG = new SecureRandom();

    private DnsQuery() {}

    private static final int TYPE_A = 1;
    private static final int TYPE_TXT = 16;

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
     * Used by the self-check to ask what the world is told this hub's name resolves to (§7.2).
     */
    public static List<String> a(String server, int port, String name, int timeoutMs) throws IOException {
        List<String> out = new ArrayList<>();
        for (byte[] rd : query(server, port, name, TYPE_A, timeoutMs)) {
            if (rd.length != 4) {
                throw new IOException("A record with " + rd.length + " bytes of rdata");
            }
            out.add((rd[0] & 0xff) + "." + (rd[1] & 0xff) + "." + (rd[2] & 0xff) + "." + (rd[3] & 0xff));
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

    /** The rdata of every answer of {@code type}, in order. */
    static List<byte[]> parse(byte[] m, int expectedId, int type) throws IOException {
        if (m.length < 12 || (((m[0] & 0xff) << 8) | (m[1] & 0xff)) != expectedId) {
            throw new IOException("bad DNS response");
        }
        int rcode = m[3] & 0x0f;
        if (rcode != 0) {
            throw new IOException("DNS rcode " + rcode);
        }
        int qd = ((m[4] & 0xff) << 8) | (m[5] & 0xff);
        int an = ((m[6] & 0xff) << 8) | (m[7] & 0xff);
        int p = 12;
        for (int i = 0; i < qd; i++) {
            p = skipName(m, p) + 4;
        }
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < an; i++) {
            p = skipName(m, p);
            int answerType = ((m[p] & 0xff) << 8) | (m[p + 1] & 0xff);
            int rdlen = ((m[p + 8] & 0xff) << 8) | (m[p + 9] & 0xff);
            int rdStart = p + 10;
            if (rdStart + rdlen > m.length) {
                throw new IOException("truncated DNS answer");
            }
            if (answerType == type) {
                out.add(java.util.Arrays.copyOfRange(m, rdStart, rdStart + rdlen));
            }
            p = rdStart + rdlen;
        }
        return out;
    }

    private static int skipName(byte[] m, int p) {
        while (true) {
            int l = m[p] & 0xff;
            if (l == 0) {
                return p + 1;
            }
            if ((l & 0xc0) == 0xc0) {
                return p + 2;
            }
            p += 1 + l;
        }
    }
}
