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

/** A stub resolver for one thing: TXT lookups over UDP (self-check, tests). */
public final class DnsQuery {

    private static final SecureRandom RNG = new SecureRandom();

    private DnsQuery() {}

    /** Sends a TXT query for {@code name} to {@code server} and returns the TXT strings (empty if none). */
    public static List<String> txt(String server, int port, String name, int timeoutMs) throws IOException {
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
        q.write(16); // TXT
        q.write(0);
        q.write(1);  // IN
        byte[] query = q.toByteArray();
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(timeoutMs);
            s.send(new DatagramPacket(query, query.length, new InetSocketAddress(server, port)));
            byte[] buf = new byte[4096];
            DatagramPacket r = new DatagramPacket(buf, buf.length);
            s.receive(r);
            return parseTxt(java.util.Arrays.copyOf(buf, r.getLength()), id);
        }
    }

    static List<String> parseTxt(byte[] m, int expectedId) throws IOException {
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
        List<String> out = new ArrayList<>();
        for (int i = 0; i < an; i++) {
            p = skipName(m, p);
            int type = ((m[p] & 0xff) << 8) | (m[p + 1] & 0xff);
            int rdlen = ((m[p + 8] & 0xff) << 8) | (m[p + 9] & 0xff);
            int rdStart = p + 10;
            if (type == 16) {
                int rd = rdStart;
                int e = rdStart + rdlen;
                StringBuilder sb = new StringBuilder();
                while (rd < e) {
                    int l = m[rd++] & 0xff;
                    sb.append(new String(m, rd, l, StandardCharsets.US_ASCII));
                    rd += l;
                }
                out.add(sb.toString());
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
