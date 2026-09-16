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
    private static final int TYPE_NS = 2;
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

    /**
     * Sends an NS query for {@code name} and returns the server names, lower case, no trailing dot
     * (empty if none). Names in the rdata may be compressed against the whole message, so this
     * reads the message rather than the rdata alone.
     */
    public static List<String> ns(String server, int port, String name, int timeoutMs) throws IOException {
        List<String> out = new ArrayList<>();
        Message m = queryMessage(server, port, name, TYPE_NS, timeoutMs);
        for (int off : m.rdataOffsets) {
            out.add(readName(m.bytes, off).toLowerCase(java.util.Locale.ROOT));
        }
        return out;
    }

    /** A name at {@code p} in {@code m}, following compression pointers a bounded number of times. */
    static String readName(byte[] m, int p) throws IOException {
        StringBuilder sb = new StringBuilder();
        int hops = 0;
        while (true) {
            need(m, p, 1);
            int l = m[p] & 0xff;
            if (l == 0) {
                return sb.toString();
            }
            if ((l & 0xc0) == 0xc0) {
                need(m, p, 2);
                if (++hops > 16) {
                    throw new IOException("compression pointer loop");
                }
                p = ((l & 0x3f) << 8) | (m[p + 1] & 0xff);
                continue;
            }
            need(m, p + 1, l);
            if (sb.length() > 0) {
                sb.append('.');
            }
            sb.append(new String(m, p + 1, l, StandardCharsets.US_ASCII));
            p += 1 + l;
        }
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

    /**
     * What a parent's name server says when asked, without recursion, for a name it has delegated:
     * a referral, whose additional section carries the glue. Returned as name to dotted quad for
     * every A record in that section (§13.3). Asking a recursive resolver instead would get the
     * child zone's own answer, which for the glue names is the very thing being looked for.
     */
    public static java.util.Map<String, String> referralGlue(String server, int port, String name, int timeoutMs) throws IOException {
        byte[] m = exchange(server, port, name, TYPE_A, timeoutMs, false);
        java.util.Map<String, String> out = new java.util.LinkedHashMap<>();
        int qd = ((m[4] & 0xff) << 8) | (m[5] & 0xff);
        int an = ((m[6] & 0xff) << 8) | (m[7] & 0xff);
        int ns = ((m[8] & 0xff) << 8) | (m[9] & 0xff);
        int ar = ((m[10] & 0xff) << 8) | (m[11] & 0xff);
        int p = 12;
        for (int i = 0; i < qd; i++) {
            p = skipName(m, p);
            need(m, p, 4);
            p += 4;
        }
        for (int i = 0; i < an + ns + ar; i++) {
            int nameAt = p;
            p = skipName(m, p);
            need(m, p, 10);
            int type = ((m[p] & 0xff) << 8) | (m[p + 1] & 0xff);
            int rdlen = ((m[p + 8] & 0xff) << 8) | (m[p + 9] & 0xff);
            int rdStart = p + 10;
            need(m, rdStart, rdlen);
            if (i >= an + ns && type == TYPE_A && rdlen == 4) {
                out.put(readName(m, nameAt).toLowerCase(java.util.Locale.ROOT),
                    InetAddress.getByAddress(java.util.Arrays.copyOfRange(m, rdStart, rdStart + 4)).getHostAddress());
            }
            p = rdStart + rdlen;
        }
        return out;
    }

    /** A parsed answer: the whole message, and where each answer of the asked type has its rdata. */
    private record Message(byte[] bytes, List<Integer> rdataOffsets, List<Integer> rdataLengths) {}

    private static List<byte[]> query(String server, int port, String name, int type, int timeoutMs) throws IOException {
        Message m = queryMessage(server, port, name, type, timeoutMs);
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < m.rdataOffsets.size(); i++) {
            int off = m.rdataOffsets.get(i);
            out.add(java.util.Arrays.copyOfRange(m.bytes, off, off + m.rdataLengths.get(i)));
        }
        return out;
    }

    private static Message queryMessage(String server, int port, String name, int type, int timeoutMs) throws IOException {
        byte[] m = exchange(server, port, name, type, timeoutMs, true);
        int id = ((m[0] & 0xff) << 8) | (m[1] & 0xff);
        return new Message(m, parseOffsets(m, id, type, true), parseOffsets(m, id, type, false));
    }

    /**
     * One query and its reply, id checked, with or without asking for recursion.
     *
     * <p><b>UDP, then TCP.</b> A datagram that does not come back, or one that comes back truncated,
     * is asked again over TCP -- which every server this asks answers, the hub's own included, and
     * where the address is proved by a handshake rather than claimed. RFC 7766 says a resolver
     * should do this; here it also decides something else. {@code Advertise.whoAmI} asks each glue
     * address for {@code _jailhub-self} to find out which one is this host, and while that lookup
     * had no fallback, anyone able to forge a source into the hub's own network could stop the
     * answer arriving with about twenty packets a second -- so the responder had to exempt that one
     * name from its answer-rate limits, which left the total that may leave on :53 unbounded
     * (§11.5). With a fallback the flood costs the attacker a UDP flood and gets a TCP answer
     * anyway, and the exemption is gone.
     *
     * <p>The cost is the worst case: a server that answers nothing at all is now waited for twice,
     * once per transport.
     */
    private static byte[] exchange(String server, int port, String name, int type, int timeoutMs, boolean recurse) throws IOException {
        int id = RNG.nextInt(0x10000);
        ByteArrayOutputStream q = new ByteArrayOutputStream(64);
        q.write(id >>> 8);
        q.write(id);
        q.write(recurse ? 0x01 : 0x00); // RD, or not: a parent asked without it answers with the delegation
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
        try {
            byte[] m = overUdp(server, port, query, id, timeoutMs);
            if ((m[2] & 0x02) == 0) {
                return m;
            }
        } catch (IOException e) {
            // Nothing usable came back over UDP: a lost or refused datagram, a server too busy to
            // answer, a flood on the path, or a reply that was not this question's -- which is what
            // an off-path forgery looks like from here. Every one of them is a reason to ask again
            // where the address is proved rather than claimed.
        }
        return overTcp(server, port, query, id, timeoutMs);
    }

    private static byte[] overUdp(String server, int port, byte[] query, int id, int timeoutMs) throws IOException {
        try (DatagramSocket s = new DatagramSocket()) {
            s.setSoTimeout(timeoutMs);
            s.send(new DatagramPacket(query, query.length, new InetSocketAddress(server, port)));
            byte[] buf = new byte[4096];
            DatagramPacket r = new DatagramPacket(buf, buf.length);
            s.receive(r);
            return checked(java.util.Arrays.copyOf(buf, r.getLength()), id);
        }
    }

    /**
     * The same question with a two-byte length in front of it, which is DNS over TCP (RFC 1035
     * §4.2.2).
     *
     * <p>Bounded by one deadline rather than by a timeout per read. {@code setSoTimeout} bounds how
     * long one {@code read} waits, which for a message read in pieces is a bound on the pieces and
     * not on the message: a peer sending one byte just inside the timeout holds the caller for as
     * long as it likes. The UDP path this falls back from was bounded by a single receive, and
     * {@code Hub.checkAddress} calls it holding a lock and answering an operator's command, so
     * "as long as it likes" is not an acceptable inheritance.
     */
    private static byte[] overTcp(String server, int port, byte[] query, int id, int timeoutMs) throws IOException {
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        try (java.net.Socket s = new java.net.Socket()) {
            s.connect(new InetSocketAddress(server, port), timeoutMs);
            java.io.OutputStream out = s.getOutputStream();
            out.write(new byte[] {(byte) (query.length >>> 8), (byte) query.length});
            out.write(query);
            out.flush();
            byte[] length = read(s, new byte[2], deadline);
            int len = ((length[0] & 0xff) << 8) | (length[1] & 0xff);
            if (len < 12) {
                throw new IOException("bad DNS response length " + len);
            }
            return checked(read(s, new byte[len], deadline), id);
        }
    }

    /** {@code buf} filled from {@code s}, with every read inside what is left of {@code deadline}. */
    private static byte[] read(java.net.Socket s, byte[] buf, long deadline) throws IOException {
        for (int n = 0; n < buf.length;) {
            long leftMs = (deadline - System.nanoTime()) / 1_000_000L;
            if (leftMs <= 0) {
                throw new IOException("DNS answer did not arrive in time");
            }
            s.setSoTimeout((int) Math.min(Integer.MAX_VALUE, leftMs));
            int r = s.getInputStream().read(buf, n, buf.length - n);
            if (r < 0) {
                throw new IOException("DNS answer cut short");
            }
            n += r;
        }
        return buf;
    }

    /** A reply is this question's only if it carries this question's id. */
    private static byte[] checked(byte[] m, int id) throws IOException {
        if (m.length < 12 || (((m[0] & 0xff) << 8) | (m[1] & 0xff)) != id) {
            throw new IOException("bad DNS response");
        }
        return m;
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
        List<Integer> offs = parseOffsets(m, expectedId, type, true);
        List<Integer> lens = parseOffsets(m, expectedId, type, false);
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < offs.size(); i++) {
            out.add(java.util.Arrays.copyOfRange(m, offs.get(i), offs.get(i) + lens.get(i)));
        }
        return out;
    }

    /** Offsets (or lengths) of the rdata of every answer of {@code type}, in order; see {@link #parse}. */
    private static List<Integer> parseOffsets(byte[] m, int expectedId, int type, boolean offsets) throws IOException {
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
        List<Integer> out = new ArrayList<>();
        for (int i = 0; i < an; i++) {
            p = skipName(m, p);
            need(m, p, 10);
            int answerType = ((m[p] & 0xff) << 8) | (m[p + 1] & 0xff);
            int rdlen = ((m[p + 8] & 0xff) << 8) | (m[p + 9] & 0xff);
            int rdStart = p + 10;
            need(m, rdStart, rdlen);
            if (answerType == type) {
                out.add(offsets ? rdStart : rdlen);
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
