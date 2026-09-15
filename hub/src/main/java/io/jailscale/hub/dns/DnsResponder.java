package io.jailscale.hub.dns;

import io.jailscale.proto.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * The hub's authoritative DNS server (ARCHITECTURE.md §7.1, §13.3). It began as the responder
 * behind {@code _acme-challenge.<hub>} alone, and still answers that name exactly as it always
 * has: TXT for the current challenge values, NS and SOA for the delegation the single-host
 * operator makes. It now also answers for the hub's whole name, for the operator who delegates
 * the subdomain itself: the apex and every name under it resolve to the hosts serving right now,
 * {@code nsN.<hub>} to the glue the parent holds, and {@code _jailhub-self.<hub>} to a token this
 * process alone knows, which is how a hub finds out which of the glue addresses is its own.
 *
 * <p>UDP and TCP, no EDNS, no compression beyond a pointer to the question name. Answers are
 * small by construction, so the server is no use as an amplifier; recursion is never offered and
 * names outside the zone are REFUSED.
 */
public final class DnsResponder implements AutoCloseable {

    private static final Log LOG = Log.get("dns");
    private static final SecureRandom RNG = new SecureRandom();
    private static final int TYPE_A = 1;
    private static final int TYPE_NS = 2;
    private static final int TYPE_SOA = 6;
    private static final int TYPE_TXT = 16;
    private static final int TYPE_AAAA = 28;
    private static final int TYPE_ANY = 255;
    private static final int RCODE_FORMERR = 1;
    private static final int RCODE_REFUSED = 5;
    /** Challenge values change per issuance and are polled by the CA: barely cached at all. */
    static final int TTL_TXT = 5;
    /** The serving set moves when a host goes; a resolver may hold it this long (§13.3). */
    public static final int TTL_ADDRESS = 30;
    /** Delegation and zone records change when the operator changes them. */
    static final int TTL_ZONE = 3600;
    /** The name whose TXT is this process's own token (§13.3). */
    public static final String SELF_LABEL = "_jailhub-self";

    /**
     * What the zone says right now, asked on every query so the answer is never stale: the
     * addresses serving, and the name servers the parent delegates to.
     */
    public interface Zone {
        /** IPv4 addresses answered for a name whose node is nowhere in particular, in order. Empty: NODATA. */
        List<String> serving();

        /** Name-server label (e.g. {@code ns1}) to IPv4 address, as delegated at the parent; empty when not. */
        Map<String, String> nameServers();

        /** The apex: where the control channel, joining and the admin pages are (§13.4). Defaults to the serving set. */
        default List<String> control() {
            return serving();
        }

        /** One label under the apex: the hosts that node is on (§13.4). Defaults to the serving set. */
        default List<String> forName(String label) {
            return serving();
        }
    }

    private static final Zone NOTHING = new Zone() {
        @Override public List<String> serving() { return List.of(); }
        @Override public Map<String, String> nameServers() { return Map.of(); }
    };

    private final String zone;      // _acme-challenge.hub.example.com (lower case, no trailing dot)
    private final String hubName;   // hub.example.com, the zone apex
    private final List<String> txt = new CopyOnWriteArrayList<>();
    private final String selfToken;
    private volatile Zone view = NOTHING;
    private volatile Consumer<List<String>> onTxtChanged;
    private DatagramSocket udp;
    private ServerSocket tcp;
    private volatile boolean running;

    public DnsResponder(String hubName) {
        this(hubName, randomToken());
    }

    /** With a chosen token (tests): two responders on one machine can then be told apart. */
    public DnsResponder(String hubName, String selfToken) {
        this.hubName = hubName.toLowerCase(Locale.ROOT);
        this.zone = "_acme-challenge." + this.hubName;
        this.selfToken = selfToken;
    }

    private static String randomToken() {
        byte[] b = new byte[16];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** The challenge name, {@code _acme-challenge.<hub>}: what the dns-01 self-check asks for. */
    public String zone() {
        return zone;
    }

    /** The token {@code _jailhub-self.<hub>} answers; only this process has it (§13.3). */
    public String selfToken() {
        return selfToken;
    }

    /** What to answer for the zone from now on. */
    public void setZone(Zone z) {
        this.view = z == null ? NOTHING : z;
    }

    /** Told whenever the challenge values change, so a standby can be sent the same ones (§13.3). */
    public void onTxtChanged(Consumer<List<String>> l) {
        this.onTxtChanged = l;
    }

    public void start(String bindHost, int port) throws IOException {
        // UDP and TCP on the same port number. With a fixed port that either binds or fails; with
        // port 0 the number UDP was given may already be a TCP port someone else holds -- the two
        // spaces are separate, and on Windows a test run made that collision ordinary -- so the
        // pair is retried with a fresh number rather than reported as a bind failure.
        IOException last = null;
        for (int attempt = 0; attempt < (port == 0 ? 8 : 1); attempt++) {
            udp = new DatagramSocket(null);
            udp.setReuseAddress(true);
            udp.bind(new InetSocketAddress(bindHost, port));
            tcp = new ServerSocket();
            tcp.setReuseAddress(true);
            try {
                tcp.bind(new InetSocketAddress(bindHost, udp.getLocalPort()), 16);
                last = null;
                break;
            } catch (IOException e) {
                last = e;
                udp.close();
                tcp.close();
            }
        }
        if (last != null) {
            throw last;
        }
        running = true;
        Thread.ofPlatform().name("dns-udp").daemon(true).start(this::udpLoop);
        Thread.ofVirtual().name("dns-tcp").start(this::tcpLoop);
        LOG.info("answering for {} and {} on {}:{}", hubName, zone, bindHost, udp.getLocalPort());
    }

    public int port() {
        return udp.getLocalPort();
    }

    public void setTxt(List<String> values) {
        txt.clear();
        txt.addAll(values);
        Consumer<List<String>> l = onTxtChanged;
        if (l != null) {
            l.accept(new ArrayList<>(txt));
        }
    }

    public void clearTxt() {
        setTxt(List.of());
    }

    public List<String> txt() {
        return new ArrayList<>(txt);
    }

    private void udpLoop() {
        byte[] buf = new byte[1024];
        while (running) {
            DatagramPacket p = new DatagramPacket(buf, buf.length);
            try {
                udp.receive(p);
                byte[] q = java.util.Arrays.copyOf(p.getData(), p.getLength());
                byte[] r = respond(q);
                if (r != null) {
                    udp.send(new DatagramPacket(r, r.length, p.getSocketAddress()));
                }
            } catch (IOException e) {
                if (running) {
                    LOG.debug("udp: {}", e.getMessage());
                }
            }
        }
    }

    private void tcpLoop() {
        while (running) {
            try {
                Socket s = tcp.accept();
                Thread.ofVirtual().start(() -> serveTcp(s));
            } catch (IOException e) {
                if (running) {
                    LOG.debug("tcp: {}", e.getMessage());
                }
            }
        }
    }

    private void serveTcp(Socket s) {
        try (s) {
            s.setSoTimeout(5000);
            DataInputStream in = new DataInputStream(s.getInputStream());
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            int len = in.readUnsignedShort();
            if (len > 4096) {
                return;
            }
            byte[] q = new byte[len];
            in.readFully(q);
            byte[] r = respond(q);
            if (r != null) {
                out.writeShort(r.length);
                out.write(r);
                out.flush();
            }
        } catch (IOException ignored) {
            // client gone
        }
    }

    /** Builds a response for one query message, or null if it is not a query we can parse. */
    byte[] respond(byte[] q) {
        if (q.length < 12) {
            return null;
        }
        int flags = ((q[2] & 0xff) << 8) | (q[3] & 0xff);
        if ((flags & 0x8000) != 0) {
            return null; // a response, not a query
        }
        int qdcount = ((q[4] & 0xff) << 8) | (q[5] & 0xff);
        if (qdcount != 1) {
            return error(q, RCODE_FORMERR);
        }
        int p = 12;
        StringBuilder name = new StringBuilder();
        while (p < q.length) {
            int l = q[p++] & 0xff;
            if (l == 0) {
                break;
            }
            if ((l & 0xc0) != 0 || p + l > q.length) {
                return error(q, RCODE_FORMERR);
            }
            if (name.length() > 0) {
                name.append('.');
            }
            name.append(new String(q, p, l, StandardCharsets.US_ASCII));
            p += l;
        }
        if (p + 4 > q.length) {
            return error(q, RCODE_FORMERR);
        }
        int qtype = ((q[p] & 0xff) << 8) | (q[p + 1] & 0xff);
        int questionEnd = p + 4;
        String qname = name.toString().toLowerCase(Locale.ROOT);
        if (qname.equals(zone)) {
            return challenge(q, questionEnd, qtype);
        }
        if (qname.equals(hubName)) {
            return apex(q, questionEnd, qtype);
        }
        if (qname.endsWith("." + hubName)) {
            return under(q, questionEnd, qtype, qname.substring(0, qname.length() - hubName.length() - 1));
        }
        return error(q, RCODE_REFUSED); // not our zone
    }

    /** {@code _acme-challenge.<hub>}, exactly as before the hub answered anything else. */
    private byte[] challenge(byte[] q, int questionEnd, int qtype) {
        List<byte[]> answers = new ArrayList<>();
        if (qtype == TYPE_TXT || qtype == TYPE_ANY) {
            for (String v : txt) {
                answers.add(rr(TYPE_TXT, TTL_TXT, txtRdata(v)));
            }
        }
        if (qtype == TYPE_NS || qtype == TYPE_ANY) {
            answers.add(rr(TYPE_NS, TTL_TXT, encodeName(hubName)));
        }
        if (qtype == TYPE_SOA || qtype == TYPE_ANY || answers.isEmpty()) {
            byte[] soa = soaRdata(hubName, TTL_TXT);
            if (qtype == TYPE_SOA || qtype == TYPE_ANY) {
                answers.add(rr(TYPE_SOA, TTL_TXT, soa));
            } else {
                // NODATA: authority section carries the SOA
                return build(q, questionEnd, List.of(), List.of(rr(TYPE_SOA, TTL_TXT, soa)), List.of(), 0);
            }
        }
        return build(q, questionEnd, answers, List.of(), List.of(), 0);
    }

    /** The zone apex: A is the serving set, NS and SOA the delegation (§13.3). */
    private byte[] apex(byte[] q, int questionEnd, int qtype) {
        Zone z = view;
        Map<String, String> ns = ordered(z.nameServers());
        List<byte[]> answers = new ArrayList<>();
        List<byte[]> additional = new ArrayList<>();
        if (qtype == TYPE_A) {
            for (String a : z.control()) {
                byte[] rd = ipv4(a);
                if (rd != null) {
                    answers.add(rr(TYPE_A, TTL_ADDRESS, rd));
                }
            }
        } else if (qtype == TYPE_NS) {
            if (ns.isEmpty()) {
                answers.add(rr(TYPE_NS, TTL_ZONE, encodeName(hubName)));
            }
            for (Map.Entry<String, String> e : ns.entrySet()) {
                String nsName = e.getKey() + "." + hubName;
                answers.add(rr(TYPE_NS, TTL_ZONE, encodeName(nsName)));
                byte[] rd = ipv4(e.getValue());
                if (rd != null) {
                    additional.add(rrNamed(encodeName(nsName), TYPE_A, TTL_ZONE, rd));
                }
            }
        } else if (qtype == TYPE_SOA) {
            answers.add(rr(TYPE_SOA, TTL_ZONE, soaRdata(mname(ns), TTL_ADDRESS)));
        }
        if (answers.isEmpty()) {
            return nodata(q, questionEnd, ns);
        }
        return build(q, questionEnd, answers, List.of(), additional, 0);
    }

    /** A name under the apex: a name server's glue, this process's token, or the wildcard. */
    private byte[] under(byte[] q, int questionEnd, int qtype, String label) {
        Zone z = view;
        Map<String, String> ns = ordered(z.nameServers());
        List<byte[]> answers = new ArrayList<>();
        if (label.equals(SELF_LABEL)) {
            if (qtype == TYPE_TXT) {
                answers.add(rr(TYPE_TXT, TTL_TXT, txtRdata(selfToken)));
            }
        } else if (ns.containsKey(label)) {
            if (qtype == TYPE_A) {
                byte[] rd = ipv4(ns.get(label));
                if (rd != null) {
                    answers.add(rr(TYPE_A, TTL_ZONE, rd));
                }
            }
        } else if (qtype == TYPE_A) {
            // A single label is a published name, answered with the hosts its node is on; anything
            // deeper, or a name nobody holds, gets the hosts serving right now, where the "not open"
            // page is. Whether the name is open is the SNI router's question, not DNS's.
            for (String a : label.indexOf('.') < 0 ? z.forName(label) : z.serving()) {
                byte[] rd = ipv4(a);
                if (rd != null) {
                    answers.add(rr(TYPE_A, TTL_ADDRESS, rd));
                }
            }
        }
        if (answers.isEmpty()) {
            return nodata(q, questionEnd, ns);
        }
        return build(q, questionEnd, answers, List.of(), List.of(), 0);
    }

    /** No records of that type here (AAAA, MX, ANY, ...): NOERROR with the apex SOA in the authority section. */
    private byte[] nodata(byte[] q, int questionEnd, Map<String, String> ns) {
        byte[] soa = rrNamed(encodeName(hubName), TYPE_SOA, TTL_ADDRESS, soaRdata(mname(ns), TTL_ADDRESS));
        return build(q, questionEnd, List.of(), List.of(soa), List.of(), 0);
    }

    /** By label, so ns1 is answered before ns2 and is the SOA's mname whatever map the zone handed over. */
    private static Map<String, String> ordered(Map<String, String> ns) {
        return ns.isEmpty() ? ns : new java.util.TreeMap<>(ns);
    }

    private String mname(Map<String, String> ns) {
        return ns.isEmpty() ? hubName : ns.keySet().iterator().next() + "." + hubName;
    }

    private byte[] build(byte[] q, int questionEnd, List<byte[]> answers, List<byte[]> authority, List<byte[]> additional,
        int rcode) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(512);
        out.write(q[0]);
        out.write(q[1]);
        int flags = 0x8400 | (q[2] & 0x01) << 8 | rcode; // QR, AA, copy RD, rcode; never RA
        out.write(flags >>> 8);
        out.write(flags);
        out.write(0);
        out.write(1);
        out.write(answers.size() >>> 8);
        out.write(answers.size());
        out.write(authority.size() >>> 8);
        out.write(authority.size());
        out.write(additional.size() >>> 8);
        out.write(additional.size());
        out.write(q, 12, questionEnd - 12);
        for (byte[] a : answers) {
            out.writeBytes(a);
        }
        for (byte[] a : authority) {
            out.writeBytes(a);
        }
        for (byte[] a : additional) {
            out.writeBytes(a);
        }
        return out.toByteArray();
    }

    private byte[] error(byte[] q, int rcode) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(12);
        out.write(q[0]);
        out.write(q[1]);
        int flags = 0x8000 | rcode;
        out.write(flags >>> 8);
        out.write(flags);
        for (int i = 0; i < 8; i++) {
            out.write(0);
        }
        return out.toByteArray();
    }

    /** A resource record whose name is a pointer to the question name (offset 12). */
    private static byte[] rr(int type, int ttl, byte[] rdata) {
        return rrNamed(new byte[] {(byte) 0xc0, 0x0c}, type, ttl, rdata);
    }

    /** A resource record with an explicit owner name (a SOA in the authority section names the apex, not the query). */
    private static byte[] rrNamed(byte[] owner, int type, int ttl, byte[] rdata) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(rdata.length + owner.length + 10);
        out.writeBytes(owner);
        out.write(type >>> 8);
        out.write(type);
        out.write(0);
        out.write(1); // IN
        out.write(ttl >>> 24);
        out.write(ttl >>> 16);
        out.write(ttl >>> 8);
        out.write(ttl);
        out.write(rdata.length >>> 8);
        out.write(rdata.length);
        out.writeBytes(rdata);
        return out.toByteArray();
    }

    /** The four bytes of a dotted quad, or null for anything that is not one (an IPv6 address is not answered as A). */
    private static byte[] ipv4(String address) {
        try {
            byte[] b = InetAddress.getByName(address).getAddress();
            return b.length == 4 ? b : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    private static byte[] txtRdata(String v) {
        byte[] b = v.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream out = new ByteArrayOutputStream(b.length + 2);
        for (int i = 0; i < b.length; i += 255) {
            int n = Math.min(255, b.length - i);
            out.write(n);
            out.write(b, i, n);
        }
        return out.toByteArray();
    }

    private byte[] soaRdata(String mname, int minimum) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        out.writeBytes(encodeName(mname));
        out.writeBytes(encodeName("hostmaster." + hubName));
        for (int v : new int[] {1, 300, 300, 604800, minimum}) { // serial, refresh, retry, expire, minimum
            out.write(v >>> 24);
            out.write(v >>> 16);
            out.write(v >>> 8);
            out.write(v);
        }
        return out.toByteArray();
    }

    static byte[] encodeName(String name) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(name.length() + 2);
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            out.write(b.length);
            out.writeBytes(b);
        }
        out.write(0);
        return out.toByteArray();
    }

    @Override
    public void close() {
        running = false;
        if (udp != null) {
            udp.close();
        }
        if (tcp != null) {
            try {
                tcp.close();
            } catch (IOException ignored) {
                // closing
            }
        }
    }
}
