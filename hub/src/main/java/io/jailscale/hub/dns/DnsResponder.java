package io.jailscale.hub.dns;

import io.jailscale.proto.util.Clock;
import io.jailscale.proto.util.Log;
import io.jailscale.proto.util.Throttle;
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
 * <p>UDP and TCP, no EDNS, no compression beyond a pointer to the question name. Recursion is never
 * offered and names outside the zone are REFUSED in twelve bytes, which is a third of what asking
 * costs. The answers that do exist are small — the largest this zone can hold is 287 bytes and the
 * worst ratio of answer to query is 5.3, both measured and gated by {@code DnsAmplificationTest} —
 * so this is a poor amplifier. It is not a harmless one, and a datagram's source address is a claim
 * rather than a fact, so what leaves on UDP is metered per network by {@link ResponseRate} and never
 * exceeds {@link #MAX_UDP}.
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
    /** A glue name's address: what the parent holds, bounded so a wrong one cannot outlive an hour by much. */
    static final int TTL_GLUE = 300;
    /** The labels the parent may delegate to; never answered from the wildcard, even before the glue is known. */
    public static final List<String> GLUE_LABELS = List.of("ns1", "ns2");
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

    /**
     * What a resolver that has not offered EDNS may be sent in a datagram (RFC 1035 §4.2.1). Beyond
     * it the answer is the header with {@code TC} set and the resolver asks again over TCP.
     */
    static final int MAX_UDP = 512;

    /**
     * How much of an answer may leave, which is two questions and not one: how many bytes the
     * transport will carry, and whether records may go at all.
     *
     * <p>They were one {@code int} to begin with, zero meaning no records. That reads like a size
     * right up to the day something computes one — an EDNS buffer minus what is already spent
     * arrives at zero meaning <i>no room at all</i>, and would have been handed the whole 512 — and
     * the ceiling the echo is measured against was then a constant rather than what was asked for,
     * so a resolver that advertised 4,096 would have had its answer cut to 512 anyway. Two fields
     * that each mean one thing cost a record and cannot be read the wrong way.
     */
    record Budget(int bytes, boolean records) {
        /** TCP: a length prefix carries whatever the answer is, so nothing there is ever truncated. */
        static final Budget WHOLE = new Budget(Integer.MAX_VALUE, true);
        /** A datagram for a resolver that has not offered EDNS (RFC 1035 §4.2.1). */
        static final Budget DATAGRAM = new Budget(MAX_UDP, true);
        /**
         * Over the answer rate, and the one query in {@code ResponseRate.SLIP} that is answered
         * rather than dropped: a datagram's room, and no records to put in it.
         */
        static final Budget NO_RECORDS = new Budget(MAX_UDP, false);
    }
    private static final long RATE_LOG_MS = 60_000;
    private final Throttle rateLog = new Throttle(RATE_LOG_MS);

    /** Per-network answer rate on UDP (§11.5); TCP is not metered, having proved its address. */
    private final ResponseRate rate = new ResponseRate();
    /**
     * The encoded question a hub's own self-probe asks (§13.3), so the meter can leave it alone.
     *
     * <p>{@code Advertise.whoAmI} asks each glue address on :53 for this name to find out which of
     * them is this host, and those queries leave from a public address, so they were metered like
     * anyone's -- which handed an attacker with the forging capability this limiter assumes a way
     * to stop a hub identifying itself: about twenty packets a second with a source forged into the
     * hub's own network empties that bucket, the probe is dropped or truncated, {@code DnsQuery}
     * has no TCP fallback, and {@code whoAmI} swallows the failure at debug and returns null. A hub
     * that never learns its address serves an empty zone. Exempting the name costs nothing to an
     * attacker: its answer is 87 bytes for a 52-byte query, the lowest ratio the zone has.
     */
    private final byte[] selfQuestion;


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
        this.selfQuestion = encodeName(SELF_LABEL + "." + this.hubName);
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
                byte[] r = answerForUdp(q, p.getAddress(), Clock.millis());
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

    /**
     * What to put in a datagram back to {@code source}, or null to send nothing at all.
     *
     * <p>Separate from {@link #respond}, which TCP shares, because both rules here are about the
     * transport rather than about the zone: a datagram's source address is a claim and not a fact
     * (§11.5), so what leaves is metered per network, and a datagram has 512 bytes for a resolver
     * that has not offered EDNS, so anything longer becomes a pointer to TCP. Over TCP neither
     * applies — the address is proved by a handshake, and a length prefix carries whatever the
     * answer is.
     *
     * <p>Both reach the encoder as a budget rather than as a pass over a finished answer: what the
     * meter decided and what a datagram holds are the same kind of statement about how much may
     * leave, and {@link #build} is the only code that knows what the answer came to.
     */
    byte[] answerForUdp(byte[] query, InetAddress source, long now) {
        // Asked before the meter, because these are the two cases respond() has no answer for at
        // all: metering them would spend a network's budget on a packet that is not a question and
        // count it as answered, which is not the order this limit has ever been applied in.
        if (!isQuery(query)) {
            return null;
        }
        if (isSelfProbe(query)) {
            return respond(query, Budget.DATAGRAM);
        }
        ResponseRate.Verdict v = rate.check(source, now);
        if (v == ResponseRate.Verdict.ANSWER) {
            return respond(query, Budget.DATAGRAM);
        }
        logRate(now);
        return v == ResponseRate.Verdict.DROP ? null : respond(query, Budget.NO_RECORDS);
    }

    /** Queries answered on UDP 53 since this hub started, for the metrics endpoint (§6.3). */
    public long answered() {
        return rate.answered();
    }

    /** Of those refused, how many by each budget: one network's own, and the table-wide one. */
    public long dropped() {
        return rate.dropped();
    }

    public long truncatedByRate() {
        return rate.truncated();
    }

    public long refusedByGlobalBudget() {
        return rate.globalRefused();
    }

    /**
     * Whether this is a hub asking {@code _jailhub-self} (§13.3). Compared as the bytes the question
     * already holds rather than parsed again: the name is fixed, so the encoded form is too, and a
     * query that does not match is merely metered, which is the safe way to be wrong.
     */
    private boolean isSelfProbe(byte[] query) {
        if (query.length < 12 + selfQuestion.length) {
            return false;
        }
        for (int i = 0; i < selfQuestion.length; i++) {
            if (query[12 + i] != selfQuestion[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * One line a minute while a flood lasts, the way the node reports a visitor ceiling: per query
     * it would be a line per packet under exactly the load that makes the limit matter.
     */
    private void logRate(long now) {
        if (rateLog.ready()) {
            LOG.warn("over the per-network answer rate on :53; {} queries dropped and {} answered truncated "
                + "so far (ARCHITECTURE.md §11.5)", rate.dropped(), rate.truncated());
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

    /** The whole response for one query message, which is what TCP sends, or null if it is not a query. */
    byte[] respond(byte[] q) {
        return respond(q, Budget.WHOLE);
    }

    /**
     * The same, within a {@link Budget}: what the transport will carry. An answer that does not fit
     * comes back as the {@code TC} form, written by the same encoder — the header, and the question
     * with it where the budget has room for the echo.
     */
    byte[] respond(byte[] q, Budget budget) {
        if (!isQuery(q)) {
            return null;
        }
        int qdcount = ((q[4] & 0xff) << 8) | (q[5] & 0xff);
        if (qdcount != 1) {
            return error(q, RCODE_FORMERR);
        }
        Question qn = parse(q, budget);
        if (qn == null) {
            return error(q, RCODE_FORMERR);
        }
        String qname = qn.name();
        boolean acme = qname.equals(zone);
        boolean atApex = !acme && qname.equals(hubName);
        boolean below = !acme && !atApex && qname.endsWith("." + hubName);
        if (!acme && !atApex && !below) {
            return error(q, RCODE_REFUSED); // not our zone
        }
        // A budget with no room for records is a truncation whatever the records would have been,
        // and this is the flood the slip exists for: building a set of them to throw away is
        // per-packet garbage on the thread reading the socket, which is the argument ResponseRate
        // already makes about its own table. Asked after the zone check, because a name outside the
        // zone is refused in twelve bytes and that reflects less than the TC form does.
        if (!budget.records()) {
            return truncated(qn);
        }
        if (acme) {
            return challenge(qn);
        }
        if (atApex) {
            return apex(qn);
        }
        return under(qn, qname.substring(0, qname.length() - hubName.length() - 1));
    }

    /**
     * Whether this is a query at all: twelve bytes of header, and {@code QR} clear. Exactly the two
     * cases {@link #respond} has nothing to say to, named so that {@link #answerForUdp} can ask them
     * without building an answer first.
     *
     * <p>It does not look at the opcode, so a NOTIFY or an UPDATE is answered as though it were a
     * standard query rather than with NOTIMP. That is how this server has always behaved and it is
     * not this method's to change quietly; the name says query because that is what it is asked.
     */
    private static boolean isQuery(byte[] q) {
        return q.length >= 12 && (q[2] & 0x80) == 0;
    }

    /**
     * One reading of the question, carried to whatever builds the answer.
     *
     * <p>{@code end} is the offset one past the question: what an answer echoes, and what a
     * truncated answer is cut to. {@code budget} is what the transport will carry. The two travel
     * with the question because they are spent in the same place — {@link #build}, which is the only
     * code that knows how large the answer came out.
     */
    private record Question(byte[] query, String name, int type, int end, Budget budget) {}

    /** The one reading of a question in this file; null is a FORMERR for the caller to send. */
    private static Question parse(byte[] q, Budget budget) {
        int p = 12;
        StringBuilder name = new StringBuilder();
        while (p < q.length) {
            int l = q[p++] & 0xff;
            if (l == 0) {
                break;
            }
            if ((l & 0xc0) != 0 || p + l > q.length) {
                return null;
            }
            if (name.length() > 0) {
                name.append('.');
            }
            name.append(new String(q, p, l, StandardCharsets.US_ASCII));
            p += l;
        }
        if (p + 4 > q.length) {
            return null;
        }
        int type = ((q[p] & 0xff) << 8) | (q[p + 1] & 0xff);
        return new Question(q, name.toString().toLowerCase(Locale.ROOT), type, p + 4, budget);
    }

    /** {@code _acme-challenge.<hub>}, exactly as before the hub answered anything else. */
    private byte[] challenge(Question qn) {
        int qtype = qn.type();
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
                return build(qn, List.of(), List.of(rr(TYPE_SOA, TTL_TXT, soa)), List.of());
            }
        }
        return build(qn, answers, List.of(), List.of());
    }

    /** The zone apex: A is the serving set, NS and SOA the delegation (§13.3). */
    private byte[] apex(Question qn) {
        int qtype = qn.type();
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
                    additional.add(rrNamed(encodeName(nsName), TYPE_A, TTL_GLUE, rd));
                }
            }
        } else if (qtype == TYPE_SOA) {
            answers.add(rr(TYPE_SOA, TTL_ZONE, soaRdata(mname(ns), TTL_ADDRESS)));
        }
        if (answers.isEmpty()) {
            return nodata(qn, ns);
        }
        return build(qn, answers, List.of(), additional);
    }

    /** A name under the apex: a name server's glue, this process's token, or the wildcard. */
    private byte[] under(Question qn, String label) {
        int qtype = qn.type();
        Zone z = view;
        Map<String, String> ns = ordered(z.nameServers());
        List<byte[]> answers = new ArrayList<>();
        if (label.equals(SELF_LABEL)) {
            if (qtype == TYPE_TXT) {
                answers.add(rr(TYPE_TXT, TTL_TXT, txtRdata(selfToken)));
            }
        } else if (ns.containsKey(label) || GLUE_LABELS.contains(label)) {
            // A glue name answers the parent's glue, or nothing until that is known: never the
            // wildcard, which would tell a resolver the other name server is this host.
            if (qtype == TYPE_A && ns.containsKey(label)) {
                byte[] rd = ipv4(ns.get(label));
                if (rd != null) {
                    answers.add(rr(TYPE_A, TTL_GLUE, rd));
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
            return nodata(qn, ns);
        }
        return build(qn, answers, List.of(), List.of());
    }

    /** No records of that type here (AAAA, MX, ANY, ...): NOERROR with the apex SOA in the authority section. */
    private byte[] nodata(Question qn, Map<String, String> ns) {
        byte[] soa = rrNamed(encodeName(hubName), TYPE_SOA, TTL_ADDRESS, soaRdata(mname(ns), TTL_ADDRESS));
        return build(qn, List.of(), List.of(soa), List.of());
    }

    /** By label, so ns1 is answered before ns2 and is the SOA's mname whatever map the zone handed over. */
    private static Map<String, String> ordered(Map<String, String> ns) {
        return ns.isEmpty() ? ns : new java.util.TreeMap<>(ns);
    }

    private String mname(Map<String, String> ns) {
        return ns.isEmpty() ? hubName : ns.keySet().iterator().next() + "." + hubName;
    }

    /**
     * The one encoder, and the one place a budget is spent. An answer that does not fit what the
     * transport will carry leaves here as the {@code TC} form, written from the {@code end} the
     * question already carries — rather than handed to a second pass that walked the finished
     * response to find that offset again. That pass was a second and weaker parser of the same
     * bytes, correct only for as long as nothing made answers larger: the change that adds EDNS,
     * question compression or a second question is the change that would make its truncation
     * malformed, and a malformed answer is not an error a resolver reports, it is one it discards.
     */
    private byte[] build(Question qn, List<byte[]> answers, List<byte[]> authority, List<byte[]> additional) {
        byte[] q = qn.query();
        Budget budget = qn.budget();
        int size = qn.end() + length(answers) + length(authority) + length(additional);
        // The definition of a budget, both halves of it. `respond` short-circuits the second before
        // any of these records is encoded; it stays here because this is the statement, and a
        // builder reached with no room for records must not answer with some.
        if (!budget.records() || size > budget.bytes()) {
            return truncated(qn);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(size);
        // QR, AA, copy RD; never RA, and no rcode -- everything that carries one goes through error()
        header(out, q, 0x8400 | (q[2] & 0x01) << 8, 1, answers.size(), authority.size(), additional.size());
        out.write(q, 12, qn.end() - 12);
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

    /**
     * The header with {@code TC} set and, where a datagram has room for it, the question echoed: a
     * resolver reads that as an instruction to ask again over TCP, which this server also answers.
     *
     * <p>Two callers with one shape. An answer past {@link #MAX_UDP} has to be cut because that is
     * what a resolver with no EDNS is allowed to receive, and one larger is discarded rather than
     * read — which under {@code _acme-challenge} is a certificate that stops renewing and says so
     * nowhere. Over the answer rate it is the polite half of the refusal
     * ({@code ResponseRate.SLIP}), and it arrives here as a budget of {@link #NO_RECORDS}.
     *
     * <p>What the echo has to fit, <b>and it does have to fit</b>: the budget's own byte count,
     * which is a datagram's for both callers that reach here and is whatever a resolver advertised
     * the day one offers EDNS. A question too long for it is dropped with the records, leaving the
     * header — still a well-formed {@code TC} answer, and the same shape this server already sends
     * for REFUSED, which echoes no question either.
     *
     * <p>That branch is not hypothetical. A name here is bounded by the packet and not by the 255
     * bytes RFC 1035 allows one ({@code #89}), so a query of nearly a kilobyte is accepted, and the
     * pass that used to cut the answer down had no idea what it was cutting it to: it echoed the
     * question whatever its size, and the answer left at the size of the query — 998 bytes in
     * {@code DnsAmplificationTest}, over the §11.5 bound, broken by the one path that existed to
     * keep it.
     */
    private static byte[] truncated(Question qn) {
        byte[] q = qn.query();
        boolean echo = qn.end() <= qn.budget().bytes();
        ByteArrayOutputStream out = new ByteArrayOutputStream(echo ? qn.end() : 12);
        header(out, q, 0x8600 | (q[2] & 0x01) << 8, echo ? 1 : 0, 0, 0, 0);
        if (echo) {
            out.write(q, 12, qn.end() - 12);
        }
        return out.toByteArray();
    }

    /**
     * A bare header: FORMERR or REFUSED in twelve bytes, which no budget can make smaller, so none
     * is taken. It is not turned into a {@code TC} answer when the answer rate slips one through
     * either — a refusal carrying {@code TC} sends a resolver to TCP to be refused a second time,
     * and a refusal echoes no question, so there is nothing in it to reflect.
     *
     * <p>RD is copied, as RFC 1035 §4.1.1 says it is and as the other two shapes already did. Only
     * this one dropped it, which was invisible while each wrote its own header.
     */
    private byte[] error(byte[] q, int rcode) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(12);
        header(out, q, 0x8000 | (q[2] & 0x01) << 8 | rcode, 0, 0, 0, 0);
        return out.toByteArray();
    }

    /** The twelve bytes every message starts with: the query's id, the flags given, and four counts. */
    private static void header(ByteArrayOutputStream out, byte[] q, int flags, int qd, int an, int ns, int ar) {
        out.write(q[0]);
        out.write(q[1]);
        writeShort(out, flags);
        writeShort(out, qd);
        writeShort(out, an);
        writeShort(out, ns);
        writeShort(out, ar);
    }

    private static void writeShort(ByteArrayOutputStream out, int v) {
        out.write(v >>> 8);
        out.write(v);
    }

    private static int length(List<byte[]> records) {
        int n = 0;
        for (byte[] r : records) {
            n += r.length;
        }
        return n;
    }

    /** A resource record whose name is a pointer to the question name (offset 12). */
    private static byte[] rr(int type, int ttl, byte[] rdata) {
        return rrNamed(new byte[] {(byte) 0xc0, 0x0c}, type, ttl, rdata);
    }

    /** A resource record with an explicit owner name (a SOA in the authority section names the apex, not the query). */
    private static byte[] rrNamed(byte[] owner, int type, int ttl, byte[] rdata) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(rdata.length + owner.length + 10);
        out.writeBytes(owner);
        writeShort(out, type);
        writeShort(out, 1); // IN
        writeShort(out, ttl >>> 16);
        writeShort(out, ttl);
        writeShort(out, rdata.length);
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
