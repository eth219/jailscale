package io.jailscale.hub.dns;

import io.jailscale.proto.util.Clock;
import io.jailscale.proto.util.Log;
import io.jailscale.proto.util.Throttle;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
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
    /**
     * How many times {@link #start} draws before it gives up on finding a TCP and UDP port of
     * the same number. Sixteen, for the reason in the comment on that loop.
     *
     * <p>Named rather than written there because the test sizes its band of held ports from it.
     * A band no wider than this budget is one a stepping loop walks out of the top of, so the
     * test that exists to catch stepping passes against it -- which is what #230 found, and
     * #220 found one file away before that. A copy of the number in the test is a copy that
     * goes stale the day this one moves.
     */
    static final int PAIR_TRIES = 16;
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
    /** The label a dns-01 challenge points the CA at. */
    static final String CHALLENGE_LABEL = "_acme-challenge";
    private static final byte[] CHALLENGE_BYTES = labelBytes(CHALLENGE_LABEL);

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
     * What a name may measure on the wire, every label's own length byte and the root's zero
     * included (RFC 1035 §2.3.4). A question over it is refused at {@link #parse} with FORMERR,
     * which is twelve bytes and the cheapest thing this server can send: no resolver asks for such
     * a name, the encoder cannot represent one, and the gap between what this parser accepts and
     * what the encoder can write is where the oversized datagram of {@link #MAX_UDP} came from.
     *
     * <p>It is also what keeps a {@code TC} answer matchable. A resolver pairs a reply with its
     * outstanding query by the question section, so a truncation that had to leave the question out
     * is one it drops as unsolicited — it never follows the {@code TC} to TCP and simply times
     * out. Bounded here, the longest question is {@code 12 + MAX_NAME + 4} bytes, which fits every
     * budget a live caller passes, so the echo is never the thing {@link #truncated} drops.
     */
    static final int MAX_NAME = 255;

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
    private final Throttle tcpLog = new Throttle(RATE_LOG_MS);

    /**
     * Connections TCP 53 will hold at once (#114). Not a rate: a TCP source has completed a
     * handshake and so is a fact rather than a claim, which is the whole argument {@link
     * ResponseRate} rests on and none of it applies here. What this bounds is the descriptor.
     *
     * <p><b>No measurement produced this number, and one should not be read into it.</b> Twenty
     * minutes of the live hub's port 53 saw <em>zero</em> TCP connections, so the measurement says
     * only that a cap of almost any size is free; it cannot say which. The number is argued from
     * two ends instead:
     *
     * <ul>
     *   <li><b>Far above legitimate use.</b> This zone's largest answer is 287 bytes, well inside a
     *       datagram, so nothing here sends a resolver to TCP for size. What arrives is the answer
     *       rate's slip and resolvers that prefer TCP by policy, and 256 at once is orders of
     *       magnitude past either.
     *   <li><b>Far below a descriptor budget the whole process shares.</b> One held connection is
     *       one descriptor, and they are not this listener's to spend -- exhausting them takes TLS
     *       443, the node sessions and the relay with them. The live hub's limit is 65,536, but a
     *       host that never raised it has 1,024, and a quarter of that is as much as an
     *       unauthenticated port should be able to take.
     * </ul>
     *
     * <p>Per-network rather than global would be the better control -- the {@code NetKey} shape
     * {@code SniRouter} already uses for visitors, which treats an IPv6 /64 as one source. It is
     * deliberately not built yet: choosing its number today would mean picking a second figure with
     * nothing behind it, and the counters below are what will produce the first one.
     */
    public static final int MAX_TCP_IN_FLIGHT = 256;

    /**
     * How long one TCP connection may take, start to finish. A query and its answer is one round
     * trip on a socket that has already completed a handshake, so five seconds is generous for
     * anything honest and is what bounds the slot: with it, holding {@link #MAX_TCP_IN_FLIGHT} means
     * opening about fifty connections a second and keeping it up, which costs an attacker real
     * addresses at a rate the counters below will show. Without it -- with only the per-read
     * {@code SO_TIMEOUT} this used to have -- the same slots are held for hours at 64 bytes a
     * second. See {@link #readFully}.
     */
    static final long TCP_DEADLINE_MS = 5_000;

    /** Per-network answer rate on UDP (§11.5); TCP is not rate-metered, having proved its address. */
    private final ResponseRate rate = new ResponseRate();
    /**
     * What TCP 53 is doing, which until #114 nothing could be asked. The four DNS counters that
     * existed were all the UDP path, so the only way to measure this one was {@code ss} from
     * outside the process -- which is how a 2,400-sample run came back all zeros because its filter
     * missed the IPv6-mapped form of the hub's own address, and could not tell that from a quiet
     * port. These are what the per-network bound above will be sized from.
     */
    private final int maxTcpInFlight;
    private final long tcpDeadlineMs;
    private final java.util.concurrent.atomic.AtomicInteger tcpInFlight = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicLong tcpAccepted = new java.util.concurrent.atomic.AtomicLong();
    private final java.util.concurrent.atomic.AtomicLong tcpRefused = new java.util.concurrent.atomic.AtomicLong();
    /**
     * Answers sent on UDP 53, for the metrics endpoint (§6.3). Counted here rather than inside
     * {@link ResponseRate} because a query from a loopback source is answered without that
     * meter ever seeing it, so a count taken there is the metered traffic under a name that says it
     * is all of it, and reads zero on a hub whose resolvers all arrive
     * through a forwarder on this host.
     *
     * <p>Every answer, not only the ones carrying records: a refusal and a datagram-sized truncation
     * are both answers that left. What is not counted here is the slip, which has its own counter --
     * so what arrives on UDP is answered, dropped or truncated, exactly once each. The fourth
     * counter is not part of that: {@code globalRefused} says which of the refusals were the
     * table-wide budget rather than one network's own, and is a subset by design.
     */
    private final java.util.concurrent.atomic.AtomicLong answered = new java.util.concurrent.atomic.AtomicLong();


    private final String zone;      // _acme-challenge.hub.example.com (lower case, no trailing dot)
    private final String hubName;   // hub.example.com, the zone apex
    private final List<byte[]> hubLabels;   // the same, label by label: what a question is matched against
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
        this(hubName, selfToken, MAX_TCP_IN_FLIGHT, TCP_DEADLINE_MS);
    }

    /**
     * With a smaller connection bound and a longer deadline (tests), the way {@code Daemon} takes
     * both a smaller visitor ceiling and its own first-byte deadline for {@code VisitorStallTest}.
     *
     * <p>Both knobs are needed and for opposite reasons. A test that filled the shipped 256 would
     * spend its time finding out whether 256 loopback connects beat a clock. A test that holds even
     * four connections open to prove the bound is full is racing {@link #TCP_DEADLINE_MS}, which
     * exists precisely to stop anyone holding a slot -- so it has to be told to wait longer than the
     * test will take. Leaving either as the shipped value makes the margin the thing under test
     * rather than the bound, which is the shape of the flake #125 was.
     */
    DnsResponder(String hubName, String selfToken, int maxTcpInFlight, long tcpDeadlineMs) {
        this.hubName = hubName.toLowerCase(Locale.ROOT);
        this.hubLabels = labels(this.hubName);
        this.zone = CHALLENGE_LABEL + "." + this.hubName;
        this.selfToken = selfToken;
        this.maxTcpInFlight = maxTcpInFlight;
        this.tcpDeadlineMs = tcpDeadlineMs;
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
        // port 0 one of the two draws the number and the other asks for its twin, which somebody
        // else may already hold -- the two spaces are separate, and on Windows a test run made
        // that collision ordinary -- so the pair is retried with a fresh number rather than
        // reported as a bind failure.
        //
        // TCP draws first and UDP asks for the twin (#102). TCP is the contended space: a closed
        // connection holds its port for 2MSL, which is four minutes on Windows by default, and
        // this suite opens hundreds of short-lived ones, while a closed UDP socket holds nothing
        // at all. Drawing from the crowded side and asking the empty one for the twin is what
        // makes the retry rare.
        //
        // First, and not always, because that reasoning is about which space is crowded and #181
        // found the other one crowded instead: eight attempts on Windows drew eight *adjacent*
        // TCP ports and every one of their UDP twins was taken. A band, not eight collisions, and
        // a stepping allocator walks into a band one number at a time however many attempts it is
        // given. So the sides alternate: whichever space is the crowded one, every other attempt
        // asks it to draw, and its own allocator will not hand out a number it has already given
        // away. Losers are held rather than returned for the same reason -- a returned number is
        // one the next attempt may be handed again, and holding pushes a sequential allocator
        // past the band instead of back into it.
        //
        // PAIR_TRIES is sixteen and not eight, because alternating halves what either side gets:
        // the eight TCP draws #102 sized are eight again only if each side is given eight of its
        // own.
        IOException last = null;
        // Every socket this loop opens and does not go on to use, bound or not, so that no path out
        // of here -- a retry, the throw below, or a RuntimeException from a bind -- leaves one
        // behind. The unbound ones hold no number and could go back sooner, but the finally is
        // microseconds away and one list is one thing to get right.
        List<Closeable> held = new ArrayList<>();
        try {
            for (int attempt = 0; attempt < (port == 0 ? PAIR_TRIES : 1); attempt++) {
                // A fixed port is never drawn by either side: it binds or it is refused, and there
                // is nothing to alternate. That needs no test of its own here -- such a port only
                // ever sees attempt 0, where TCP draws anyway.
                boolean tcpDraws = attempt % 2 == 0;
                ServerSocket t = new ServerSocket();
                held.add(t);
                DatagramSocket u = new DatagramSocket(null);
                held.add(u);
                try {
                    t.setReuseAddress(true);
                    u.setReuseAddress(true);
                    if (tcpDraws) {
                        t.bind(new InetSocketAddress(bindHost, port), 16);
                        u.bind(new InetSocketAddress(bindHost, t.getLocalPort()));
                    } else {
                        u.bind(new InetSocketAddress(bindHost, 0));
                        t.bind(new InetSocketAddress(bindHost, u.getLocalPort()), 16);
                    }
                    tcp = t;
                    udp = u;
                    // The winners are the two the finally below must not close.
                    held.remove(t);
                    held.remove(u);
                    last = null;
                    break;
                } catch (IOException e) {
                    // Which side failed is the thing worth saying, and #181 was answered from
                    // these lines: eight of them naming eight adjacent numbers is a band, where
                    // eight scattered ones would have been eight collisions.
                    last = e;
                    boolean drew = tcpDraws ? t.isBound() : u.isBound();
                    String side = tcpDraws ? "tcp" : "udp";
                    if (drew) {
                        LOG.debug("attempt {}: {} drew {}:{}, the other could not have the twin: {}",
                            attempt, side, bindHost, tcpDraws ? t.getLocalPort() : u.getLocalPort(), e.getMessage());
                    } else {
                        LOG.debug("attempt {}: {} could not have {}:{}: {}",
                            attempt, side, bindHost, port, e.getMessage());
                    }
                }
            }
        } finally {
            // Before the throw below, not after it. A hub that failed to start and is still
            // holding the numbers it tried is worse than one that simply did not start, and
            // aNumberUdpCannotHaveLeavesNoListenerBehind is the test that says so.
            for (Closeable s : held) {
                closeQuietly(s);
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

    /** Giving a socket back: the close throws only when it is already gone. */
    private static void closeQuietly(Closeable s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // already given back
        }
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
        // No name is exempt from here. `_jailhub-self` was, because the lookup that asks for it
        // had no TCP fallback and anyone able to forge a source into the hub's own network could
        // stop a hub identifying itself by emptying that bucket -- and one unmetered name is one
        // name's worth of unbounded egress, which is the total §11.5 says is a number.
        // `DnsQuery` follows a drop or a TC to TCP now, so the flood costs an attacker a flood and
        // buys nothing.
        ResponseRate.Verdict v = rate.check(source, now);
        if (v == ResponseRate.Verdict.ANSWER) {
            return counted(respond(query, Budget.DATAGRAM));
        }
        logRate(now);
        return v == ResponseRate.Verdict.DROP ? null : respond(query, Budget.NO_RECORDS);
    }

    /** One answer on its way out, counted as it goes. */
    private byte[] counted(byte[] response) {
        if (response != null) {
            answered.incrementAndGet();
        }
        return response;
    }

    /** Queries answered on UDP 53 since this hub started, for the metrics endpoint (§6.3). */
    public long answered() {
        return answered.get();
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

    /** Connections being served on TCP 53 right now, against the bound this responder was given (#114). */
    public int tcpInFlight() {
        return tcpInFlight.get();
    }

    /** That bound: {@link #MAX_TCP_IN_FLIGHT}, unless a test asked for a smaller one. */
    public int maxTcpInFlight() {
        return maxTcpInFlight;
    }

    /** Every connection this listener accepted, refused ones included: the denominator for the next. */
    public long tcpAccepted() {
        return tcpAccepted.get();
    }

    /** Of those, the ones closed unread because the bound was already full. */
    public long tcpRefused() {
        return tcpRefused.get();
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
                tcpAccepted.incrementAndGet();
                if (tcpInFlight.incrementAndGet() > maxTcpInFlight) {
                    tcpInFlight.decrementAndGet();
                    refuseTcp(s);
                    continue;
                }
                Thread.ofVirtual().start(() -> {
                    try {
                        serveTcp(s);
                    } finally {
                        tcpInFlight.decrementAndGet();
                    }
                });
            } catch (IOException e) {
                if (running) {
                    LOG.debug("tcp: {}", e.getMessage());
                }
            }
        }
    }

    /**
     * One connection over {@link #MAX_TCP_IN_FLIGHT}, closed without being read.
     *
     * <p><b>It is closed rather than answered, and that is indistinguishable from this hub being
     * down</b> -- which matters, because a resolver arriving here has usually just been told
     * {@code TC} and sent away from a working datagram. The alternative is to read the query and
     * answer it with {@code SERVFAIL}, which is politer and is exactly the work this bound exists
     * to refuse: a message read is up to 4,096 bytes and a slot held to {@link #TCP_DEADLINE_MS},
     * per connection, under precisely the load that makes the bound matter. {@code Visitors.refuse}
     * makes the same trade on the node for the same reason -- "saying anything politer would mean
     * completing the handshake that this exists to avoid".
     *
     * <p>So what an operator gets instead is the counter and a line a minute, because a resolver
     * cannot be told and a person can.
     */
    private void refuseTcp(Socket s) {
        tcpRefused.incrementAndGet();
        try {
            s.close();
        } catch (IOException ignored) {
            // refusing it is the point; it is gone either way
        }
        if (tcpLog.ready()) {
            LOG.warn("at the TCP connection bound ({}) on :53; {} refused so far. A resolver sent here by TC "
                + "sees this as the hub being unreachable (ARCHITECTURE.md §11.5)", maxTcpInFlight, tcpRefused.get());
        }
    }

    private void serveTcp(Socket s) {
        long deadline = Clock.millis() + tcpDeadlineMs;
        try (s) {
            java.io.InputStream in = s.getInputStream();
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            byte[] prefix = new byte[2];
            readFully(s, in, prefix, deadline);
            int len = ((prefix[0] & 0xff) << 8) | (prefix[1] & 0xff);
            if (len > 4096) {
                return;
            }
            byte[] q = new byte[len];
            readFully(s, in, q, deadline);
            byte[] r = respond(q);
            if (r != null) {
                out.writeShort(r.length);
                out.write(r);
                out.flush();
            }
        } catch (IOException ignored) {
            // client gone, or out of time
        }
    }

    /**
     * Reads exactly {@code buf.length} bytes, or gives up at {@code deadline} — which bounds the
     * <em>connection</em> and not one read of it.
     *
     * <p>This was {@code setSoTimeout(5000)} and {@code DataInputStream.readFully}, and that pair
     * bounds neither. {@code SO_TIMEOUT} applies to a single blocking read and is restarted by every
     * byte that arrives, so a client that declares a 4,096-byte message and then sends one byte
     * every four seconds holds its slot for about four and a half hours at a quarter of a byte per
     * second. That is the whole of {@link #MAX_TCP_IN_FLIGHT} held indefinitely for roughly 64 bytes
     * a second, which would have made the bound below a way to take TCP 53 down rather than a way to
     * keep it up -- and the per-connection cost the 256 was argued from was wrong by four orders of
     * magnitude. Re-arming against what is left of the deadline is what makes the slot recycle.
     */
    private static void readFully(Socket s, java.io.InputStream in, byte[] buf, long deadline) throws IOException {
        int off = 0;
        while (off < buf.length) {
            long left = deadline - Clock.millis();
            if (left <= 0) {
                throw new java.net.SocketTimeoutException("past the connection deadline");
            }
            s.setSoTimeout((int) Math.min(left, Integer.MAX_VALUE));
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) {
                throw new java.io.EOFException("client gone");
            }
            off += n;
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
        List<byte[]> labels = qn.labels();
        if (labels.size() < hubLabels.size() || !endsWithApex(labels)) {
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
        // What is left above the apex: nothing at all is the apex itself, and one label is a name
        // this zone may hold.
        List<byte[]> prefix = labels.subList(0, labels.size() - hubLabels.size());
        if (prefix.size() == 1 && java.util.Arrays.equals(prefix.get(0), CHALLENGE_BYTES)) {
            return challenge(qn);
        }
        if (prefix.isEmpty()) {
            return apex(qn);
        }
        return under(qn, prefix);
    }

    /** Whether {@code labels} ends in the apex's, byte for byte and label for label. */
    private boolean endsWithApex(List<byte[]> labels) {
        int off = labels.size() - hubLabels.size();
        for (int i = 0; i < hubLabels.size(); i++) {
            if (!java.util.Arrays.equals(labels.get(off + i), hubLabels.get(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * ASCII case folding, which is the only case rule DNS has (RFC 4343). A byte over 0x7F is
     * itself: it is not a letter here, whatever encoding the sender had in mind.
     */
    private static byte lower(byte b) {
        return b >= 'A' && b <= 'Z' ? (byte) (b + 0x20) : b;
    }

    /** A name as the case-folded labels a question is compared against. */
    private static List<byte[]> labels(String name) {
        List<byte[]> out = new ArrayList<>();
        for (String label : name.split("\\.")) {
            out.add(labelBytes(label));
        }
        return out;
    }

    private static byte[] labelBytes(String label) {
        byte[] b = label.getBytes(StandardCharsets.ISO_8859_1);
        for (int i = 0; i < b.length; i++) {
            b[i] = lower(b[i]);
        }
        return b;
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
     * <p>{@code labels} is the name, label by label and case-folded as ASCII, and never joined
     * into one string: a label may hold a dot, and a byte over 0x7F is not a character, so the
     * string form makes two names that differ on the wire into one -- which is how a single label
     * reading {@code ns1.<hub>} was answered with ns1's glue.
     *
     * <p>{@code end} is the offset one past the question: what an answer echoes, and what a
     * truncated answer is cut to. {@code budget} is what the transport will carry. The two travel
     * with the question because they are spent in the same place — {@link #build}, which is the only
     * code that knows how large the answer came out.
     */
    private record Question(byte[] query, List<byte[]> labels, int type, int end, Budget budget) {}

    /** The one reading of a question in this file; null is a FORMERR for the caller to send. */
    private static Question parse(byte[] q, Budget budget) {
        int p = 12;
        List<byte[]> labels = new ArrayList<>();
        while (p < q.length) {
            int l = q[p++] & 0xff;
            if (l == 0) {
                break;
            }
            if ((l & 0xc0) != 0 || p + l > q.length) {
                return null;
            }
            byte[] label = new byte[l];
            for (int i = 0; i < l; i++) {
                label[i] = lower(q[p + i]);
            }
            labels.add(label);
            p += l;
        }
        // `p` is one past the name, so `p - 12` is what it measures on the wire: RFC 1035 §2.3.4,
        // and the bound the encoder has always assumed it was writing within.
        if (p - 12 > MAX_NAME || p + 4 > q.length) {
            return null;
        }
        int type = ((q[p] & 0xff) << 8) | (q[p + 1] & 0xff);
        return new Question(q, labels, type, p + 4, budget);
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
    private byte[] under(Question qn, List<byte[]> prefix) {
        int qtype = qn.type();
        Zone z = view;
        Map<String, String> ns = ordered(z.nameServers());
        List<byte[]> answers = new ArrayList<>();
        // One label is a name this zone may hold, decoded a byte to a character so that two labels
        // that differ on the wire cannot arrive here as one string; deeper is null, since no name
        // this zone holds has two labels and the wildcard covers the rest.
        String label = prefix.size() == 1 ? new String(prefix.get(0), StandardCharsets.ISO_8859_1) : null;
        if (SELF_LABEL.equals(label)) {
            if (qtype == TYPE_TXT) {
                answers.add(rr(TYPE_TXT, TTL_TXT, txtRdata(selfToken)));
            }
        } else if (label != null && (ns.containsKey(label) || GLUE_LABELS.contains(label))) {
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
            for (String a : label != null ? z.forName(label) : z.serving()) {
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
     * for REFUSED, which echoes no question either. Useful to nobody, though: a resolver pairs a
     * reply with its query by the question section, so it drops that one as unsolicited and times
     * out rather than coming back over TCP.
     *
     * <p>Which is why nothing live reaches that branch any more. {@link #parse} refuses a name over
     * {@link #MAX_NAME}, so a question is at most {@code 12 + MAX_NAME + 4} bytes and fits every
     * budget that exists here. What used to reach it — 60 labels under the hub name, 998 bytes,
     * echoed at whatever size it came by the pass that cut the answer down, leaving a 998-byte
     * datagram over the §11.5 bound that pass existed to keep — is twelve bytes of FORMERR now and
     * never sees an encoder. The branch stays because the byte count is the budget's and not this
     * file's constant: a resolver that offers EDNS may advertise less room than the question it
     * sent, and that is the caller it is for. {@code
     * DnsAmplificationTest.aBudgetSmallerThanADatagramBoundsTheEchoToo} holds it to the promise
     * meanwhile.
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
            closeQuietly(tcp);
        }
    }
}
