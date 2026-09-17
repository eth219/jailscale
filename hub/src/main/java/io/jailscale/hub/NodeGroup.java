package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.mux.MuxSession;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.tls.Tls13;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * All connections of one node (multiple connections per node): connection 0 carries control,
 * every connection carries visitor streams. Visitor bookkeeping for the signing checks lives
 * here, keyed by the full stream id {@code (conn << 24) | localId}.
 */
final class NodeGroup {

    private static final Log LOG = Log.get("group");
    static final int MAX_SIGNATURES_PER_STREAM = 4;
    /** Token bucket: a burst of 2,000 handshakes at once, 1,000/s sustained (an ECDSA signature is ~50 µs). */
    static final int SIGN_BURST = 2000;
    static final int SIGN_PER_SECOND = 1000;
    static final int CONN_SHIFT = 24;
    static final long LOCAL_MASK = (1L << CONN_SHIFT) - 1;

    /**
     * A visitor stream while it is open: which link, which SNI, how many signatures it has used,
     * and the plaintext handshake messages the visitor sent (its ClientHello, or two of them
     * around a HelloRetryRequest), which are what a signature gets bound to.
     */
    record VisitorStream(String linkId, String sni, int signatures, Tls13.Tap clientSide) {}

    private final Hub hub;
    private final String mkey;
    private final Map<Integer, NodeSession> sessions = new ConcurrentHashMap<>();
    private final Map<Long, VisitorStream> visitors = new ConcurrentHashMap<>();
    /** Stream object -> full id, so a finished stream is removed under the id it was opened with (never a guess). */
    private final Map<MuxStream, Long> streamIds = new ConcurrentHashMap<>();
    private long signRefillAt = System.currentTimeMillis();
    private double signTokens = SIGN_BURST;
    /**
     * Signing requests being served right now, and the most that were ever in flight at once.
     * The token bucket above says how many arrive; this says how many the hub is inside, which is
     * what tells a queue apart from a burst when the bucket is not the thing refusing.
     */
    private final AtomicInteger signsInFlight = new AtomicInteger();
    private volatile int peakSignsInFlight;

    NodeGroup(Hub hub, String mkey) {
        this.hub = hub;
        this.mkey = mkey;
    }

    String machineKey() {
        return mkey;
    }

    /** Adds a connection; an existing one with the same index is replaced (told to shut down). */
    NodeSession attach(NodeSession s) {
        NodeSession old = sessions.put(s.conn(), s);
        if (old != null && old != s) {
            old.goodbye(Message.Goodbye.SHUTDOWN);
        }
        return old;
    }

    void detach(NodeSession s) {
        sessions.remove(s.conn(), s);
        if (s.conn() == 0) {
            // Losing the control connection ends the whole group.
            for (NodeSession other : new ArrayList<>(sessions.values())) {
                other.close();
            }
            sessions.clear();
        }
        visitors.keySet().removeIf(id -> (id >>> CONN_SHIFT) == s.conn());
        streamIds.values().removeIf(id -> (id >>> CONN_SHIFT) == s.conn());
    }

    /**
     * The control connection, or -- on a host the node reaches only by a relay connection
     * (§13.4) -- the lowest-numbered connection it has here, which is what carries the
     * certificate and speaks for the node on this host.
     */
    NodeSession primary() {
        NodeSession p = sessions.get(0);
        if (p != null) {
            return p;
        }
        NodeSession best = null;
        for (Map.Entry<Integer, NodeSession> e : sessions.entrySet()) {
            if (best == null || e.getKey() < best.conn()) {
                best = e.getValue();
            }
        }
        return best;
    }

    boolean isEmpty() {
        return sessions.isEmpty();
    }

    /** The address the control connection came from, or null when there is none right now. */
    String remoteIp() {
        NodeSession p = primary();
        return p == null ? null : p.remoteIp();
    }

    int connections() {
        return sessions.size();
    }

    List<NodeSession> all() {
        return new ArrayList<>(sessions.values());
    }

    Store.NodeRec node() {
        NodeSession p = primary();
        return p == null ? null : p.node();
    }

    /**
     * Thrown when the node has as many visitors as it said it will hold (ARCHITECTURE.md §9.3). Its
     * own type because the caller's answer differs from every other failure here: there is nothing
     * wrong with the node, nothing to retry, and the visitor is turned away rather than told the
     * name is down.
     */
    static final class AtCapacity extends IOException {
        private static final long serialVersionUID = 1L;
        private final int ceiling;

        AtCapacity(String mkey, int ceiling) {
            super("node " + mkey + " is holding the " + ceiling + " visitors it said it would");
            this.ceiling = ceiling;
        }

        int ceiling() {
            return ceiling;
        }
    }

    /**
     * What this node said it will hold, or 0 if it did not say. The maximum across its sessions
     * rather than one of them: a hand-off has the old and the new connection alive at once (§13)
     * and they carry the same number, but during an upgrade they need not, and the larger is the
     * one that came from whichever build is willing to hold more.
     */
    int visitorCeiling() {
        int max = 0;
        for (NodeSession s : sessions.values()) {
            max = Math.max(max, s.visitorCeiling());
        }
        return max;
    }

    /** Visitor streams open on this node right now, across every one of its connections. */
    int visitorsInFlight() {
        return visitors.size();
    }

    /** Opens a visitor stream on the least loaded connection. */
    MuxStream openVisitor(Links.Link link, String sni, String visitorAddr, int visitorPort, String keyId, boolean dgram) throws IOException {
        NodeSession best = null;
        int bestLoad = Integer.MAX_VALUE;
        for (NodeSession s : sessions.values()) {
            MuxSession m = s.mux();
            if (m == null || m.isClosed() || s.isDraining()) {
                continue;
            }
            int load = m.streamCount();
            if (load < bestLoad) {
                best = s;
                bestLoad = load;
            }
        }
        if (best == null) {
            throw new IOException("node has no usable connection");
        }
        // Checked here because this is the one place a visitor stream is opened -- TLS through the
        // SNI router and raw TCP and UDP through RawPorts all arrive at this method -- and because
        // the map below is already the exact count: it is filled on open, emptied on close, and
        // purged when a session detaches. A node that does not advertise a bound gets the behaviour
        // it had before the field existed, which is the hub sending and the node resetting.
        int ceiling = visitorCeiling();
        if (ceiling > 0 && visitors.size() >= ceiling) {
            Metrics.VISITORS_REFUSED.increment();
            Metrics.VISITORS_REFUSED_CAPACITY.increment();
            throw new AtCapacity(mkey, ceiling);
        }
        JsonObject meta = JsonObject.builder().put("linkId", link.linkId()).put("kind", link.kind()).put("sni", sni)
            .put("visitorAddr", visitorAddr).put("visitorPort", visitorPort).put("keyId", keyId).build();
        // Recorded before the OPEN frame goes out, not after. The node begins the visitor's TLS
        // handshake the moment it sees that frame and asks this hub to sign inside it; a hub that
        // had not yet reached its own `visitors.put` answered `not-your-stream` and took the
        // handshake down with it. 238 of them in 155 ms on one run of the load test (#201, #183).
        long[] opened = {-1};
        NodeSession on = best;   // the lambda needs it effectively final
        MuxStream stream;
        try {
            stream = on.mux().open(meta, dgram, s -> {
                long id = fullId(on.conn(), s.id());
                opened[0] = id;
                streamIds.put(s, id);
                visitors.put(id, new VisitorStream(link.linkId(), sni, 0, new Tls13.Tap()));
            });
        } catch (IOException | RuntimeException e) {
            // The OPEN frame never went out, so nothing will ever ask about this stream. Its
            // registration would otherwise sit in the map until the session detached, counting
            // against the ceiling that turns visitors away.
            if (opened[0] >= 0) {
                visitors.remove(opened[0]);
            }
            throw e;
        }
        return stream;
    }

    /** The ids of the visitor streams open right now (tests). */
    java.util.Set<Long> visitorIds() {
        return java.util.Set.copyOf(visitors.keySet());
    }

    /** How many signatures a visitor stream has used, or -1 if it is not open (tests). */
    int signaturesUsed(long streamId) {
        VisitorStream vs = visitors.get(streamId);
        return vs == null ? -1 : vs.signatures();
    }

    /** Where the relay hands the visitor's first bytes so the hub can see the ClientHello it delivered. */
    Tls13.Tap clientSide(MuxStream stream) {
        Long id = streamIds.get(stream);
        VisitorStream vs = id == null ? null : visitors.get(id);
        return vs == null ? new Tls13.Tap() : vs.clientSide();
    }

    /**
     * Forgets a visitor stream. Keyed by the stream object: every connection numbers its streams
     * from the same range, so deriving the id from "whichever session still holds it" could hit
     * a live stream on another connection (found by the M4 load test).
     */
    void visitorDone(MuxStream stream) {
        Long id = streamIds.remove(stream);
        if (id != null) {
            visitors.remove(id);
        }
    }

    static long fullId(int conn, long localId) {
        return ((long) conn << CONN_SHIFT) | (localId & LOCAL_MASK);
    }

    /** The most signing requests this group has had in flight at once, since it connected. */
    int peakConcurrentSignatures() {
        return peakSignsInFlight;
    }

    /**
     * Takes one of the stream's {@link #MAX_SIGNATURES_PER_STREAM} signatures, or returns false
     * when they are gone. This is condition 5 of ARCHITECTURE.md §9.2 and the only place that
     * enforces it.
     *
     * <p>Counting it has to be one operation. Requests used to be answered on the connection's mux
     * reader, one at a time, and a read-check-write was safe for that reason alone; they are now
     * answered off that thread (§12), and nothing stops a node from putting several requests for
     * one {@code streamId} on the wire at once. Read, check and write separately and each of them
     * sees the old count, so every one of them is allowed and every one writes 1 -- the cap
     * silently stops existing for a node that asks for it to. The hub does not get to assume the
     * node makes one request at a time; that assumption is what the §9.2 conditions are here
     * instead of.
     */
    boolean reserveSignature(long id) {
        boolean[] taken = new boolean[1];
        visitors.computeIfPresent(id, (k, cur) -> {
            if (cur.signatures() >= MAX_SIGNATURES_PER_STREAM) {
                return cur;
            }
            taken[0] = true;
            return new VisitorStream(cur.linkId(), cur.sni(), cur.signatures() + 1, cur.clientSide());
        });
        return taken[0];
    }

    /** The four conditions of ARCHITECTURE.md §9.2, then the signature. */
    Message sign(Message.SignRequest sr) {
        int inFlight = signsInFlight.incrementAndGet();
        if (inFlight > peakSignsInFlight) {
            peakSignsInFlight = inFlight; // a high-water mark; racing writers can only under-report
        }
        try {
            Message m = signChecked(sr);
            // One place, so a refusal added later cannot forget to be counted: what went back to
            // the node is what says whether it was signed.
            if (m instanceof Message.SignResponse r) {
                (r.sig() == null ? Metrics.SIGNATURES_REFUSED : Metrics.SIGNATURES).increment();
            }
            return m;
        } finally {
            signsInFlight.decrementAndGet();
        }
    }

    private Message signChecked(Message.SignRequest sr) {
        long id = sr.streamId();
        int conn = (int) (id >>> CONN_SHIFT);
        long localId = id & LOCAL_MASK;
        VisitorStream vs = visitors.get(id);
        NodeSession s = sessions.get(conn);
        MuxStream stream = s == null || s.mux() == null ? null : s.mux().stream(localId);
        if (vs == null || stream == null) {
            return reject(sr, "not-your-stream");
        }
        Links.Link link = hub.links().byId(vs.linkId());
        if (link == null || link.group() != this || !link.name().equals(hub.links().nameOf(vs.sni()))) {
            return reject(sr, "name-not-yours");
        }
        if (vs.signatures() >= MAX_SIGNATURES_PER_STREAM) {
            return reject(sr, "too-many-signatures"); // cheap pre-check; reserveSignature is the binding one
        }
        // The hash the node wants signed must be the transcript of the handshake on this very
        // stream: the ClientHello the hub delivered, the ServerHello and EncryptedExtensions the
        // node says it answered with, and the hub's own certificate. A member that is on-path
        // for another name cannot get its forged handshake signed, because that handshake's
        // ClientHello never came through here.
        String hashAlg = Tls13.hashAlgorithmOf(sr.content());
        if (hashAlg == null) {
            return reject(sr, "not-a-certificate-verify");
        }
        byte[] certificate = hub.tls().certificateMessage(sr.keyId());
        if (certificate == null) {
            return reject(sr, "unknown-key");
        }
        try {
            byte[] expected = Tls13.transcriptHash(hashAlg, vs.clientSide().messages(), sr.helloRetryRequest(), sr.serverHello(),
                sr.encryptedExtensions(), certificate);
            if (!java.util.Arrays.equals(expected, Tls13.transcriptHashIn(sr.content()))) {
                return reject(sr, "transcript-mismatch");
            }
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return reject(sr, "transcript-mismatch: " + e.getMessage());
        }
        synchronized (this) {
            long now = System.currentTimeMillis();
            signTokens = Math.min(SIGN_BURST, signTokens + (now - signRefillAt) * SIGN_PER_SECOND / 1000.0);
            signRefillAt = now;
            if (signTokens < 1) {
                return reject(sr, "rate-limited");
            }
            signTokens -= 1;
        }
        if (!reserveSignature(id)) {
            return reject(sr, "too-many-signatures");
        }
        try {
            byte[] sig = hub.tls().sign(sr.keyId(), sr.content());
            if (sig == null) {
                return reject(sr, "unknown-key");
            }
            return new Message.SignResponse(id, sig, null);
        } catch (GeneralSecurityException e) {
            return reject(sr, "sign-failed: " + e.getMessage());
        }
    }

    private Message reject(Message.SignRequest sr, String reason) {
        LOG.warn("node {}: signature refused for stream {}: {}", mkey, sr.streamId(), reason);
        return new Message.SignResponse(sr.streamId(), null, reason);
    }

    /** Sends a control message on connection 0. */
    void send(Message m) throws IOException {
        NodeSession p = primary();
        if (p == null) {
            throw new IOException("no control connection");
        }
        p.send(m);
    }

    void goodbyeAll(String reason) {
        for (NodeSession s : all()) {
            s.goodbye(reason);
        }
    }

    /** Hand-off: tell the node to open fresh connections elsewhere but keep these until drained. */
    void drain() {
        for (NodeSession s : all()) {
            s.drain();
        }
    }
}
