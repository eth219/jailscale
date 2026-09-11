package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.mux.MuxSession;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

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

    /** What the hub remembers about a visitor stream it opened. */
    record VisitorStream(String linkId, String sni, int signatures) {}

    private final Hub hub;
    private final String mkey;
    private final Map<Integer, NodeSession> sessions = new ConcurrentHashMap<>();
    private final Map<Long, VisitorStream> visitors = new ConcurrentHashMap<>();
    /** Stream object -> full id, so a finished stream is removed under the id it was opened with (never a guess). */
    private final Map<MuxStream, Long> streamIds = new ConcurrentHashMap<>();
    private long signRefillAt = System.currentTimeMillis();
    private double signTokens = SIGN_BURST;

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

    NodeSession primary() {
        return sessions.get(0);
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
        JsonObject meta = JsonObject.builder().put("linkId", link.linkId()).put("kind", link.kind()).put("sni", sni)
            .put("visitorAddr", visitorAddr).put("visitorPort", visitorPort).put("keyId", keyId).build();
        MuxStream stream = best.mux().open(meta, dgram);
        long id = fullId(best.conn(), stream.id());
        streamIds.put(stream, id);
        visitors.put(id, new VisitorStream(link.linkId(), sni, 0));
        return stream;
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

    /** The four conditions of ARCHITECTURE.md §9.2, then the signature. */
    Message sign(Message.SignRequest sr) {
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
            return reject(sr, "too-many-signatures");
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
        visitors.put(id, new VisitorStream(vs.linkId(), vs.sni(), vs.signatures() + 1));
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
