package io.jailscale.hub;

import io.jailscale.crypto.KeyText;
import io.jailscale.crypto.NoiseException;
import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.CodecException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.mux.MuxSession;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.mux.NoiseChannel;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.Locale;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * One connection from a node after the HTTP 101 (ARCHITECTURE.md §5, §5.3, §6). The Hello carries the
 * connection index; index 0 is the control connection and handles registration, links,
 * invites and signing on stream 0. Every connection carries visitor streams.
 */
final class NodeSession implements AutoCloseable, MuxSession.Listener {

    private static final Log LOG = Log.get("session");
    static final int MIN_PROTO = 1;
    static final int IDLE_TIMEOUT_MS = 60_000;
    static final int MAX_CONNECTIONS = 4;
    /**
     * Signing requests this connection will answer off the reader thread at once. Sized above the
     * concurrency a real burst produces (a 1,000-visitor load peaks at a few hundred across the
     * node) so the bound is only reached by a peer that is trying to reach it.
     */
    static final int MAX_CONCURRENT_SIGNS = 256;
    /**
     * What a new connection actually starts with. A legitimate burst does not come near the
     * default -- 1,000 visitors against one node peak at about 150 in flight, because that number
     * is the arrival rate times the time a signature takes and neither grows with the visitor
     * count -- so the fallback below is only reached by a peer that sets out to reach it. Tests
     * lower this to get there.
     */
    static int concurrentSignLimit = MAX_CONCURRENT_SIGNS;

    private final Hub hub;
    private final Socket socket;
    private final String remoteIp;
    private MuxSession mux;
    private String mkey;
    private int conn;
    /**
     * A relay connection (ARCHITECTURE.md §13.4): opened by a node that has its control
     * connection elsewhere, to serve visitors who reach this host. It registers nothing and asks
     * for nothing that writes; it opens the links its node already holds, and it signs.
     */
    private boolean relay;
    /**
     * What the node said it will hold (ARCHITECTURE.md §9.3), or 0 from a node that does not say --
     * every build before the field existed, and any build that chose not to. 0 means "no bound the
     * hub knows of" and puts admission back where it was: the hub's own caps and the node's reset.
     */
    private volatile int visitorCeiling;
    private NodeGroup group;
    private volatile Store.NodeRec node;
    private volatile boolean closed;
    private volatile boolean draining;
    private volatile byte[] handshakeHash;
    private final Semaphore signSlots = new Semaphore(concurrentSignLimit);
    /** Signing requests answered on the reader thread because the limit above was reached. */
    private final AtomicInteger signedInline = new AtomicInteger();

    NodeSession(Hub hub, Socket socket, String remoteIp) {
        this.hub = hub;
        this.socket = socket;
        this.remoteIp = remoteIp;
    }

    String machineKey() {
        return mkey;
    }

    int visitorCeiling() {
        return visitorCeiling;
    }

    int conn() {
        return conn;
    }

    boolean isRelay() {
        return relay;
    }

    Store.NodeRec node() {
        return node;
    }

    NodeGroup group() {
        return group;
    }

    MuxSession mux() {
        return mux;
    }

    boolean isDraining() {
        return draining;
    }

    String remoteIp() {
        return remoteIp;
    }

    /**
     * The Noise handshake hash of this connection. Both ends derive it and nobody else can, so it
     * is what a node signs to prove a domain claim belongs to this connection (§8.3).
     */
    byte[] handshakeHash() {
        return handshakeHash;
    }

    /** Runs to completion on the connection's virtual thread. */
    void run(InputStream in, OutputStream out) {
        try {
            if (hub.bans().isBanned(remoteIp)) {
                // Refused before the Noise handshake, so a banned address cannot make the hub do
                // any crypto. Nothing is sent back: there is nothing useful to say.
                hub.bans().logRefusal(remoteIp, "control connection");
                return;
            }
            socket.setSoTimeout(IDLE_TIMEOUT_MS);
            boolean[] rejected = new boolean[1];
            String[] peerHost = new String[1];
            String[] peerAddress = new String[1];
            Message.PeerHello[] demoteTo = new Message.PeerHello[1];
            String[] peerEndpoint = new String[1];
            NoiseChannel ch = NoiseChannel.respond(in, out, hub.keys().responders(), (p1, hs) -> {
                Message m;
                try {
                    m = Codec.decode(p1);
                } catch (CodecException e) {
                    throw new NoiseException("bad Hello: " + e.getMessage());
                }
                // A caller whose static key is this hub's own holds hub.key: a standby hub, not a
                // node (ARCHITECTURE.md §13.1). Decided by the key the handshake authenticated,
                // not by what the message claims to be.
                if (hub.keys().isOwn(hs.remoteStatic())) {
                    if (!(m instanceof Message.PeerHello ph)) {
                        throw new NoiseException("a peer's first message must be PeerHello, got " + m.type());
                    }
                    if (Role.PRIMARY.equals(ph.role()) && !hub.isStandby()) {
                        // Two primaries meeting (§13.5): the epochs decide, and the tie by address.
                        rejected[0] = true;
                        if (hub.roleFile().outrankedBy(ph.epoch(), ph.address(), hub.advertisedAddress())) {
                            LOG.warn("{} says it is the primary at epoch {}; this hub is at {} and stands down", ph.host(),
                                ph.epoch(), hub.epoch());
                            demoteTo[0] = ph;
                            return Codec.encode(new Message.PeerHelloResponse(Message.PROTO, Hub.version(), hub.config().hostname(),
                                hub.advertisedAddress(), hub.relayEndpoint(), Role.STANDBY, hub.epoch()));
                        }
                        return Codec.encode(new Message.PeerHelloResponse(Message.PROTO, Hub.version(), hub.config().hostname(),
                            hub.advertisedAddress(), hub.relayEndpoint(), Role.PRIMARY, hub.epoch()));
                    }
                    if (hub.isStandby()) {
                        // Told what this hub is, with its epoch: a primary that dialled it learns
                        // there is no primary here to stand down before; a standby learns both
                        // are standbys, which is for a person to sort out (§13.5).
                        rejected[0] = true;
                        return Codec.encode(new Message.PeerHelloResponse(Message.PROTO, Hub.version(), hub.config().hostname(),
                            hub.advertisedAddress(), hub.relayEndpoint(), Role.STANDBY, hub.epoch()));
                    }
                    peerHost[0] = ph.host() == null ? remoteIp : ph.host();
                    peerAddress[0] = ph.address();
                    peerEndpoint[0] = ph.endpoint();
                    LOG.info("standby {} from {} (v{}{})", peerHost[0], remoteIp, ph.version(),
                        ph.address() == null ? "" : ", advertises " + ph.address());
                    return Codec.encode(new Message.PeerHelloResponse(Message.PROTO, Hub.version(), hub.config().hostname(),
                        hub.advertisedAddress(), hub.relayEndpoint(), Role.PRIMARY, hub.epoch()));
                }
                mkey = KeyText.format(KeyText.MACHINE, hs.remoteStatic());
                if (!(m instanceof Message.Hello hello)) {
                    throw new NoiseException("first message must be Hello, got " + m.type());
                }
                relay = hello.relay();
                if (hub.isStandby() && !relay) {
                    // Told where to go rather than served: a standby holds no registration that a
                    // node could act on, and the reason is not one the node stops retrying for, so
                    // it keeps trying until DNS moves or this hub is promoted. A relay connection
                    // is the exception (§13.4): it wants nothing written, only its links served.
                    rejected[0] = true;
                    return Codec.encode(new Message.Goodbye("standby", "this hub is a standby of "
                        + hub.config().peer().getHost() + " and takes no nodes until it is promoted"));
                }
                if (hello.proto() < MIN_PROTO) {
                    rejected[0] = true;
                    // Say what is needed. The node cannot work it out: it never gets a
                    // HelloResponse, so minProto and the hub's version never reach it otherwise.
                    LOG.info("refused a node speaking proto {} from {} (need {}); told it to upgrade",
                        hello.proto(), remoteIp, MIN_PROTO);
                    return Codec.encode(new Message.Goodbye(Message.Goodbye.UPGRADE_REQUIRED,
                        "this hub speaks protocol " + MIN_PROTO + " and newer; your jailscale speaks "
                            + hello.proto() + ". The hub runs jailhub " + Hub.version()
                            + ". Update jailscale and run `jailscale up` again."));
                }
                conn = hello.conn();
                visitorCeiling = hello.visitors();
                if (conn < 0 || conn >= MAX_CONNECTIONS || ((conn > 0 || relay) && hub.store().node(mkey) == null)) {
                    rejected[0] = true;
                    return Codec.encode(new Message.Goodbye("bad-connection-index"));
                }
                LOG.info("node {} conn {}{} from {} (v{}, {})", mkey, conn, relay ? " (relay)" : "", remoteIp, hello.version(), hello.os());
                if (!relay) {
                    hub.reachedBy(hello.host(), remoteIp);
                }
                return Codec.encode(new Message.HelloResponse(Message.PROTO, MIN_PROTO, Hub.version(), hub.config().dnsSuffix(),
                    relay ? null : hub.relaysForNodes()));
            });
            if (rejected[0]) {
                if (demoteTo[0] != null) {
                    hub.demote(demoteTo[0].epoch(), demoteTo[0].host());
                }
                return;
            }
            if (peerHost[0] != null) {
                hub.peers().new Session(remoteIp, peerHost[0], peerAddress[0], peerEndpoint[0]).run(ch);
                return;
            }
            Metrics.NODE_SESSIONS.increment();
            handshakeHash = ch.handshakeHash();
            if (hub.isHandingOff()) {
                LOG.info("node {} arrived during hand-off; asking it to retry", mkey);
                return;
            }
            node = hub.store().node(mkey);
            mux = new MuxSession(ch, true, this, hub.flowBudget());
            group = hub.registry().attach(this);
            if ((conn == 0 || relay) && node != null && hub.tls().isLoaded()) {
                send(hub.tls().certUpdate());
            }
            if (conn == 0 && node != null && !hub.isStandby()) {
                deliverNotices();
            }
            mux.run();
        } catch (NoiseException e) {
            LOG.warn("handshake with {} failed: {}", remoteIp, e.getMessage());
        } catch (IOException | GeneralSecurityException e) {
            if (!closed) {
                LOG.debug("session {} ended: {}", mkey, e.toString());
            }
        } finally {
            if (group != null) {
                hub.registry().detach(this);
            }
            if (conn == 0 && mkey != null) {
                hub.challenges().clearNode(mkey);
            }
            close();
        }
    }

    // --- MuxSession.Listener -------------------------------------------------------------------

    @Override
    public void onControl(MuxSession session, byte[] json) throws IOException {
        Message m;
        try {
            m = Codec.decode(json);
        } catch (CodecException e) {
            throw new IOException("bad control message: " + e.getMessage());
        }
        if (!handle(m)) {
            close();
        }
    }

    @Override
    public void onOpen(MuxSession session, MuxStream stream) {
        LOG.warn("node {} opened stream {}; nodes do not open streams", mkey, stream.id());
        stream.reset(2);
    }

    @Override
    public void onClosed(MuxSession session, Throwable cause) {
        if (!closed) {
            LOG.info("node {} conn {} disconnected{}", mkey, conn, cause == null ? "" : ": " + cause.getMessage());
        }
        close();
    }

    /** Returns false to end the session. */
    private boolean handle(Message m) throws IOException {
        switch (m) {
            case Message.Ping p -> send(new Message.Pong(p.id()));
            case Message.Goodbye g -> {
                LOG.info("node {} conn {} said goodbye: {}", mkey, conn, g.reason());
                return false;
            }
            case Message.SignRequest sr -> signOffThread(sr);
            // §13.5: a node carrying a standby's question here, and carrying the primary's answer
            // back. The primary answers on any of the node's connections; the standby accepts the
            // answer on the relay connection it asked on.
            case Message.PeerProbe pp -> {
                if (hub.isStandby()) {
                    send(new Message.Error(pp.type(), "primary-only"));
                } else {
                    send(new Message.PeerProbeAnswer(pp.nonce(), Liveness.mac(hub.livenessSecret(), pp.nonce(), hub.epoch()), hub.epoch()));
                }
            }
            case Message.PeerProbeAnswer pa -> hub.probeAnswered(pa);
            // A newer node sending something this hub has no case for (ARCHITECTURE.md §5.4). The
            // Error is the point: the node learns the message did not happen, rather than assuming
            // silence means success.
            case Message.Unknown u -> {
                LOG.info("node {} conn {}: ignoring {}, a message type this hub does not know", mkey, conn, u.type());
                send(new Message.Error(u.type(), "unknown-type"));
            }
            default -> {
                if (conn != 0 && !relay) {
                    LOG.warn("node {} conn {}: {} is only valid on the control connection", mkey, conn, m.type());
                    send(new Message.Error(m.type(), "control-connection-only"));
                    return true;
                }
                if (relay || hub.isStandby()) {
                    // What a relay connection, or any connection to a standby, may ask for: its
                    // links opened (from the replicated store, no write) and closed. Everything
                    // else changes state, and only the primary's control connection does that.
                    if (!(m instanceof Message.LinkOpen) && !(m instanceof Message.LinkClose)) {
                        send(new Message.Error(m.type(), "primary-only"));
                        return true;
                    }
                }
                return handleControl(m);
            }
        }
        return true;
    }

    /**
     * Why a node may not have the hub answer http-01 for this domain, or null. The hub owns port 80
     * for every name that resolves to it, so relaying a token is lending out domain validation:
     * it is lent only for a domain this node may claim (the same rule {@code LinkOpen} applies),
     * and never for the hub's own name (which serves /admin, /join and the first-contact key).
     */
    private String challengeRefusal(String domain) {
        return domain == null ? "bad-domain" : hub.links().domainRefusal(node, domain);
    }

    private boolean handleControl(Message m) throws IOException {
        switch (m) {
            case Message.RegisterRequest r -> {
                Registrar.Decision d = hub.registrar().decide(mkey, r, remoteIp);
                if (d.node() != null) {
                    node = d.node();
                }
                send(d.response());
                if (d.node() != null) {
                    sendCert();
                }
            }
            case Message.InviteCreate ic -> send(hub.invites().createForNode(this, ic));
            case Message.AdminLinkRequest a -> {
                if (node == null || !hub.store().isAdmin(node.user())) {
                    send(new Message.Error(a.type(), "not-an-admin"));
                } else {
                    send(new Message.AdminLink(hub.adminWeb().loginLink(node.user()),
                        (System.currentTimeMillis() + AdminWeb.LOGIN_LINK_TTL_MS) / 1000));
                }
            }
            case Message.LinkOpen lo -> send(hub.links().open(this, lo));
            case Message.ChallengeSet cs -> {
                String domain = cs.domain() == null ? null : cs.domain().toLowerCase(Locale.ROOT);
                String refusal = node == null ? null : challengeRefusal(domain);
                if (node == null) {
                    send(new Message.Error(cs.type(), "not-registered"));
                } else if (!hub.config().hasHttp()) {
                    send(new Message.Error(cs.type(), "hub-has-no-port-80"));
                } else if (refusal != null) {
                    LOG.warn("node {}: refused http-01 relay for {}: {}", mkey, cs.domain(), refusal);
                    send(new Message.Error(cs.type(), refusal));
                } else if ((refusal = hub.challenges().set(mkey, domain, cs.token(), cs.keyAuthorization())) != null) {
                    send(new Message.Error(cs.type(), refusal));
                } else {
                    send(new Message.Ack(cs.type()));
                }
            }
            case Message.ChallengeClear cc -> {
                hub.challenges().clear(mkey, cc.token());
                send(new Message.Ack(cc.type()));
            }
            case Message.LinkClose lc -> hub.links().close(group, lc.linkId());
            default -> {
                LOG.warn("node {}: unexpected {} from node", mkey, m.type());
                send(new Message.Error(m.type(), "unexpected"));
            }
        }
        return true;
    }

    /**
     * Answers a signing request on a thread of its own (ARCHITECTURE.md §9.2, §12).
     *
     * <p>{@link MuxSession.Listener} says callbacks run on the reader thread and must be short,
     * and this one is not: it hashes a transcript, signs with the wildcard key, then writes the
     * reply through the channel's write lock, which can block on a full socket buffer. Done in
     * line, every first visitor handshake stops that connection's reader, and with it the DATA
     * frames of every other visitor stream on it -- 1,024 visitors may share one connection
     * (§8.1), so a burst of handshakes became a burst of stalls for everyone already served.
     *
     * <p>The node already does this in the other direction: it hands each incoming visitor stream
     * to its own virtual thread rather than serving it on the reader. Signing is ordered per
     * stream by the node's own handshake, which cannot ask twice at once, and {@code sign} takes
     * the token bucket under a lock, so nothing here depended on the reader's serialisation.
     */
    private void signOffThread(Message.SignRequest sr) throws IOException {
        // Bounded, because how many of these exist is the node's choice otherwise: it decides how
        // many SignRequests to put on the wire, and each one that got a thread of its own would
        // hold the request, its transcript and a stack until the channel write lock came free.
        // §12 bounds memory by the connection limits, and an unbounded spawn is outside them.
        // Over the limit the request is answered on the reader thread instead, which is where all
        // of them used to be answered: a flood degrades to the old serialisation rather than to a
        // refusal, so a legitimate burst is slow at worst and never fails.
        if (!signSlots.tryAcquire()) {
            signedInline.incrementAndGet();
            send(group.sign(sr));
            return;
        }
        Thread.ofVirtual().name("sign-" + sr.streamId()).start(() -> {
            try {
                send(group.sign(sr));
            } catch (IOException e) {
                LOG.debug("node {}: could not answer a signing request: {}", mkey, e.getMessage());
                close();
            } finally {
                signSlots.release();
            }
        });
    }

    /** How many signing requests this connection had to answer on its reader thread. */
    int signedInline() {
        return signedInline.get();
    }

    void visitorDone(MuxStream stream) {
        if (group != null) {
            group.visitorDone(stream);
        }
    }

    void send(Message m) throws IOException {
        MuxSession s = mux;
        if (s == null) {
            throw new IOException("not connected");
        }
        s.control(Codec.encode(m));
    }

    private void sendCert() throws IOException {
        if (hub.tls().isLoaded()) {
            try {
                send(hub.tls().certUpdate());
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }
    }

    /** Called when a pending node is approved by an admin. */
    void approved(Store.NodeRec n) {
        node = n;
        try {
            send(Message.RegisterResponse.approved(n.id(), n.user()));
            sendCert();
        } catch (IOException e) {
            close();
        }
    }

    /**
     * Hands over the names this node lost while it was away (ARCHITECTURE.md §11.4), then forgets them.
     * Cleared only after every one is on the wire, so a node that dies mid-delivery is told again.
     */
    private void deliverNotices() throws IOException {
        java.util.List<Store.NoticeRec> pending = hub.store().notices(mkey);
        if (pending.isEmpty()) {
            return;
        }
        for (Store.NoticeRec r : pending) {
            send(new Message.LinkRevoked(r.linkId(), r.name(), r.reason(), r.at()));
        }
        hub.store().clearNotices(mkey);
        LOG.info("told {} about {} name(s) it lost while away", mkey, pending.size());
    }

    /** Pushes a certificate change to a registered node. */
    void certChanged() {
        if (node != null && (conn == 0 || relay)) {
            try {
                sendCert();
            } catch (IOException e) {
                close();
            }
        }
    }

    void goodbye(String reason) {
        try {
            send(new Message.Goodbye(reason));
        } catch (IOException ignored) {
            // closing anyway
        }
        close();
    }

    /**
     * Hand-off (ARCHITECTURE.md §13): the node is asked to reconnect elsewhere; this connection stays
     * open only for the streams already on it and closes once they are gone.
     */
    void drain() {
        draining = true;
        try {
            send(new Message.Goodbye(Message.Goodbye.DRAINING));
        } catch (IOException e) {
            close();
            return;
        }
        Thread.ofVirtual().name("drain-" + mkey).start(() -> {
            long deadline = System.currentTimeMillis() + Hub.DRAIN_TIMEOUT_MS;
            try {
                while (!closed && System.currentTimeMillis() < deadline) {
                    MuxSession s = mux;
                    if (s == null || s.isClosed() || s.streamCount() == 0) {
                        break;
                    }
                    Thread.sleep(200);
                }
            } catch (InterruptedException ignored) {
                // fall through
            }
            close();
        });
    }

    @Override
    public void close() {
        closed = true;
        MuxSession s = mux;
        if (s != null) {
            s.close();
        }
        try {
            socket.close();
        } catch (IOException ignored) {
            // nothing to do
        }
    }
}
