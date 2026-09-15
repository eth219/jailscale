package io.jailscale.node;

import io.jailscale.crypto.NoiseException;
import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.CodecException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.mux.FlowBudget;
import io.jailscale.proto.mux.MuxSession;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;

/**
 * The node's connections to the hub (ARCHITECTURE.md §5, §5.3, §6): connection 0 carries control and
 * registration; {@code --connections N} adds N-1 more that only carry visitor streams. On a hub
 * hand-off ({@code Goodbye(draining)}) the current sessions are kept for their streams while a
 * fresh set is opened, so nothing in flight is cut (§13).
 */
final class HubLink implements AutoCloseable {

    private static final Log LOG = Log.get("link");
    private static final long[] BACKOFF_MS = {1000, 2000, 4000, 8000, 16000, 30000};
    static final long DRAIN_TIMEOUT_MS = 60_000;
    static final int CONN_SHIFT = 24;

    /** Credentials for the next RegisterRequest; cleared once registered. */
    record Credentials(String invite, String code, String authKey, String user) {}

    /** The connection index a relay connection uses (§13.4): the last one, so extras keep 1 and 2. */
    static final int RELAY_CONN = 3;

    /** What the daemon wants to know. */
    interface Events {
        void onConnected(HubLink link);

        /** The control connection was told which hosts serve this hub's names right now (§13.4). */
        default void onRelays(HubLink control, List<String> relays) {
        }

        /** A standby asked, on a relay connection, whether the primary can be reached (§13.5). */
        default void onProbe(HubLink relay, Message.PeerProbe probe) {
        }

        /** The primary answered a probe on the control connection; it goes back to whoever asked (§13.5). */
        default void onProbeAnswer(Message.PeerProbeAnswer answer) {
        }

        void onCert(Message.CertUpdate cert);

        /** The hub says this node no longer serves a name it opened (ARCHITECTURE.md §11.4). */
        void onRevoked(Message.LinkRevoked revoked);

        void onVisitor(HubLink link, Session session, MuxStream stream);
    }

    /** The oldest hub protocol this node can talk to; below it the hub cannot decode what we send. */
    static final int MIN_HUB_PROTO = 1;

    /** One connection to the hub. */
    final class Session implements MuxSession.Listener {
        final int conn;
        final MuxSession mux;
        final HubClient.Connected connected;
        final CountDownLatch done = new CountDownLatch(1);
        volatile boolean draining;

        Session(int conn, HubClient.Connected c) {
            this.conn = conn;
            this.connected = c;
            this.mux = new MuxSession(c.channel(), false, this, flowBudget);
        }

        @Override
        public void onControl(MuxSession session, byte[] json) throws IOException {
            Message m;
            try {
                m = Codec.decode(json);
            } catch (CodecException e) {
                throw new IOException("bad control message: " + e.getMessage());
            }
            if (!handle(this, m)) {
                session.close();
            }
        }

        @Override
        public void onOpen(MuxSession session, MuxStream stream) {
            Thread.ofVirtual().name("visitor-" + conn + "-" + stream.id()).start(() -> events.onVisitor(HubLink.this, this, stream));
        }

        @Override
        public void onClosed(MuxSession session, Throwable cause) {
            if (cause != null && running && !draining) {
                lastError = cause.getMessage();
            }
            sessionEnded(this);
            done.countDown();
        }

        void close() {
            mux.close();
            try {
                connected.socket().close();
            } catch (IOException ignored) {
                // closing
            }
        }
    }

    /**
     * One receive budget for every connection to the hub at once (§5.3). The mirror of the hub's
     * exposure: here it is a stalled local app that makes the node hold a visitor's upload, and the
     * heap being protected is again one pool shared by up to four connections.
     */
    private final FlowBudget flowBudget = FlowBudget.ofHeap();
    private final NodeState state;
    private final String version;
    private final Events events;
    /**
     * Null for the control connection. For a relay connection (§13.4), the {@code address} or
     * {@code address:port} of the host it goes to: the same hub name, the same pinned key, the
     * same certificate, another machine.
     */
    private final String relayAddress;
    private volatile Credentials credentials;
    private volatile boolean running;
    private volatile boolean stopReconnecting;
    private volatile Session primary;
    private final Map<Integer, Session> extras = new ConcurrentHashMap<>();
    private final List<Session> draining = new CopyOnWriteArrayList<>();
    private volatile String lastError;
    private volatile Message.RegisterResponse lastRegister;
    /** The relay list the hub gave on the last hello (§13.4); announced once this node is registered. */
    private volatile List<String> lastRelays = List.of();
    private final Map<String, CompletableFuture<Message>> waiting = new ConcurrentHashMap<>();
    private Thread thread;
    /**
     * What this node tells the hub it will hold (ARCHITECTURE.md §9.3), sent on every Hello. Fixed
     * for the life of the process, which is why it rides on Hello rather than having a message of
     * its own: it is derived from the heap ceiling at startup and nothing moves it afterwards. A
     * hand-off or a reconnect re-sends the same number, so the hub needs no notion of it expiring.
     */
    private final int visitorCeiling;

    HubLink(NodeState state, String version, Events events, int visitorCeiling) {
        this(state, version, events, visitorCeiling, null);
    }

    HubLink(NodeState state, String version, Events events, int visitorCeiling, String relayAddress) {
        this.state = state;
        this.version = version;
        this.events = events;
        this.visitorCeiling = visitorCeiling;
        this.relayAddress = relayAddress;
    }

    /** Whether this is a relay connection (§13.4), and to where. */
    boolean isRelay() {
        return relayAddress != null;
    }

    String relayAddress() {
        return relayAddress;
    }

    /**
     * The endpoint the control connection reached, as the socket says, in the form the hub names
     * relays in ({@code address}, or {@code address:port} off 443); null while not connected.
     */
    String remoteEndpoint() {
        Session p = primary;
        if (p == null) {
            return null;
        }
        java.net.InetAddress a = p.connected.socket().getInetAddress();
        if (a == null) {
            return null;
        }
        int port = p.connected.socket().getPort();
        return port == 443 ? a.getHostAddress() : a.getHostAddress() + ":" + port;
    }

    synchronized void start(Credentials creds) {
        this.credentials = creds;
        // A new credential is a new question, so the old answer is not the answer to it. Without
        // this, a rejection stayed on the link and `awaitRegistration` handed it to the next `up`:
        // the hub accepted the invite, the node joined, and the person at the keyboard was told it
        // had failed with the reason the previous attempt failed for.
        this.lastRegister = null;
        this.stopReconnecting = false;
        if (running) {
            Session p = primary;
            if (p != null) {
                p.close(); // reconnect with the new credentials
            }
            return;
        }
        running = true;
        thread = Thread.ofVirtual().name(isRelay() ? "relay-link-" + relayAddress : "hub-link").start(this::loop);
    }

    boolean isConnected() {
        Session p = primary;
        return p != null && !p.mux.isClosed();
    }

    int connectionCount() {
        return (isConnected() ? 1 : 0) + extras.size();
    }

    int drainingCount() {
        return draining.size();
    }

    /** Why each draining connection is still held, for diagnosing a hand-off that will not finish. */
    public String drainingDetail() {
        StringBuilder b = new StringBuilder();
        for (Session s : draining) {
            if (b.length() > 0) {
                b.append("; ");
            }
            b.append("conn ").append(s.conn)
                .append(" muxClosed=").append(s.mux.isClosed())
                .append(" streams=").append(s.mux.streamCount())
                .append(" socketClosed=").append(s.connected.socket().isClosed());
        }
        return b.length() == 0 ? "none" : b.toString();
    }

    String lastError() {
        return lastError;
    }

    Message.RegisterResponse lastRegister() {
        return lastRegister;
    }

    Message.RegisterResponse awaitRegistration(long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            Message.RegisterResponse r = lastRegister;
            if (r != null || stopReconnecting) {
                return r;
            }
            Thread.sleep(50);
        }
        return lastRegister;
    }

    // --- connection loop ---------------------------------------------------------------------

    private void loop() {
        int attempt = 0;
        while (running && !stopReconnecting) {
            Session p = null;
            try {
                p = connectOnce(isRelay() ? RELAY_CONN : 0);
                primary = p;
                attempt = 0;
                p.mux.start();
                afterPrimaryConnected(p);
                p.done.await(); // ends on disconnect or when the session moves to draining
            } catch (NoiseException e) {
                lastError = "hub key mismatch: the hub's key is not the pinned one (" + e.getMessage() + ")";
                LOG.error(lastError);
                stopReconnecting = true;
            } catch (HubClient.Rejected e) {
                // The hub turned us away during the handshake. Retrying an upgrade-required or a
                // revoked node just loops; print what the hub said and stop.
                lastError = e.getMessage();
                LOG.error("{}", lastError);
                if (Message.Goodbye.UPGRADE_REQUIRED.equals(e.reason()) || Message.Goodbye.REVOKED.equals(e.reason())
                    || Message.Goodbye.BANNED.equals(e.reason())) {
                    LOG.error("not reconnecting. `jailscale status` repeats this.");
                    stopReconnecting = true;
                    if (Message.Goodbye.REVOKED.equals(e.reason())) {
                        state.registered = false;
                        try {
                            state.save();
                        } catch (IOException ignored) {
                            // the in-memory flag is what stops the loop
                        }
                    }
                }
            } catch (IOException | RuntimeException e) {
                lastError = e.getMessage() == null ? e.toString() : e.getMessage();
                if (running && !stopReconnecting) {
                    LOG.warn("connection lost: {}", lastError);
                }
            } catch (InterruptedException e) {
                return;
            } finally {
                if (p != null && primary == p) {
                    primary = null;
                    p.close();
                    closeExtras();
                }
            }
            if (!running || stopReconnecting) {
                break;
            }
            if (p != null && p.draining) {
                continue; // hand-off: reconnect right away
            }
            long wait = BACKOFF_MS[Math.min(attempt++, BACKOFF_MS.length - 1)];
            try {
                Thread.sleep(wait);
            } catch (InterruptedException e) {
                return;
            }
        }
        running = false;
    }

    private Session connectOnce(int conn) throws IOException, NoiseException {
        SSLContext ctx;
        try {
            ctx = HubClient.clientContext(state);
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("TLS setup: " + e.getMessage(), e);
        }
        boolean verify = !state.tlsInsecure;
        List<String> keys = new ArrayList<>(2);
        keys.add(state.hubKey);
        if (state.nextHubKey != null) {
            keys.add(state.nextHubKey);
        }
        // Only when DNS was actually asked: with --hub-addr the name never resolved, and a hub
        // reading this as proof that its A record works would be reading our configuration file.
        String resolved = state.hubAddr == null && !isRelay() ? state.hubHost : null;
        Message.Hello hello = new Message.Hello(Message.PROTO, version, osName(), conn, resolved, visitorCeiling, isRelay());
        String addr = state.hubAddr;
        int port = state.hubPort;
        if (isRelay()) {
            int colon = relayAddress.lastIndexOf(':');
            if (colon > 0 && relayAddress.indexOf(':') == colon) {
                addr = relayAddress.substring(0, colon);
                port = Integer.parseInt(relayAddress.substring(colon + 1));
            } else {
                addr = relayAddress;
            }
        }
        HubClient.Connected c = HubClient.connect(state.hubHost, addr, port, ctx, verify, state.machineKey, keys, hello);
        if (c.hello().proto() < MIN_HUB_PROTO) {
            // There is no older encoding to fall back to: the first SignRequest, domain claim or
            // http-01 upload would be a message the hub cannot decode, and it would just close.
            c.channel().close();
            throw new HubClient.Rejected(Message.Goodbye.UPGRADE_REQUIRED, "the hub speaks protocol " + c.hello().proto()
                + " and this jailscale needs " + MIN_HUB_PROTO + ". The hub runs jailhub " + c.hello().version()
                + "; update jailhub there (or run a jailscale from the same release as the hub).");
        }
        if (isRelay()) {
            lastError = null;
            LOG.info("relay connection to {} up (hub v{})", relayAddress, c.hello().version());
        } else if (conn == 0) {
            if (!c.usedHubKey().equals(state.hubKey)) {
                LOG.info("hub key rotation complete; pinning the new key");
                state.hubKey = c.usedHubKey();
                state.nextHubKey = null;
                state.hubKeyActivatesAt = 0;
                state.save();
            }
            if (c.hello().dnsSuffix() != null && !c.hello().dnsSuffix().equals(state.dnsSuffix)) {
                state.dnsSuffix = c.hello().dnsSuffix();
                state.save();
            }
            lastError = null;
            LOG.info("connected to {} (hub v{})", state.hubHost, c.hello().version());
            List<String> relays = c.hello().relays();
            lastRelays = relays == null ? List.of() : relays;
        }
        return new Session(conn, c);
    }

    private void afterPrimaryConnected(Session p) throws IOException {
        if (isRelay()) {
            // Nothing to register: the host on the other end holds this node's registration in the
            // copy it keeps, and a relay connection asks it only to serve what the node already has.
            onRegistered();
            return;
        }
        if (!state.registered) {
            Credentials cr = credentials;
            send(new Message.RegisterRequest(hostname(), osName(), cr == null ? null : cr.user(),
                cr == null ? null : cr.invite(), cr == null ? null : cr.code(), cr == null ? null : cr.authKey()));
        } else {
            onRegistered();
        }
    }

    /**
     * What a rejected registration means to the person at the keyboard. The hub's reason is one
     * word; the ones with a known remedy get it spelled out, because a bare {@code user-taken}
     * leaves them nothing to act on (§6.1).
     */
    static String rejectionText(String reason) {
        String text = "registration rejected: " + reason;
        if ("user-taken".equals(reason)) {
            text += ". That name already belongs to someone on this hub. If it is you, run `jailscale invite --self`"
                + " on a machine that is already joined and use that invite here; otherwise join with `--user <another name>`.";
        }
        return text;
    }

    /** Registered (now or earlier): reopen links and bring up the extra connections. */
    private void onRegistered() {
        Thread.ofVirtual().name("link-connected").start(() -> {
            if (!isRelay()) {
                // After registration and after `primary` is set: a relay connection is refused
                // for a node the host does not know, and the one endpoint to leave out of the
                // list is the one this connection reached, which the socket only says now.
                events.onRelays(this, lastRelays);
            }
            events.onConnected(this);
            openExtras();
        });
    }

    private void openExtras() {
        if (isRelay()) {
            return;
        }
        int want = Math.max(1, Math.min(state.connections, RELAY_CONN)); // 3 leaves the index a relay connection uses
        for (int i = 1; i < want; i++) {
            if (extras.containsKey(i) || primary == null) {
                continue;
            }
            try {
                Session s = connectOnce(i);
                extras.put(i, s);
                s.mux.start();
                LOG.info("extra connection {} up", i);
            } catch (IOException | NoiseException e) {
                LOG.warn("extra connection {} failed: {}", i, e.getMessage());
            }
        }
    }

    private void closeExtras() {
        for (Session s : new ArrayList<>(extras.values())) {
            s.close();
        }
        extras.clear();
    }

    private void sessionEnded(Session s) {
        if (draining.remove(s)) {
            LOG.info("drained connection {} closed", s.conn);
            return;
        }
        if (s.conn > 0) {
            extras.remove(s.conn, s);
            if (running && primary != null && !primary.mux.isClosed()) {
                Thread.ofVirtual().start(() -> {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ignored) {
                        return;
                    }
                    openExtras();
                });
            }
        }
    }

    /** Hand-off: keep every current session for its streams, reconnect the whole set now. */
    private void beginDraining() {
        Session p = primary;
        List<Session> all = new ArrayList<>();
        if (p != null) {
            all.add(p);
        }
        all.addAll(extras.values());
        extras.clear();
        for (Session s : all) {
            s.draining = true;
            draining.add(s);
            Thread.ofVirtual().name("drain-" + s.conn).start(() -> drainWatch(s));
        }
        for (CompletableFuture<Message> f : waiting.values()) {
            f.completeExceptionally(new IOException("hub is handing off"));
        }
        waiting.clear();
        primary = null;
        LOG.info("hub is handing off: keeping {} connection(s) for in-flight streams, reconnecting", all.size());
        if (p != null) {
            p.done.countDown(); // the loop reconnects immediately without closing p
        }
    }

    private void drainWatch(Session s) {
        long deadline = System.currentTimeMillis() + DRAIN_TIMEOUT_MS;
        try {
            while (!s.mux.isClosed() && s.mux.streamCount() > 0 && System.currentTimeMillis() < deadline) {
                Thread.sleep(200);
            }
        } catch (InterruptedException ignored) {
            // fall through
        }
        s.close();
        // Only onClosed takes a session off this list, and it does not fire again for one the hub
        // already closed. That happens two ways: the hub drops the connection before this watch
        // starts, or an extra's own read loop reaches onClosed before beginDraining has added it,
        // so the remove there finds nothing. Either way the entry outlives the connection and
        // drainingCount() never returns to zero. Removing here covers both.
        if (draining.remove(s)) {
            LOG.info("drained connection {} closed", s.conn);
        }
    }

    // --- control messages --------------------------------------------------------------------

    private boolean handle(Session s, Message m) throws IOException {
        switch (m) {
            case Message.RegisterResponse r -> {
                lastRegister = r;
                switch (r.status()) {
                    case Message.RegisterResponse.APPROVED -> {
                        state.registered = true;
                        state.nodeId = r.nodeId();
                        state.user = r.user();
                        state.save();
                        credentials = null;
                        LOG.info("registered as node {} for {}", r.nodeId(), r.user());
                        onRegistered();
                    }
                    case Message.RegisterResponse.PENDING -> LOG.info("waiting for admin approval");
                    default -> {
                        lastError = rejectionText(r.reason());
                        LOG.error("{}", lastError);
                        stopReconnecting = true;
                        return false;
                    }
                }
            }
            case Message.HubKeyRotation k -> {
                state.nextHubKey = k.nextHubKey();
                state.hubKeyActivatesAt = k.activatesAt() * 1000;
                state.save();
                LOG.info("hub announced key rotation, activates at {}", k.activatesAt());
            }
            case Message.Goodbye g -> {
                if (g.reason().equals(Message.Goodbye.DRAINING)) {
                    if (s == primary) {
                        beginDraining();
                    }
                    return true; // keep the session open for its streams
                }
                lastError = g.detail() != null ? g.detail() : "hub said goodbye: " + g.reason();
                if (g.reason().equals(Message.Goodbye.REVOKED) || g.reason().equals(Message.Goodbye.UPGRADE_REQUIRED)
                    || g.reason().equals(Message.Goodbye.BANNED)) {
                    stopReconnecting = true;
                    // This is where the node gives up for good, so say why in full rather than
                    // leaving one reason word in a log the user is unlikely to be reading.
                    LOG.error("{}", lastError);
                    LOG.error("not reconnecting. `jailscale status` repeats this.");
                    if (g.reason().equals(Message.Goodbye.REVOKED)) {
                        state.registered = false;
                        state.save();
                    }
                }
                return false;
            }
            case Message.CertUpdate c -> events.onCert(c);
            case Message.LinkRevoked r -> events.onRevoked(r);
            case Message.PeerProbe pp -> {
                if (isRelay()) {
                    events.onProbe(this, pp);
                }
            }
            case Message.PeerProbeAnswer pa -> {
                if (!isRelay()) {
                    events.onProbeAnswer(pa);
                }
            }
            case Message.RelaysChanged rc -> {
                lastRelays = rc.relays() == null ? List.of() : rc.relays();
                if (!isRelay() && state.registered) {
                    events.onRelays(this, lastRelays);
                }
            }
            case Message.Pong p -> complete("Pong", m);
            case Message.InviteCreated ic -> complete("InviteCreated", m);
            case Message.AdminLink al -> complete("AdminLink", m);
            case Message.LinkOpened lo -> complete("LinkOpened", m);
            case Message.Ack a -> complete("Ack", m);
            case Message.SignResponse sr -> complete("SignResponse:" + sr.streamId(), m);
            case Message.Error e -> {
                String key = e.inReplyTo() == null ? "" : replyKeyFor(e.inReplyTo());
                if (!complete(key, m)) {
                    LOG.warn("hub error: {}", e.reason());
                }
            }
            // A newer hub sending something this jailscale has no case for (ARCHITECTURE.md §5.4).
            case Message.Unknown u -> LOG.info("ignoring {} from the hub: this jailscale does not know that message type", u.type());
            default -> LOG.warn("unexpected {} from hub", m.type());
        }
        return true;
    }

    private static String replyKeyFor(String request) {
        return switch (request) {
            case "InviteCreate" -> "InviteCreated";
            case "AdminLinkRequest" -> "AdminLink";
            case "Ping" -> "Pong";
            case "LinkOpen" -> "LinkOpened";
            case "ChallengeSet", "ChallengeClear" -> "Ack";
            default -> request;
        };
    }

    private boolean complete(String key, Message m) {
        CompletableFuture<Message> f = waiting.remove(key);
        if (f != null) {
            f.complete(m);
            return true;
        }
        return false;
    }

    /** Full stream id as the hub sees it: {@code (conn << 24) | localId}. */
    static long fullStreamId(int conn, long localId) {
        return ((long) conn << CONN_SHIFT) | (localId & ((1L << CONN_SHIFT) - 1));
    }

    /** Builds a message bound to the connection it will travel on, given that connection's Noise handshake hash. */
    interface Bound {
        Message build(byte[] handshakeHash) throws IOException;
    }

    /**
     * Sends a request built over the control connection's Noise handshake hash, on that same
     * connection. A domain claim is signed over the hash so the hub can tell the claim was made on
     * this connection and not copied from somewhere else (§8.3); taking the hash and sending
     * against one snapshot of the session is what keeps a reconnect in between from producing a
     * proof for one connection on another.
     */
    Message request(Bound m, String replyKey, long timeoutMs) throws IOException, TimeoutException {
        Session s = primary;
        if (s == null || s.mux.isClosed()) {
            throw new IOException(lastError != null ? "not connected: " + lastError : "not connected");
        }
        return requestOn(s, m.build(s.connected.channel().handshakeHash()), replyKey, timeoutMs);
    }

    /** Sends a request on the control connection and waits for the reply registered under {@code replyKey}. */
    Message request(Message m, String replyKey, long timeoutMs) throws IOException, TimeoutException {
        if (!isConnected()) {
            throw new IOException(lastError != null ? "not connected: " + lastError : "not connected");
        }
        CompletableFuture<Message> f = new CompletableFuture<>();
        if (waiting.putIfAbsent(replyKey, f) != null) {
            throw new IOException("another " + m.type() + " is in flight");
        }
        try {
            send(m);
            return f.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        } catch (java.util.concurrent.ExecutionException e) {
            throw new IOException(e.getCause());
        } finally {
            waiting.remove(replyKey, f);
        }
    }

    /**
     * Sends a request on the session that owns the stream and waits for its reply. Signing
     * requests must reach the hub process that delivered the stream (it may be a draining one),
     * and the hub accepts them on any connection.
     */
    Message requestOn(Session s, Message m, String replyKey, long timeoutMs) throws IOException, TimeoutException {
        if (s.mux.isClosed()) {
            throw new IOException("session closed");
        }
        CompletableFuture<Message> f = new CompletableFuture<>();
        if (waiting.putIfAbsent(replyKey, f) != null) {
            throw new IOException("another " + m.type() + " is in flight");
        }
        try {
            s.mux.control(Codec.encode(m));
            return f.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        } catch (java.util.concurrent.ExecutionException e) {
            throw new IOException(e.getCause());
        } finally {
            waiting.remove(replyKey, f);
        }
    }

    void send(Message m) throws IOException {
        Session p = primary;
        if (p == null || p.mux.isClosed()) {
            throw new IOException("not connected");
        }
        p.mux.control(Codec.encode(m));
    }

    @Override
    public synchronized void close() {
        running = false;
        stopReconnecting = true;
        Session p = primary;
        primary = null;
        if (p != null) {
            p.close();
        }
        closeExtras();
        for (Session s : draining) {
            s.close();
        }
        for (CompletableFuture<Message> f : waiting.values()) {
            f.completeExceptionally(new IOException("closed"));
        }
        waiting.clear();
        if (thread != null) {
            thread.interrupt();
        }
    }

    static String osName() {
        return osName(System.getProperty("os.name", ""));
    }

    /** {@code macos}, {@code windows}, {@code linux}, or the lowercased name itself: one classification of {@code os.name}. */
    static String osName(String osName) {
        String os = osName.toLowerCase(java.util.Locale.ROOT);
        if (os.contains("mac") || os.contains("darwin")) { // darwin before "win", which it also contains
            return "macos";
        }
        if (os.contains("win")) {
            return "windows";
        }
        if (os.contains("linux")) {
            return "linux";
        }
        return os.isEmpty() ? "unknown" : os;
    }

    static String hostname() {
        String h = System.getenv("HOSTNAME");
        if (h == null || h.isBlank()) {
            try {
                h = java.net.InetAddress.getLocalHost().getHostName();
            } catch (java.net.UnknownHostException e) {
                h = "node";
            }
        }
        int dot = h.indexOf('.');
        return dot > 0 ? h.substring(0, dot) : h;
    }
}
