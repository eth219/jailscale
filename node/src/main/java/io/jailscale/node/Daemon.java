package io.jailscale.node;

import io.jailscale.crypto.KeyText;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.mux.MuxSession;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/** The resident node process: owns the state file, the hub link, links and the local IPC (ARCHITECTURE.md §9). */
public final class Daemon implements AutoCloseable, Ipc.Handler, HubLink.Events {

    private static final Log LOG = Log.get("daemon");
    private static final long REGISTER_TIMEOUT_MS = 30_000;
    private static final long REPLY_TIMEOUT_MS = 10_000;

    private final NodeConfig config;
    private final NodeState state;
    private final HubLink link;
    /**
     * Relay connections (ARCHITECTURE.md §13.4), by the address the hub named: one to every host
     * serving this hub's names other than the one the control connection reached. Each reopens
     * this node's links there, so a visitor who reaches that host is served by this node.
     */
    private final java.util.Map<String, HubLink> relays = new java.util.concurrent.ConcurrentHashMap<>();
    private static final int VERIFY_TIMEOUT_MS = 10_000;

    private final Visitors visitors;
    private volatile boolean closed;
    /** The last release check, for {@code status}; null until the first one has run. */
    private volatile Updates.Result lastUpdate;
    static final URI LETS_ENCRYPT = URI.create("https://acme-v02.api.letsencrypt.org/directory");
    static final long RENEW_CHECK_MS = 3600_000;
    static final long UPDATE_CHECK_MS = 24 * 3600_000L;
    /**
     * How long a full pass of the self-probe takes: every name this node holds is looked at once
     * within it, whatever the number of names (ARCHITECTURE.md §11.3). This, and not the interval
     * between two ticks, is the number the detection bound is written in.
     */
    static final long PROBE_PASS_MS = 30 * 60_000L;
    /** And the shortest a tick may be, so that a pass target cannot turn into a burst of requests. */
    static final long PROBE_MIN_TICK_MS = 60_000L;
    /**
     * How far a sweep is spread out after a hub connection comes up. A hub restarting brings every
     * node back at once, and each of them would otherwise ask it to sign a handshake for every name
     * it holds in the same instant, on top of the reopens that reconnection already costs.
     */
    static final long SWEEP_SPREAD_MS = 5_000L;
    /**
     * What the self-probe waits on between ticks, so that a hub connection coming up can ask for a
     * pass now instead of at the end of one (ARCHITECTURE.md §11.3).
     */
    private final Object probeWake = new Object();
    private boolean sweepAsked;          // guarded by probeWake
    private boolean namesChanged;        // guarded by probeWake: a name was opened, resize the tick
    /**
     * When the last sweep ran, on {@link System#nanoTime}: the probe thread's own, and monotonic
     * because a clock that steps must not move the interval anything here is written in.
     */
    private long lastSweepNanos = System.nanoTime() - PROBE_PASS_MS * 1_000_000L;
    /** How close to its end a certificate has to be before anyone is told (ARCHITECTURE.md §15). */
    static final long CERT_WARN_MS = 14 * 86400_000L;
    private static final long CERT_WARN_REPEAT_MS = 86400_000L;
    private Ipc.Server ipc;

    public Daemon(NodeConfig config) throws IOException {
        this.config = config;
        this.state = NodeState.load(config.stateFile());
        // visitors first: its bound goes into every Hello this link sends (ARCHITECTURE.md §9.3).
        this.visitors = new Visitors(state, config.tuning().visitorCeiling(), config.tuning().firstByteMs());
        this.link = new HubLink(state, Version.string(), this, visitors.maxInFlight());
    }

    public void start() throws IOException {
        ipc = Ipc.serve(config.socketPath(), this);
        LOG.info("jailscale {} daemon, machine key {}", Version.string(), state.machineKeyText());
        if (state.hasHub()) {
            link.start(null);
        }
        Thread.ofVirtual().name("update-check").start(this::updateLoop);
        Thread.ofVirtual().name("self-probe").start(this::probeLoop);
    }

    // --- HubLink.Events --------------------------------------------------------------------------

    @Override
    public void onConnected(HubLink l) {
        for (NodeState.LinkRec rec : state.links) {
            try {
                reopen(rec, l);
            } catch (IOException | TimeoutException e) {
                LOG.warn("could not reopen link {}{}: {}", rec.name, l.isRelay() ? " on " + l.relayAddress() : "", e.getMessage());
            }
        }
        if (!l.isRelay()) {
            // Only the control connection decides who owns a name. A relay coming up changes
            // nothing the probe could see -- it connects through the hub's address either way --
            // and its ask would spend the once-per-pass sweep on the wrong event, leaving none
            // for the control connection's own return inside the same pass.
            askProbeSweep();
        }
    }

    /**
     * {@code linkId} is per hub session (NodeState.LinkRec), so it goes when the session does --
     * not when the next session fails to reopen the name, which is too late. From the moment a
     * new connection is up, {@link HubLink#isConnected} is true, and the reopens that give this
     * session its ids are answered one at a time after that; a link id left over from the last
     * session would meanwhile say the name is open to everything that reads it. {@code status}
     * would call it open, and the self-probe would connect to the name, be answered by the hub's
     * own page under the wildcard certificate, and report a hub still starting up as an
     * interception (§11.3) -- the false report that feature must never make.
     */
    @Override
    public void onDisconnected(HubLink l) {
        if (l.isRelay()) {
            return;
        }
        for (NodeState.LinkRec rec : state.links) {
            rec.linkId = null;
        }
    }

    /**
     * Ask the self-probe for a full pass now rather than at its own pace (ARCHITECTURE.md §11.3).
     * A node that loses a name is usually offline when it happens -- being offline is why someone
     * else took it (§11.4) -- so the moment the link is back is the moment worth looking, and the
     * ticks spent disconnected went nowhere. The ask is a flag, not a queue: a link that flaps must
     * cost one pass at most, and {@code lastSweepNanos} is what holds it to that.
     */
    private void askProbeSweep() {
        synchronized (probeWake) {
            sweepAsked = true;
            probeWake.notifyAll();
        }
    }

    /**
     * A name was opened: the tick in flight was sized for one name fewer, and
     * {@link #awaitProbeTick} sizes it again from the names held now.
     */
    private void wakeProbe() {
        synchronized (probeWake) {
            namesChanged = true;
            probeWake.notifyAll();
        }
    }

    /**
     * The hub named the hosts serving its names (§13.4). One relay connection to each that is not
     * the host the control connection reached; one that is no longer named is closed. Compared by
     * address, because the hub names hosts by address and the socket knows the one it reached.
     */
    @Override
    public synchronized void onRelays(HubLink control, List<String> named) {
        String reached = control.remoteEndpoint();
        java.util.Set<String> want = new java.util.LinkedHashSet<>();
        for (String r : named) {
            if (reached == null || !r.equals(reached)) {
                want.add(r);
            }
        }
        for (String gone : new ArrayList<>(relays.keySet())) {
            if (!want.contains(gone)) {
                HubLink old = relays.remove(gone);
                old.close();
                LOG.info("relay {} is no longer named by the hub; connection closed", gone);
            }
        }
        for (String r : want) {
            if (!relays.containsKey(r) && !closed) {
                HubLink rl = new HubLink(state, Version.string(), this, visitors.maxInFlight(), r);
                relays.put(r, rl);
                rl.start(null);
                LOG.info("hub names {} as a relay; opening a connection there", r);
            }
        }
    }

    /** Probes in flight (§13.5): the standby's nonce to the relay connection it asked on. Bounded by pruning. */
    private final java.util.Map<String, HubLink> probes = new java.util.concurrent.ConcurrentHashMap<>();

    /**
     * §13.5: a standby asks whether the primary is reachable. This node passes the question up
     * its control connection and the answer back down the relay connection it came on. It cannot
     * make the answer: the MAC is under a key only the hubs hold. What it can do is stay silent,
     * and one honest node answering is enough to block a promotion.
     */
    @Override
    public void onProbe(HubLink relay, Message.PeerProbe probe) {
        String key = java.util.HexFormat.of().formatHex(probe.nonce());
        if (probes.size() > 64) {
            probes.clear();
        }
        probes.put(key, relay);
        try {
            link.send(probe);
        } catch (IOException e) {
            probes.remove(key);
            LOG.debug("probe from {} not forwarded: {}", relay.relayAddress(), e.getMessage());
        }
    }

    @Override
    public void onProbeAnswer(Message.PeerProbeAnswer answer) {
        HubLink relay = probes.remove(java.util.HexFormat.of().formatHex(answer.nonce()));
        if (relay != null && relay.isConnected()) {
            try {
                relay.send(answer);
            } catch (IOException e) {
                LOG.debug("probe answer to {} not delivered: {}", relay.relayAddress(), e.getMessage());
            }
        }
    }

    /** The relay connections and whether each is up, for {@code status}. */
    private List<Object> relayRows() {
        return relays.entrySet().stream().<Object>map(e -> JsonObject.builder()
            .put("address", e.getKey()).put("connected", e.getValue().isConnected())
            .put("lastError", e.getValue().lastError()).build().asMap()).toList();
    }

    @Override
    public void onCert(Message.CertUpdate cert) {
        visitors.onCert(cert);
    }

    @Override
    public void onVisitor(HubLink l, HubLink.Session session, MuxStream stream) {
        visitors.serve(l, session, stream);
    }

    /**
     * A name this node opened is no longer served by it (ARCHITECTURE.md §11.4). Drop it from the state
     * so the next reconnect does not silently reopen it, and say so loudly: if the node did not
     * expect this, someone else is now answering for that name.
     */
    @Override
    public synchronized void onRevoked(Message.LinkRevoked r) {
        // Match by name first: a reopen racing this notice would carry a new linkId. Raw ports
        // have no name of ours ("tcp/1234" is the hub's label), so fall back to the link id.
        NodeState.LinkRec rec = state.linkByName(r.name());
        if (rec == null && r.linkId() != null) {
            for (NodeState.LinkRec l : state.links) {
                if (r.linkId().equals(l.linkId)) {
                    rec = l;
                }
            }
        }
        if (rec != null) {
            state.links.remove(rec);
        }
        state.revoked.add(new NodeState.RevokedRec(r.name(), r.reason(), r.at()));
        try {
            state.save();
        } catch (IOException e) {
            LOG.warn("cannot record that {} was revoked: {}", r.name(), e.getMessage());
        }
        if (Message.LinkRevoked.REASSIGNED.equals(r.reason())) {
            LOG.error("{} was reassigned: the hub now serves that name from another node. If you did not "
                + "move it, treat it as compromised and read ARCHITECTURE.md §11.2.", r.name());
        } else {
            LOG.error("{} was released by the hub operator and is no longer yours.", r.name());
        }
        LOG.error("`jailscale status` repeats this.");
    }

    private Message.LinkOpened reopen(NodeState.LinkRec rec) throws IOException, TimeoutException {
        Message.LinkOpened lo = reopen(rec, link);
        // Then on every relay host that is up: best effort, since a relay that is down reopens
        // everything when it comes back (onConnected), and the primary's answer is the one that
        // names the link.
        for (HubLink rl : relays.values()) {
            if (rl.isConnected()) {
                try {
                    reopen(rec, rl);
                } catch (IOException | TimeoutException e) {
                    LOG.warn("could not open {} on relay {}: {}", rec.name, rl.relayAddress(), e.getMessage());
                }
            }
        }
        return lo;
    }

    /**
     * Opens one link on one hub connection. On the control connection this is where a name is
     * assigned and the link's identity comes from; on a relay connection (§13.4) the name is the
     * one already assigned, and the id that host gives is kept by address, so a close can name it.
     */
    private synchronized Message.LinkOpened reopen(NodeState.LinkRec rec, HubLink on) throws IOException, TimeoutException {
        if (on.isRelay() && rec.name == null) {
            throw new IOException("not yet named by the primary");
        }
        Message r = on.request(new Message.LinkOpen(rec.name, rec.local()), "LinkOpened", REPLY_TIMEOUT_MS);
        if (r instanceof Message.LinkOpened lo && lo.reason() == null) {
            if (on.isRelay()) {
                rec.relayLinkIds.put(on.relayAddress(), lo.linkId());
                LOG.info("link {} -> {} also served from {}", lo.name(), rec.local(), on.relayAddress());
                return lo;
            }
            rec.linkId = lo.linkId();
            rec.name = lo.name();
            rec.url = lo.url();
            LOG.info("link {} -> {} open at {}", lo.name(), rec.local(), lo.url());
            return lo;
        }
        String reason = r instanceof Message.LinkOpened lo ? lo.reason() : r instanceof Message.Error e ? e.reason() : r.type();
        throw new IOException(reason);
    }

    // --- IPC -------------------------------------------------------------------------------------

    @Override
    public void handle(JsonObject req, Ipc.Reply reply) throws Exception {
        switch (req.string("cmd")) {
            case "status" -> reply.done(status());
            case "up" -> up(req, reply);
            case "verify" -> verify(reply);
            case "down" -> {
                link.close();
                closeRelays();
                reply.ok();
            }
            case "invite" -> {
                Message r = link.request(new Message.InviteCreate(req.optString("user", null), req.optInt("uses", 0),
                    req.has("ttl") ? req.lng("ttl") : 0, req.optBool("self", false)), "InviteCreated", REPLY_TIMEOUT_MS);
                switch (r) {
                    case Message.InviteCreated(String url, String code, long expiresAt) ->
                        reply.done(JsonObject.builder().put("ok", true).put("url", url).put("code", code).put("expiresAt", expiresAt));
                    case Message.Error e -> reply.error(e.reason());
                    default -> reply.error("unexpected " + r.type());
                }
            }
            case "open" -> open(req, reply);
            case "gate" -> {
                NodeState.LinkRec rec = state.linkByName(req.string("name"));
                if (rec == null) {
                    reply.error("no link named " + req.string("name"));
                    return;
                }
                if (req.optBool("off", false)) {
                    rec.gateHash = null;
                    rec.gateExpiresAt = 0;
                    state.save();
                    reply.done(JsonObject.builder().put("ok", true).put("gate", false));
                    return;
                }
                String token = Gate.newToken();
                rec.gateHash = Gate.hash(token);
                long ttl = req.has("ttl") ? req.lng("ttl") : 24 * 3600;
                rec.gateExpiresAt = ttl <= 0 ? 0 : System.currentTimeMillis() + ttl * 1000;
                state.save();
                reply.done(JsonObject.builder().put("ok", true).put("gate", true).put("visitUrl", visitUrl(rec, token))
                    .put("expiresAt", rec.gateExpiresAt));
            }
            case "ls" -> reply.done(JsonObject.builder().put("ok", true).put("links", linkRows()));
            case "close" -> {
                String name = req.string("name");
                NodeState.LinkRec rec = state.linkByName(name);
                if (rec == null) {
                    reply.error("no link named " + name);
                    return;
                }
                if (isOpen(rec)) {
                    link.send(new Message.LinkClose(rec.linkId));
                }
                for (HubLink rl : relays.values()) {
                    String id = rec.relayLinkIds.get(rl.relayAddress());
                    if (id != null && rl.isConnected()) {
                        try {
                            rl.send(new Message.LinkClose(id));
                        } catch (IOException e) {
                            LOG.debug("close on relay {}: {}", rl.relayAddress(), e.getMessage());
                        }
                    }
                }
                state.links.remove(rec);
                state.save();
                reply.ok();
            }
            case "netcheck" -> {
                long t = System.nanoTime();
                Message r = link.request(new Message.Ping(t), "Pong", REPLY_TIMEOUT_MS);
                if (r instanceof Message.Pong) {
                    reply.done(JsonObject.builder().put("ok", true).put("rttMicros", (System.nanoTime() - t) / 1000));
                } else {
                    reply.error("no pong");
                }
            }
            case "leave" -> {
                link.close();
                state.registered = false;
                state.nodeId = 0;
                state.user = null;
                state.hubHost = null;
                state.hubKey = null;
                state.nextHubKey = null;
                state.links.clear();
                state.save();
                reply.ok();
            }
            case "shutdown" -> {
                reply.ok();
                Thread.ofVirtual().start(() -> {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException _) {
                        // exiting
                    }
                    System.exit(0);
                });
            }
            default -> reply.error("unknown command " + req.string("cmd"));
        }
    }

    /**
     * Whether the hub is routing this link here right now: it has an id on the current session,
     * and there is a current session. The one definition, so that {@code status}, {@code close}
     * and the self-probe cannot disagree about the same record.
     */
    private boolean isOpen(NodeState.LinkRec rec) {
        return rec.linkId != null && link.isConnected();
    }

    /**
     * Whether this node is serving {@code rec} right now: through the hub it is joined to, or
     * through any relay host whose connection is up (§13.4).
     *
     * <p>{@link #isOpen} alone is the wrong question for the self-probe. A relay serves this node's
     * names while the primary is away -- "losing the primary then stops nothing a visitor can see"
     * -- so a name reached over a relay is publicly served and is exactly the kind whose TLS
     * somebody else might be terminating. Answering `link not open` for it would leave the check
     * silent over the window §11.4 says names change hands in, which is the window it exists for.
     */
    private boolean servedHere(NodeState.LinkRec rec) {
        if (isOpen(rec)) {
            return true;
        }
        for (java.util.Map.Entry<String, HubLink> e : relays.entrySet()) {
            if (e.getValue().isConnected() && rec.relayLinkIds.containsKey(e.getKey())) {
                return true;
            }
        }
        return false;
    }

    private List<Object> linkRows() {
        return state.links.stream().<Object>map(l -> JsonObject.builder()
            .put("name", l.name).put("local", l.local())
            .put("url", l.url).put("gate", l.gateHash != null).put("open", isOpen(l))
            .put("probe", l.lastProbe == null ? null : l.lastProbe.json()).build().asMap()).toList();
    }

    /** Names the hub took away, so `status` keeps saying it after the log line has scrolled. */
    private List<Object> revokedRows() {
        return state.revoked.stream().<Object>map(r -> JsonObject.builder()
            .put("name", r.name()).put("reason", r.reason()).put("at", r.at()).build().asMap()).toList();
    }

    /** "count mean/max" in milliseconds, which is how these read next to the hub's own line. */
    private static String millis(MuxSession.Timing t) {
        long n = t.observations();
        double mean = n == 0 ? 0 : t.totalSeconds() * 1000 / n;
        return String.format(java.util.Locale.ROOT, "%d %.1f/%.1f", n, mean, t.maxSeconds() * 1000);
    }

    private JsonObject.Builder status() {
        JsonObject.Builder b = JsonObject.builder().put("ok", true)
            .put("machineKey", state.machineKeyText())
            .put("hub", state.hubHost)
            .put("hubKey", state.hubKey)
            .put("connected", link.isConnected())
            .put("connections", link.connectionCount())
            .put("visitorsInFlight", visitors.inFlight())
            // The ceiling next to the count, and how many it has turned away: in flight on its own
            // cannot say whether a node is busy or full, and those are different problems.
            .put("visitorCeiling", visitors.maxInFlight())
            .put("visitorsRefused", visitors.refused())
            // And how many took a slot without ever speaking (§9.3). A node whose refusals climb
            // while this does too is being held open, not visited, which is a different answer.
            .put("visitorsStalled", visitors.stalled())
            // The multiplexer's own three waits, which `proto` records on both sides and only the
            // hub publishes (ARCHITECTURE.md §14). The node is the busy writer in the saturation
            // case -- the bulk travels node to hub -- so these are the numbers that say whether a
            // visitor's handshake is waiting on this node's writer or on something after it.
            .put("muxQueueWaitMs", millis(MuxSession.QUEUE_WAIT))
            .put("muxSocketWriteMs", millis(MuxSession.SOCKET_WRITE))
            .put("muxOpenDispatchMs", millis(MuxSession.OPEN_DISPATCH))
            .put("draining", link.drainingCount())
            .put("relays", relayRows())
            .put("drainingDetail", link.drainingDetail())
            .put("registered", state.registered)
            .put("nodeId", state.nodeId > 0 ? Long.valueOf(state.nodeId) : null)
            .put("user", state.user)
            .put("dnsSuffix", state.dnsSuffix)
            .put("links", linkRows())
            .put("revoked", revokedRows())
            .put("lastError", link.lastError())
            .put("update", lastUpdate == null ? null : lastUpdate.json().build());
        Message.RegisterResponse r = link.lastRegister();
        if (r != null) {
            b.put("registration", r.status());
        }
        return b;
    }

    /**
     * Daily: ask whether a newer jailscale has been published and keep the answer for {@code status}
     * (ARCHITECTURE.md §9.4). The first check waits a random few minutes so that a fleet started
     * together does not arrive in one burst, and a failure is kept rather than logged every day --
     * a node with no way out to the internet should not fill its log saying so.
     */
    private void updateLoop() {
        try {
            Thread.sleep(ThreadLocalRandom.current().nextLong(60_000, 300_000));
            while (!closed) {
                Updates.Result r = Updates.check(Version.string());
                if (r.newer()) {
                    LOG.info("{}", r.line());
                }
                // Nothing else is said: a node with no route to the internet and a `dev` build are
                // both conditions that would otherwise fill this log with the same line every day
                // for ever. `status` carries the reason for whoever asks.
                lastUpdate = r;
                Thread.sleep(UPDATE_CHECK_MS);
            }
        } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
        }
    }


    private static String days(long millis) {
        long d = millis / 86400_000L;
        if (d >= 2) {
            return d + " days";
        }
        long h = Math.max(1, millis / 3600_000L);
        return h == 1 ? "an hour" : h + " hours";
    }

    /** {@code jailscale open <port>}: ask the hub for a name and remember the link. */
    private void open(JsonObject req, Ipc.Reply reply) throws Exception {
        if (!state.registered) {
            reply.error("not joined to a hub yet; run 'jailscale up' first");
            return;
        }
        if (!link.isConnected()) {
            reply.error(link.lastError() != null ? "not connected: " + link.lastError() : "not connected to the hub");
            return;
        }
        int port = req.integer("port");
        String host = req.optString("host", "127.0.0.1");
        String name = req.optString("name", null);
        NodeState.LinkRec rec = null;
        for (NodeState.LinkRec l : state.links) {
            if (l.host.equals(host) && l.port == port && (name == null || name.equals(l.name))) {
                rec = l;
            }
        }
        // Opening a name deliberately answers the warning about it, so stop repeating it.
        if (name != null) {
            state.revoked.removeIf(r -> r.name().equals(name) || r.name().equals(name + "." + state.dnsSuffix));
        }
        boolean fresh = rec == null;
        if (fresh) {
            rec = new NodeState.LinkRec(host, port, name);
        } else if (name != null) {
            rec.name = name;
        }
        if (req.has("proxyProtocol")) {
            rec.proxyProtocol = req.optBool("proxyProtocol", false);
        }
        Message.LinkOpened lo;
        try {
            lo = reopen(rec);
        } catch (IOException e) {
            reply.error(e.getMessage());
            return;
        }
        if (fresh) {
            state.links.add(rec);
        }
        wakeProbe();
        String visitUrl = null;
        if (req.optBool("gate", false)) {
            String token = Gate.newToken();
            rec.gateHash = Gate.hash(token);
            rec.gateExpiresAt = System.currentTimeMillis() + 24 * 3600 * 1000L;
            visitUrl = visitUrl(rec, token);
        }
        state.save();
        reply.done(JsonObject.builder().put("ok", true).put("name", lo.name()).put("url", lo.url()).put("local", rec.local())
            .put("visitUrl", visitUrl)
            .put("certExpiresAt", rec.certExpiresAt > 0 ? Long.valueOf(rec.certExpiresAt) : null));
    }

    /**
     * ARCHITECTURE.md §11.3: connect to each open name as an ordinary visitor and check that the TLS
     * was terminated here. The keying material of a TLS 1.3 session is derivable by its two ends
     * and nobody else, so a value this node never recorded means something in between -- a hub
     * holding the wildcard key can be that something. The §11.1 signing conditions do not help:
     * the hub enforces those, so they bind nodes, not the hub.
     */
    private void verify(Ipc.Reply reply) throws IOException {
        List<Object> rows = new ArrayList<>();
        boolean allOk = true;
        int probed = 0;
        SSLContext ctx = probeContext();
        for (NodeState.LinkRec rec : state.links) {
            ProbeResult p = probe(rec, ctx);
            if (p == null) {
                continue; // raw ports carry no TLS of ours to compare
            }
            // A name that is not open here is reported and not counted: nothing was probed, so it
            // is neither a pass nor a failure, and the exit status is what an operator scripting
            // §11.3 reads as "the hub is terminating my TLS". It is left out of `checked` for the
            // same reason -- `checked >= 1 && allOk` is the shape a monitor is written in, and a
            // count that included the unprobed rows would answer it with "all clear" on a node that
            // verified nothing at all.
            if (p.checked()) {
                allOk &= p.ok();
                probed++;
            }
            rows.add(p.json().asMap());
        }
        // `ok` is whether the command ran; what each name concluded is its row. Folding the
        // verdicts into `ok` made the CLI print `error: failed` and drop the rows, so the one
        // answer this section sends operators to never reached them (§11.3).
        reply.done(JsonObject.builder().put("ok", true).put("allOk", allOk).put("checked", probed).put("results", rows));
    }

    /**
     * The client context every probe of one pass can share: the CA file read and the trust store
     * built once rather than once per name. Null when it cannot be built, in which case each probe
     * tries for itself and its verdict says why.
     */
    private SSLContext probeContext() {
        try {
            return HubClient.clientContext(state);
        } catch (IOException | GeneralSecurityException _) {
            return null;
        }
    }

    /**
     * What a row of {@code verify} calls a link: the name out of its URL, and the URL itself when
     * that will not parse. Every row in one answer has to be labelled the same way whatever its
     * verdict, or a reader correlating them by name matches some links and not others.
     */
    private static String probeLabel(NodeState.LinkRec rec) {
        try {
            String host = URI.create(rec.url).getHost();
            return host != null ? host : rec.url;
        } catch (RuntimeException _) {
            return rec.url;
        }
    }

    /**
     * Probes one link, or null when it carries no TLS this node terminates. Records the result on
     * the link for {@code status} and shouts on the one verdict that means something is wrong, so
     * a probe from the loop below is as loud as one the operator asked for.
     *
     * <p>Nothing in here throws. The URL is the hub's word (§11.2), so parsing it is inside the
     * same net as connecting to it: a hub that sends a name Java's {@code URI} will not parse must
     * get a verdict saying so, not end the loop that exists to catch a dishonest hub.
     *
     * <p>A link the hub is not routing here is answered before any of that, because every verdict
     * below is about who terminated the TLS and none of them would be true of it. The hub answers a
     * name it does not route here with its own page under the wildcard certificate, and a node that
     * took the name terminates its own TLS, so probing either would read as an interception. That
     * is reachable without anything going wrong: `jailscale down` and then `jailscale verify`, or a
     * reopen that timed out while the hub was restarting. The check sits here rather than in the
     * loop so that the command §11.3 sends operators to is covered by it too -- a false report of
     * a compromised hub is the worst thing this feature can do.
     */
    private ProbeResult probe(NodeState.LinkRec rec, SSLContext shared) {
        if (rec.url == null) {
            return null;
        }
        if (!state.links.contains(rec) || !servedHere(rec)) {
            // Closed or revoked (§11.4), or not open on this hub session -- the same test `status`
            // makes, plus whether the record is still in the list, which `status` only iterates.
            // The verdict does not go on the record: `status` keeps the last real one beside
            // `open: false` rather than losing it, and the name still counts as never probed if
            // it never was.
            return new ProbeResult(probeLabel(rec), false, ProbeResult.NOT_OPEN, System.currentTimeMillis());
        }
        String host = rec.url;
        String verdict;
        boolean ok = false;
        try {
            URI u = URI.create(rec.url);
            if (u.getHost() == null) {
                throw new IllegalArgumentException("no host in " + rec.url);
            }
            host = u.getHost();
            int port = u.getPort() > 0 ? u.getPort() : 443;
            SSLContext ctx = shared != null ? shared : HubClient.clientContext(state);
            try (SSLSocket s = Tls.connect(ctx, host, state.hubAddr, port, !state.tlsInsecure, VERIFY_TIMEOUT_MS)) {
                Http.writeRequest(s.getOutputStream(), "GET", host, "/", null, null);
                // Headers only. The node records the exporter on the first application byte of
                // the request (Visitors), so once a status line is back the comparison is ready,
                // and the local app's page -- whatever its size -- is not what is being checked.
                Http.readResponse(s.getInputStream(), 1 << 16, true);
                String material = SelfProbe.material(s.getSession());
                ok = visitors.probe().terminatedHere(material);
                verdict = material == null ? "keying material unavailable (needs TLS 1.3)"
                    : ok ? "terminated by this node" : "TERMINATED ELSEWHERE";
            }
        } catch (IOException | GeneralSecurityException | io.jailscale.proto.http.HttpException | RuntimeException e) {
            verdict = "unreachable: " + e.getMessage();
        }
        if (verdict.startsWith("TERMINATED")) {
            visitors.probe().warn(host);
        }
        ProbeResult p = new ProbeResult(host, ok, verdict, System.currentTimeMillis());
        rec.lastProbe = p;
        return p;
    }

    /**
     * ARCHITECTURE.md §11.3: run the self-probe without being asked, so an interception is found
     * rather than waited for. **One name per tick, and the tick is what a pass costs divided by the
     * number of names**, so every name is looked at once every {@code PROBE_PASS_MS} whether this
     * node holds one or twenty. That is the number worth holding still: an interception lasts until
     * the name's next turn, so the pass is the detection bound and the tick is only how it is paid
     * for.
     *
     * <p>No switch to turn it off, deliberately. The traffic goes to this node's own public name
     * through its own hub and reaches no third party, so there is nothing here for an operator to
     * opt out of.
     */
    private void probeLoop() {
        Set<NodeState.LinkRec> pass = new HashSet<>();
        try {
            while (!closed) {
                boolean sweep = awaitProbeTick();
                if (closed || !link.isConnected()) {
                    continue;
                }
                List<NodeState.LinkRec> links = new ArrayList<>(state.links);
                if (sweep) {
                    sweepProbe(links, pass);
                    continue;
                }
                NodeState.LinkRec rec = dueProbe(links, pass);
                if (rec != null) {
                    probeSafely(rec, null);
                }
            }
        } catch (InterruptedException _) {
            // exiting
        }
    }

    /**
     * Waits out one tick, or less when a hub connection comes up and a sweep is allowed. True when
     * this tick is that sweep.
     *
     * <p>An ask that arrives inside a pass of the last sweep is dropped rather than queued, and the
     * ordinary ticks carry on underneath it: a node whose link flaps every minute would otherwise
     * turn every flap into a full pass, which is the one way this could become traffic worth
     * noticing. What it is held to instead is a doubling of the steady rate, at worst.
     *
     * <p>The deadline is {@link System#nanoTime}, not the wall clock. The remaining wait is worked
     * out again after every wakeup, so a clock stepped backwards -- NTP correcting a fast RTC, a VM
     * resuming -- would otherwise push the next look at a name out by the size of the step, and the
     * bound this loop exists to hold would be gone without anything saying so.
     *
     * <p>The tick itself is sized again on every wakeup too, from the names held now. {@code open}
     * wakes this ({@link #wakeProbe}), so a name opened one minute into a half-hour tick shortens
     * the tick in flight to what the new count calls for rather than waiting out the old one --
     * without that, nineteen names opened behind a single one would sit unprobed for the rest of
     * the half hour, which is the bound this loop exists to hold, spent before the first look.
     */
    private boolean awaitProbeTick() throws InterruptedException {
        long since = System.nanoTime();
        long deadline = since;
        synchronized (probeWake) {
            namesChanged = true; // the first deadline is sized here too
            while (!closed) {
                if (sweepAsked) {
                    sweepAsked = false;
                    if (System.nanoTime() - lastSweepNanos >= PROBE_PASS_MS * 1_000_000L) {
                        return true;
                    }
                }
                if (namesChanged) {
                    namesChanged = false;
                    deadline = since + jitter(probeTick(probableNames(state.links))) * 1_000_000L;
                }
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    return false;
                }
                probeWake.wait(Math.max(1, left / 1_000_000L));
            }
        }
        return false;
    }

    /**
     * One pass in one go: every name this node holds, checked now. That is at most 20 requests
     * (the link ceiling) and it is spent on the case the schedule is worst at -- a node that has
     * just been away, which is exactly when a name changes hands.
     *
     * <p>It counts as the pass, so the names it covers are marked and the loop carries on into the
     * next one rather than going round again. If the link goes down mid-sweep the rest are left
     * unmarked, so the ordinary ticks pick them up instead of the sweep pretending to have.
     *
     * <p>Nothing is spent until it is about to probe: a sweep that turns back -- no names to look
     * at, or the link gone again -- neither takes the pass in flight down with it nor holds the
     * next sweep off for a pass. Both would cost the thing this exists to shorten. A node whose
     * link blips mid-pass would lose the turns already taken and start over, so the names still
     * waiting would wait nearly two passes rather than the one PROBE_PASS_MS bounds; and a sweep
     * that made no requests at all has nothing to answer the cooldown for.
     */
    private void sweepProbe(List<NodeState.LinkRec> links, Set<NodeState.LinkRec> pass) throws InterruptedException {
        List<NodeState.LinkRec> all = remaining(links, Set.of());
        if (all.isEmpty()) {
            return;
        }
        // A hub restart brings every node back at the same second; this is what keeps the sweeps
        // that follow from arriving as one burst of signing requests on the hub that just came up.
        awaitSpread(ThreadLocalRandom.current().nextLong(SWEEP_SPREAD_MS));
        if (closed || !link.isConnected()) {
            return;
        }
        lastSweepNanos = System.nanoTime();
        pass.clear();
        SSLContext ctx = probeContext();
        for (NodeState.LinkRec rec : all) {
            ProbeResult p = probeSafely(rec, ctx);
            pass.add(rec);
            if (closed || !link.isConnected()) {
                break;
            }
            if (p != null && p.verdict().startsWith("unreachable")) {
                // Every name is reached through the same hub address, so a path that swallowed
                // this probe swallows the next nineteen too, at VERIFY_TIMEOUT_MS each: a hub
                // whose control port is open but whose visitor port is not yet. The rest are left
                // unmarked for the ordinary ticks, which pay for one name at a time.
                LOG.debug("self-probe: sweep stopped at {} ({}); the ordinary ticks take the rest", rec.name, p.verdict());
                break;
            }
        }
        LOG.debug("self-probe: {} of {} name(s) checked on the hub link coming up", pass.size(), all.size());
    }

    /**
     * Waits out the spread on the probe's own monitor rather than in {@link Thread#sleep}, so that
     * {@link #close} -- which notifies that monitor for exactly this reason -- is noticed here as
     * well and not only between ticks.
     */
    private void awaitSpread(long ms) throws InterruptedException {
        long deadline = System.nanoTime() + ms * 1_000_000L;
        synchronized (probeWake) {
            for (long left = deadline - System.nanoTime(); !closed && left > 0; left = deadline - System.nanoTime()) {
                probeWake.wait(Math.max(1, left / 1_000_000L));
            }
        }
    }

    private ProbeResult probeSafely(NodeState.LinkRec rec, SSLContext ctx) {
        try {
            return probe(rec, ctx);
        } catch (RuntimeException e) {
            // probe() is written not to throw; if it ever does, one bad tick must not be the
            // last one. Say so, at the volume of a thing that should not happen.
            LOG.error("self-probe of {} failed unexpectedly: {}", rec.name, e.toString());
            return null;
        }
    }

    /**
     * The link to probe on this tick, or null when this node holds no name to probe. {@code pass}
     * is the turn-taking: the names already looked at in the current pass, carried across ticks and
     * cleared here once every name has had its turn, which is what makes a pass a pass.
     *
     * <p>It is a set of the link records themselves rather than a position, because a position is a
     * claim about a list that does not hold still. Links are opened and closed while a pass runs,
     * and an index into yesterday's list points at a different name in today's: closing one link
     * used to shift every later name up a place, which skips the one that moved past the cursor --
     * for a whole pass, silently, in the loop whose entire purpose is that no name goes
     * unlooked-at for long. Holding the records makes every case right by construction: a link that
     * goes away takes its turn with it, one that appears is due, and a name closed and opened again
     * -- which §11.4 says is the answer to a revocation warning -- is due as well, because it is a
     * new record. Keyed by name it would have inherited the turn the old one took, and `status`
     * would sit blank for the one name the operator is watching until the pass ended.
     *
     * <p>A name with no verdict at all goes first. It is the one nothing is known about, and until
     * its first probe the reassurance in {@code status} is an empty field rather than an answer.
     * So does a name whose verdict is older than a pass, in list order, and that is what keeps the
     * first rule honest: on its own it lets a steady stream of new names -- one opened per tick --
     * take every tick from the names already waiting, and the bound this loop exists for would be
     * broken by nothing more than churn. A name overdue by that measure is one the bound has
     * already failed, and it goes before anything newer. That one comparison is on the wall
     * clock, because {@code lastProbe.at} is; a stepped clock reorders a tick, it does not
     * lengthen one.
     *
     * <p>Links that have gone are dropped from {@code pass} on the way in, or a pass that churn
     * never lets finish would keep every record it ever saw.
     *
     * <p>Separate from the probing so that the turn-taking can be checked without opening a socket.
     */
    static NodeState.LinkRec dueProbe(List<NodeState.LinkRec> links, Set<NodeState.LinkRec> pass) {
        pass.retainAll(new HashSet<>(links));
        List<NodeState.LinkRec> due = remaining(links, pass);
        if (due.isEmpty()) {
            pass.clear();
            due = remaining(links, pass);
        }
        if (due.isEmpty()) {
            return null;
        }
        NodeState.LinkRec pick = due.get(0);
        long overdue = System.currentTimeMillis() - PROBE_PASS_MS;
        for (NodeState.LinkRec rec : due) {
            ProbeResult last = rec.lastProbe;
            if (last == null || last.at() < overdue) {
                pick = rec;
                break;
            }
        }
        pass.add(pick);
        return pick;
    }

    /**
     * How long to wait before looking at the next name, so that a pass over all of them takes
     * {@code PROBE_PASS_MS} whatever the number of names: half an hour at one name, ninety seconds
     * at the 20-link ceiling.
     *
     * <p>This is the other way round from where this started, on purpose. Holding the tick at half
     * an hour and letting the pass stretch to ten hours fixes the quantity that costs nothing and
     * lets the one carrying the whole point of the feature float: a name taken over just after its
     * turn keeps until its next one, so the pass **is** the detection bound. What the swap costs is
     * that probe traffic now grows with the number of names, which is what the fixed tick was
     * refusing -- but it grows to a ceiling, because 20 links is one: 20 requests a pass, so 40 an
     * hour, and 80 in the hour where a link comes back every half hour and each return pays for a
     * sweep as well. All of it to its own names, through its own hub, and a node holding 20 public
     * names is carrying more visitor traffic than that by a wide margin.
     *
     * <p>The floor is not reachable at that ceiling; it is there so that raising the ceiling cannot
     * turn this into a request a second by arithmetic nobody looked at again.
     */
    static long probeTick(int names) {
        return Math.max(PROBE_MIN_TICK_MS, PROBE_PASS_MS / Math.max(1, names));
    }

    /**
     * A tick with up to a fifth taken off it, never added, so that the moment a name is looked at is
     * not one anybody can name in advance and a pass still finishes inside its target.
     *
     * <p>The order names are taken in is deliberately *not* shuffled with it. Random order would
     * make a name's position in the pass unpredictable too, at the price of doubling the worst gap
     * between two looks at the same name -- last in one pass, first in the next is one pass, but
     * first and then last is nearly two -- and the attacker it would buy anything against is one
     * timing an interception around the schedule, who has a far easier way out already: the probe
     * leaves this node's address, so a hub that routes those connections honestly and nobody else's
     * is not caught by any order or any interval (§15). Trading a bound that holds against the
     * careless hub for unpredictability against the careful one, when the careful one is not caught
     * either way, is the wrong side of that trade.
     */
    static long jitter(long tickMs) {
        return tickMs - ThreadLocalRandom.current().nextLong(tickMs / 5 + 1);
    }

    /** How many names a pass has to cover. */
    static int probableNames(List<NodeState.LinkRec> links) {
        return remaining(new ArrayList<>(links), Set.of()).size();
    }

    /** The links carrying TLS this node terminates that have not had their turn in {@code pass}. */
    private static List<NodeState.LinkRec> remaining(List<NodeState.LinkRec> links, Set<NodeState.LinkRec> pass) {
        List<NodeState.LinkRec> due = new ArrayList<>();
        for (NodeState.LinkRec rec : links) {
            // A link the hub has not answered for yet has no URL to connect to, so it is not a
            // name this can say anything about.
            if (rec.url == null || rec.name == null) {
                continue;
            }
            if (!pass.contains(rec)) {
                due.add(rec);
            }
        }
        return due;
    }

    private static String visitUrl(NodeState.LinkRec rec, String token) {
        return rec.url + "/?" + Gate.COOKIE + "=" + token;
    }

    /**
     * {@code jailscale up}: pin the hub key (fetching it unless given), connect, register with
     * the supplied credential, and stream progress until approved, pending or rejected.
     */
    private void up(JsonObject req, Ipc.Reply reply) throws Exception {
        String invite = req.optString("invite", null);
        String host = req.optString("hub", null);
        int port = req.optInt("port", 443);
        if (invite != null) {
            URI u = URI.create(invite);
            if (u.getHost() == null || !u.getPath().startsWith("/join/")) {
                reply.error("invite must look like https://hub/join/<token>");
                return;
            }
            host = u.getHost();
            port = u.getPort() > 0 ? u.getPort() : 443;
            invite = u.getPath().substring("/join/".length());
        }
        if (host == null) {
            if (!state.hasHub()) {
                reply.error("no hub configured; use --invite <link> or --hub <host>");
                return;
            }
            host = state.hubHost;
            port = state.hubPort;
        }
        String addr = req.optString("addr", null);
        String hubKey = req.optString("hubKey", null);
        boolean insecure = req.optBool("tlsInsecure", false);
        String caFile = req.optString("caFile", null);
        if (insecure && hubKey == null) {
            reply.error("--tls-insecure requires --hub-key");
            return;
        }
        if (hubKey != null) {
            KeyText.parse(KeyText.HUB, hubKey);
        }
        boolean hubChanged = !host.equals(state.hubHost) || port != state.hubPort;
        if (hubChanged && state.registered) {
            reply.error("already joined " + state.hubHost + "; run 'jailscale leave' first");
            return;
        }
        state.hubHost = host;
        state.hubAddr = addr;
        state.hubPort = port;
        if (req.has("connections")) {
            state.connections = Math.max(1, Math.min(4, req.integer("connections")));
        }
        state.caFile = caFile;
        state.tlsInsecure = insecure;
        if (hubKey != null) {
            state.hubKey = hubKey;
            state.nextHubKey = null;
        } else if (state.hubKey == null || hubChanged) {
            reply.progress("fetching hub key from https://" + host + (port == 443 ? "" : ":" + port) + "/v1/key");
            SSLContext ctx;
            try {
                ctx = Tls.clientContext(caFile == null ? null : Path.of(caFile), false);
            } catch (GeneralSecurityException e) {
                reply.error("TLS setup: " + e.getMessage());
                return;
            }
            HubClient.HubKeyInfo info = HubClient.fetchHubKey(host, addr, port, ctx, true);
            state.hubKey = info.hubKey();
            state.nextHubKey = info.nextHubKey();
            reply.progress("pinned hub key " + info.hubKey());
        }
        state.save();
        reply.progress("joining " + host + " as " + state.machineKeyText());

        HubLink.Credentials creds = new HubLink.Credentials(invite, req.optString("code", null),
            req.optString("user", null));
        link.start(creds);
        if (state.registered) {
            waitConnected();
            reply.done(JsonObject.builder().put("ok", true).put("status", "connected").put("nodeId", state.nodeId).put("user", state.user));
            return;
        }
        Message.RegisterResponse r = link.awaitRegistration(REGISTER_TIMEOUT_MS);
        if (r == null) {
            reply.error(link.lastError() != null ? link.lastError() : "no answer from hub within " + REGISTER_TIMEOUT_MS / 1000 + "s");
            return;
        }
        switch (r.status()) {
            case Message.RegisterResponse.APPROVED -> reply.done(JsonObject.builder().put("ok", true).put("status", "approved")
                .put("nodeId", r.nodeId()).put("user", r.user()));
            case Message.RegisterResponse.PENDING -> reply.done(JsonObject.builder().put("ok", true).put("status", "pending")
                .put("machineKey", state.machineKeyText()));
            default -> reply.error(HubLink.rejectionText(r.reason()));
        }
    }

    private void waitConnected() throws IOException, InterruptedException {
        long deadline = System.currentTimeMillis() + 15_000;
        while (!link.isConnected() && System.currentTimeMillis() < deadline) {
            if (link.lastError() != null && link.lastError().startsWith("hub key mismatch")) {
                throw new IOException(link.lastError());
            }
            Thread.sleep(50);
        }
        if (!link.isConnected()) {
            throw new IOException(link.lastError() != null ? link.lastError() : "could not connect");
        }
    }

    /** Test hook: sends any control message and waits for the reply registered under {@code replyKey}. */
    public Message debugRequest(Message m, String replyKey) throws IOException, TimeoutException {
        return link.request(m, replyKey, REPLY_TIMEOUT_MS);
    }

    /** The node's MachineKey text (tests). */
    public String machineKey() {
        return state.machineKeyText();
    }

    /** Test hook: whether the certificate with {@code keyId} has been installed. */
    public boolean hasCert(String keyId) {
        return visitors.hasCert(keyId);
    }

    @Override
    public void close() throws IOException {
        // The flag is set under the self-probe's monitor because that is what the probe thread is
        // waiting on: it would otherwise sleep out the rest of a tick before noticing.
        synchronized (probeWake) {
            closed = true;
            probeWake.notifyAll();
        }
        link.close();
        closeRelays();
        if (ipc != null) {
            ipc.close();
        }
    }

    private void closeRelays() {
        for (HubLink rl : new ArrayList<>(relays.values())) {
            rl.close();
        }
        relays.clear();
    }

    /** Whether the hub this node joined is connected right now (tests; `status` reports it too). */
    public boolean isHubConnected() {
        return link.isConnected();
    }

    /** The relay connections that are up right now, by address (tests). */
    public List<String> connectedRelays() {
        return relays.entrySet().stream().filter(e -> e.getValue().isConnected())
            .map(java.util.Map.Entry::getKey).toList();
    }
}
