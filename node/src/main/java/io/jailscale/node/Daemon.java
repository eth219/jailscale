package io.jailscale.node;

import io.jailscale.crypto.KeyText;
import io.jailscale.proto.acme.AcmeException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.tls.DomainProof;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
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
    private static final int VERIFY_TIMEOUT_MS = 10_000;

    private final Visitors visitors;
    private final DomainCerts domainCerts;
    private volatile boolean closed;
    /** The last release check, for {@code status}; null until the first one has run. */
    private volatile Updates.Result lastUpdate;
    static final URI LETS_ENCRYPT = URI.create("https://acme-v02.api.letsencrypt.org/directory");
    static final long RENEW_CHECK_MS = 3600_000;
    static final long UPDATE_CHECK_MS = 24 * 3600_000L;
    static final long PROBE_INTERVAL_MS = 30 * 60_000L;
    /** How close to its end a certificate has to be before anyone is told (ARCHITECTURE.md §15). */
    static final long CERT_WARN_MS = 14 * 86400_000L;
    private static final long CERT_WARN_REPEAT_MS = 86400_000L;
    private Ipc.Server ipc;

    public Daemon(NodeConfig config) throws IOException {
        this.config = config;
        this.state = NodeState.load(config.stateFile());
        this.link = new HubLink(state, Version.string(), this);
        this.visitors = new Visitors(state);
        this.domainCerts = new DomainCerts(config.configDir());
    }

    public void start() throws IOException {
        ipc = Ipc.serve(config.socketPath(), this);
        LOG.info("jailscale {} daemon, machine key {}", Version.string(), state.machineKeyText());
        if (state.hasHub()) {
            link.start(null);
        }
        Thread.ofVirtual().name("domain-renew").start(this::renewLoop);
        Thread.ofVirtual().name("update-check").start(this::updateLoop);
        Thread.ofVirtual().name("self-probe").start(this::probeLoop);
    }

    // --- HubLink.Events --------------------------------------------------------------------------

    @Override
    public void onConnected(HubLink l) {
        for (NodeState.LinkRec rec : state.links) {
            try {
                reopen(rec);
            } catch (IOException | TimeoutException e) {
                LOG.warn("could not reopen link {}: {}", rec.name, e.getMessage());
            }
        }
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
            if (rec.domain != null) {
                visitors.removeDomain(rec.domain);
            }
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

    private synchronized Message.LinkOpened reopen(NodeState.LinkRec rec) throws IOException, TimeoutException {
        DomainCerts.Material material = rec.domain == null ? null : domainMaterial(rec, false);
        List<String> chain = material == null ? null : material.chainPem();
        Message r = link.request(handshakeHash -> {
            byte[] proof = null;
            if (material != null) {
                // The chain says which certificate; the proof says we hold its key. Signed over
                // the handshake hash of the connection the claim goes out on, so it is good for
                // this claim on this connection only.
                try {
                    proof = DomainProof.sign(material.key(), handshakeHash, rec.domain);
                } catch (GeneralSecurityException e) {
                    throw new IOException("cannot prove " + rec.domain + " with its certificate key: " + e.getMessage(), e);
                }
            }
            return new Message.LinkOpen(rec.kind, rec.name, rec.domain, rec.hubPort > 0 ? rec.hubPort : null, rec.local(), chain, proof);
        }, "LinkOpened", REPLY_TIMEOUT_MS);
        if (r instanceof Message.LinkOpened lo && lo.reason() == null) {
            if (lo.hubPort() != null) {
                rec.hubPort = lo.hubPort();
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
                reply.ok();
            }
            case "invite" -> {
                Message r = link.request(new Message.InviteCreate(req.optString("user", null), req.optInt("uses", 0),
                    req.has("ttl") ? req.lng("ttl") : 0, req.optBool("self", false)), "InviteCreated", REPLY_TIMEOUT_MS);
                if (r instanceof Message.InviteCreated ic) {
                    reply.done(JsonObject.builder().put("ok", true).put("url", ic.url()).put("code", ic.code()).put("expiresAt", ic.expiresAt()));
                } else if (r instanceof Message.Error e) {
                    reply.error(e.reason());
                } else {
                    reply.error("unexpected " + r.type());
                }
            }
            case "admin" -> {
                Message r = link.request(new Message.AdminLinkRequest(), "AdminLink", REPLY_TIMEOUT_MS);
                if (r instanceof Message.AdminLink al) {
                    reply.done(JsonObject.builder().put("ok", true).put("url", al.url()).put("expiresAt", al.expiresAt()));
                } else if (r instanceof Message.Error e) {
                    reply.error(e.reason());
                } else {
                    reply.error("unexpected " + r.type());
                }
            }
            case "open" -> open(req, reply);
            case "gate" -> {
                NodeState.LinkRec rec = state.linkByName(req.string("name"));
                if (rec == null) {
                    reply.error("no link named " + req.string("name"));
                    return;
                }
                // The same rule `open --gate` applies (§9.3). Without it this arms a gate on a raw
                // link, saves it, prints a visit link and reports the link as gated, while the raw
                // path serves every visitor without looking at it: a control that is on in the
                // status output and absent on the wire is worse than one that was never offered.
                if (!Message.LinkOpen.HTTPS.equals(rec.kind) && !req.optBool("off", false)) {
                    reply.error("the gate is for https links; raw tcp/udp links have no HTTP to gate");
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
                if (rec.linkId != null && link.isConnected()) {
                    link.send(new Message.LinkClose(rec.linkId));
                }
                if (rec.domain != null) {
                    visitors.removeDomain(rec.domain);
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
                    } catch (InterruptedException ignored) {
                        // exiting
                    }
                    System.exit(0);
                });
            }
            default -> reply.error("unknown command " + req.string("cmd"));
        }
    }

    private List<Object> linkRows() {
        List<Object> rows = new ArrayList<>();
        for (NodeState.LinkRec l : state.links) {
            rows.add(JsonObject.builder().put("name", l.name).put("kind", l.kind).put("local", l.local())
                .put("url", l.url).put("gate", l.gateHash != null).put("open", l.linkId != null && link.isConnected())
                .put("domain", l.domain).put("certExpiresAt", l.certExpiresAt > 0 ? Long.valueOf(l.certExpiresAt) : null)
                .put("probe", l.lastProbe == null ? null : l.lastProbe.json()).build().asMap());
        }
        return rows;
    }

    /** Names the hub took away, so `status` keeps saying it after the log line has scrolled. */
    private List<Object> revokedRows() {
        List<Object> rows = new ArrayList<>();
        for (NodeState.RevokedRec r : state.revoked) {
            rows.add(JsonObject.builder().put("name", r.name()).put("reason", r.reason()).put("at", r.at()).build().asMap());
        }
        return rows;
    }

    private JsonObject.Builder status() {
        JsonObject.Builder b = JsonObject.builder().put("ok", true)
            .put("machineKey", state.machineKeyText())
            .put("hub", state.hubHost)
            .put("hubKey", state.hubKey)
            .put("connected", link.isConnected())
            .put("connections", link.connectionCount())
            .put("draining", link.drainingCount())
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
     * The certificate for a domain link: from disk, or freshly issued when missing, due for
     * renewal, or {@code force}. Installs it for TLS termination either way.
     */
    private DomainCerts.Material domainMaterial(NodeState.LinkRec rec, boolean force) throws IOException {
        DomainCerts.Material m = domainCerts.load(rec.domain);
        if (m == null || force || m.dueForRenewal()) {
            if (!link.isConnected()) {
                throw new IOException("not connected to the hub; cannot run the ACME challenge");
            }
            URI directory = rec.acmeDirectory != null ? URI.create(rec.acmeDirectory) : LETS_ENCRYPT;
            try {
                m = domainCerts.issue(rec.domain, directory, rec.acmeEmail, link);
            } catch (AcmeException | GeneralSecurityException e) {
                throw new IOException("certificate for " + rec.domain + ": " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted");
            }
        }
        try {
            visitors.installDomain(m);
        } catch (GeneralSecurityException e) {
            throw new IOException("cannot use certificate for " + rec.domain + ": " + e.getMessage(), e);
        }
        rec.certExpiresAt = m.notAfter();
        return m;
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
                lastUpdate = r;
                Thread.sleep(UPDATE_CHECK_MS);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

/**
     * Hourly: renew domain certificates that have a third of their lifetime left
     * (ARCHITECTURE.md §8.3), and say so when one is running out anyway.
     *
     * <p>The warning is not conditional on being connected, which is the whole point: renewal needs
     * the hub, so the node that cannot renew is exactly the node nobody is going to hear from. §15
     * called this out as nothing counting down for the operator.
     */
    private void renewLoop() {
        while (!closed) {
            try {
                Thread.sleep(RENEW_CHECK_MS);
            } catch (InterruptedException e) {
                return;
            }
            for (NodeState.LinkRec rec : state.links) {
                if (rec.domain == null) {
                    continue;
                }
                DomainCerts.Material m = domainCerts.load(rec.domain);
                if (m != null) {
                    rec.certExpiresAt = m.notAfter();
                }
                if (link.isConnected() && (m == null || m.dueForRenewal())) {
                    try {
                        LOG.info("renewing certificate for {}", rec.domain);
                        reopen(rec);
                    } catch (IOException | TimeoutException e) {
                        LOG.warn("renewal of {} failed: {}", rec.domain, e.getMessage());
                    }
                }
                warnIfExpiring(rec);
            }
        }
    }

    /** Logs {@link #expiryWarning} at most once a day per name, so a fortnight is not 336 lines. */
    private void warnIfExpiring(NodeState.LinkRec rec) {
        long now = System.currentTimeMillis();
        String w = expiryWarning(rec.domain, rec.certExpiresAt, now);
        if (w == null) {
            rec.certWarnedAt = 0;
            return;
        }
        if (now - rec.certWarnedAt < CERT_WARN_REPEAT_MS) {
            return;
        }
        rec.certWarnedAt = now;
        LOG.warn("{}", w);
    }

    /**
     * What to say about a certificate close to its end, or null while there is nothing to say.
     * Separate from the logging so the wording of the one message an operator may act on can be
     * checked without a clock or a daemon.
     */
    static String expiryWarning(String domain, long expiresAt, long now) {
        if (expiresAt <= 0) {
            return null;
        }
        long left = expiresAt - now;
        if (left > CERT_WARN_MS) {
            return null;
        }
        if (left <= 0) {
            return "the certificate for " + domain + " EXPIRED " + days(-left) + " ago: visitors now see a warning"
                + " instead of your site. Renewal needs this node connected to its hub.";
        }
        return "the certificate for " + domain + " expires in " + days(left) + " and has not renewed."
            + " Renewal needs this node connected to its hub.";
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
        String kind = req.optString("kind", Message.LinkOpen.HTTPS);
        boolean raw = !kind.equals(Message.LinkOpen.HTTPS);
        String domain = raw ? null : req.optString("domain", null);
        if (domain != null) {
            domain = domain.toLowerCase(java.util.Locale.ROOT);
        }
        String name = raw || domain != null ? null : req.optString("name", null);
        if (raw && req.optBool("gate", false)) {
            reply.error("--gate is for https links; raw tcp/udp links have no HTTP to gate");
            return;
        }
        NodeState.LinkRec rec = null;
        for (NodeState.LinkRec l : state.links) {
            if (l.host.equals(host) && l.port == port && l.kind.equals(kind) && (name == null || name.equals(l.name))
                && java.util.Objects.equals(domain, l.domain)) {
                rec = l;
            }
        }
        // Opening a name deliberately answers the warning about it, so stop repeating it.
        if (name != null || domain != null) {
            String wanted = domain != null ? domain : name;
            state.revoked.removeIf(r -> r.name().equals(wanted) || r.name().equals(wanted + "." + state.dnsSuffix));
        }
        boolean fresh = rec == null;
        if (fresh) {
            rec = new NodeState.LinkRec(kind, host, port, name);
            rec.domain = domain;
        } else if (name != null) {
            rec.name = name;
        }
        if (req.has("proxyProtocol")) {
            rec.proxyProtocol = req.optBool("proxyProtocol", false);
        }
        if (domain != null) {
            if (req.has("acmeDirectory")) {
                rec.acmeDirectory = req.string("acmeDirectory");
            }
            if (req.has("acmeEmail")) {
                rec.acmeEmail = req.string("acmeEmail");
            }
        }
        if (raw && req.has("hubPort")) {
            rec.hubPort = req.integer("hubPort");
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
        String visitUrl = null;
        if (req.optBool("gate", false)) {
            String token = Gate.newToken();
            rec.gateHash = Gate.hash(token);
            rec.gateExpiresAt = System.currentTimeMillis() + 24 * 3600 * 1000L;
            visitUrl = visitUrl(rec, token);
        }
        state.save();
        reply.done(JsonObject.builder().put("ok", true).put("name", lo.name()).put("url", lo.url()).put("local", rec.local())
            .put("kind", kind).put("hubPort", lo.hubPort()).put("visitUrl", visitUrl)
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
        for (NodeState.LinkRec rec : state.links) {
            ProbeResult p = probe(rec);
            if (p == null) {
                continue; // raw ports carry no TLS of ours to compare
            }
            allOk &= p.ok();
            rows.add(p.json().asMap());
        }
        reply.done(JsonObject.builder().put("ok", allOk).put("checked", rows.size()).put("results", rows));
    }

    /**
     * Probes one link, or null when it carries no TLS this node terminates. Records the result on
     * the link for {@code status} and shouts on the one verdict that means something is wrong, so
     * a probe from the loop below is as loud as one the operator asked for.
     *
     * <p>Nothing in here throws. The URL is the hub's word (§11.2), so parsing it is inside the
     * same net as connecting to it: a hub that sends a name Java's {@code URI} will not parse must
     * get a verdict saying so, not end the loop that exists to catch a dishonest hub.
     */
    private ProbeResult probe(NodeState.LinkRec rec) {
        if (!Message.LinkOpen.HTTPS.equals(rec.kind) || rec.url == null) {
            return null;
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
            SSLContext ctx = Tls.clientContext(state.caFile == null ? null : Path.of(state.caFile), state.tlsInsecure);
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
     * rather than waited for. **One name per tick, in turn**, which is what makes the interval
     * independent of how many names this node holds: §15 objected that a period has to scale with
     * the number of open names, and it does not if each tick costs one probe regardless. With the
     * default tick a node with one name is checked every half hour and a node at the 20-link
     * ceiling every ten hours, at the same cost to the hub either way.
     *
     * <p>No switch to turn it off, deliberately. The traffic goes to this node's own public name
     * through its own hub and reaches no third party, so there is nothing here for an operator to
     * opt out of.
     */
    private void probeLoop() {
        int next = 0;
        while (!closed) {
            try {
                Thread.sleep(PROBE_INTERVAL_MS);
            } catch (InterruptedException e) {
                return;
            }
            List<NodeState.LinkRec> links = new ArrayList<>(state.links);
            if (!link.isConnected()) {
                continue;
            }
            int i = nextProbeIndex(links, next);
            if (i < 0) {
                continue;
            }
            next = (i + 1) % links.size();
            try {
                probe(links.get(i));
            } catch (RuntimeException e) {
                // probe() is written not to throw; if it ever does, one bad tick must not be the
                // last one. Say so, at the volume of a thing that should not happen.
                LOG.error("self-probe of {} failed unexpectedly: {}", links.get(i).name, e.toString());
            }
        }
    }

    /**
     * The link to probe on this tick: the first one at or after {@code from}, wrapping, that carries
     * TLS this node terminates. -1 when none does, which is a node with only raw ports open.
     * Separate from the probing so that the turn-taking -- the part that keeps the cost of a tick
     * independent of how many names are open -- can be checked without opening a socket.
     */
    static int nextProbeIndex(List<NodeState.LinkRec> links, int from) {
        for (int i = 0; i < links.size(); i++) {
            int at = (from + i) % links.size();
            NodeState.LinkRec rec = links.get(at);
            if (Message.LinkOpen.HTTPS.equals(rec.kind) && rec.url != null) {
                return at;
            }
        }
        return -1;
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
            req.optString("authKey", null), req.optString("user", null));
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
        closed = true;
        link.close();
        if (ipc != null) {
            ipc.close();
        }
    }
}
