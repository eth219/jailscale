package io.jailscale.node;

import io.jailscale.crypto.KeyText;
import io.jailscale.proto.acme.AcmeException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/** The resident node process: owns the state file, the hub link, links and the local IPC (DESIGN.md §10). */
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
    static final URI LETS_ENCRYPT = URI.create("https://acme-v02.api.letsencrypt.org/directory");
    static final long RENEW_CHECK_MS = 3600_000;
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

    private synchronized Message.LinkOpened reopen(NodeState.LinkRec rec) throws IOException, TimeoutException {
        List<String> chain = null;
        if (rec.domain != null) {
            chain = domainMaterial(rec, false).chainPem();
        }
        Message r = link.request(new Message.LinkOpen(rec.kind, rec.name, rec.domain, rec.hubPort > 0 ? rec.hubPort : null, rec.local(), chain),
            "LinkOpened", REPLY_TIMEOUT_MS);
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
                .put("domain", l.domain).put("certExpiresAt", l.certExpiresAt > 0 ? Long.valueOf(l.certExpiresAt) : null).build().asMap());
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
            .put("lastError", link.lastError());
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

    /** Hourly: renew domain certificates that have a third of their lifetime left (DESIGN.md §9.4). */
    private void renewLoop() {
        while (!closed) {
            try {
                Thread.sleep(RENEW_CHECK_MS);
            } catch (InterruptedException e) {
                return;
            }
            for (NodeState.LinkRec rec : state.links) {
                if (rec.domain == null || !link.isConnected()) {
                    continue;
                }
                DomainCerts.Material m = domainCerts.load(rec.domain);
                if (m == null || m.dueForRenewal()) {
                    try {
                        LOG.info("renewing certificate for {}", rec.domain);
                        reopen(rec);
                    } catch (IOException | TimeoutException e) {
                        LOG.warn("renewal of {} failed: {}", rec.domain, e.getMessage());
                    }
                }
            }
        }
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
     * DESIGN.md §12.3: connect to each open name as an ordinary visitor and check that the TLS
     * was terminated here. The keying material of a TLS 1.3 session is derivable by its two ends
     * and nobody else, so a value this node never recorded means something in between -- a hub
     * holding the wildcard key can be that something. The §12.1 signing conditions do not help:
     * the hub enforces those, so they bind nodes, not the hub.
     */
    private void verify(Ipc.Reply reply) throws IOException {
        List<Object> rows = new ArrayList<>();
        boolean allOk = true;
        for (NodeState.LinkRec rec : state.links) {
            if (!Message.LinkOpen.HTTPS.equals(rec.kind) || rec.url == null) {
                continue; // raw ports carry no TLS of ours to compare
            }
            URI u = URI.create(rec.url);
            String host = u.getHost();
            int port = u.getPort() > 0 ? u.getPort() : 443;
            String verdict;
            boolean ok = false;
            try {
                SSLContext ctx = Tls.clientContext(state.caFile == null ? null : Path.of(state.caFile), state.tlsInsecure);
                try (SSLSocket s = Tls.connect(ctx, host, state.hubAddr, port, !state.tlsInsecure, VERIFY_TIMEOUT_MS)) {
                    Http.writeRequest(s.getOutputStream(), "GET", host, "/", null, null);
                    Http.readResponse(s.getInputStream(), 1 << 16);
                    String material = SelfProbe.material(s.getSession());
                    ok = visitors.probe().terminatedHere(material);
                    verdict = material == null ? "keying material unavailable (needs TLS 1.3)"
                        : ok ? "terminated by this node" : "TERMINATED ELSEWHERE";
                }
            } catch (IOException | GeneralSecurityException | io.jailscale.proto.http.HttpException | RuntimeException e) {
                verdict = "unreachable: " + e.getMessage();
            }
            if (!ok) {
                allOk = false;
                if (verdict.startsWith("TERMINATED")) {
                    visitors.probe().warn(host);
                }
            }
            rows.add(JsonObject.builder().put("name", host).put("ok", ok).put("verdict", verdict).build().asMap());
        }
        reply.done(JsonObject.builder().put("ok", allOk).put("checked", rows.size()).put("results", rows));
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
            default -> reply.error("registration rejected: " + r.reason());
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
