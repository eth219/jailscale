package io.jailscale.node;

import io.jailscale.crypto.KeyText;
import io.jailscale.proto.control.Message;
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

/** The resident node process: owns the state file, the hub link, links and the local IPC (DESIGN.md §10). */
public final class Daemon implements AutoCloseable, Ipc.Handler, HubLink.Events {

    private static final Log LOG = Log.get("daemon");
    private static final long REGISTER_TIMEOUT_MS = 30_000;
    private static final long REPLY_TIMEOUT_MS = 10_000;

    private final NodeConfig config;
    private final NodeState state;
    private final HubLink link;
    private final Visitors visitors;
    private Ipc.Server ipc;

    public Daemon(NodeConfig config) throws IOException {
        this.config = config;
        this.state = NodeState.load(config.stateFile());
        this.link = new HubLink(state, Version.string(), this);
        this.visitors = new Visitors(state);
    }

    public void start() throws IOException {
        ipc = Ipc.serve(config.socketPath(), this);
        LOG.info("jailscale {} daemon, machine key {}", Version.string(), state.machineKeyText());
        if (state.hasHub()) {
            link.start(null);
        }
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
    public void onVisitor(HubLink l, MuxStream stream) {
        visitors.serve(l, stream);
    }

    private synchronized Message.LinkOpened reopen(NodeState.LinkRec rec) throws IOException, TimeoutException {
        Message r = link.request(new Message.LinkOpen(rec.kind, rec.name, null, null, rec.local()), "LinkOpened", REPLY_TIMEOUT_MS);
        if (r instanceof Message.LinkOpened lo && lo.reason() == null) {
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
            case "open" -> open(req, reply);
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
                .put("url", l.url).put("open", l.linkId != null && link.isConnected()).build().asMap());
        }
        return rows;
    }

    private JsonObject.Builder status() {
        JsonObject.Builder b = JsonObject.builder().put("ok", true)
            .put("machineKey", state.machineKeyText())
            .put("hub", state.hubHost)
            .put("hubKey", state.hubKey)
            .put("connected", link.isConnected())
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
        String name = req.optString("name", null);
        NodeState.LinkRec rec = null;
        for (NodeState.LinkRec l : state.links) {
            if (l.host.equals(host) && l.port == port && l.kind.equals(kind) && (name == null || name.equals(l.name))) {
                rec = l;
            }
        }
        boolean fresh = rec == null;
        if (fresh) {
            rec = new NodeState.LinkRec(kind, host, port, name);
        } else if (name != null) {
            rec.name = name;
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
        state.save();
        reply.done(JsonObject.builder().put("ok", true).put("name", lo.name()).put("url", lo.url()).put("local", rec.local()));
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

    /** Test hook: whether the certificate with {@code keyId} has been installed. */
    public boolean hasCert(String keyId) {
        return visitors.hasCert(keyId);
    }

    @Override
    public void close() throws IOException {
        link.close();
        if (ipc != null) {
            ipc.close();
        }
    }
}
