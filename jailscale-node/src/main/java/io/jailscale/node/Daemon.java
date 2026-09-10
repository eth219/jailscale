package io.jailscale.node;

import io.jailscale.crypto.KeyText;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import javax.net.ssl.SSLContext;

/** The resident node process: owns the state file, the hub link and the local IPC (DESIGN.md §10.5). */
public final class Daemon implements AutoCloseable, Ipc.Handler {

    private static final Log LOG = Log.get("daemon");
    private static final long REGISTER_TIMEOUT_MS = 30_000;

    private final NodeConfig config;
    private final NodeState state;
    private final HubLink link;
    private Ipc.Server ipc;

    public Daemon(NodeConfig config) throws IOException {
        this.config = config;
        this.state = NodeState.load(config.stateFile());
        this.link = new HubLink(state, Version.string());
    }

    public void start() throws IOException {
        ipc = Ipc.serve(config.socketPath(), this);
        LOG.info("jailscale {} daemon, machine key {}", Version.string(), state.machineKeyText());
        if (state.hasHub()) {
            link.start(null);
        }
    }

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
                    req.has("ttl") ? req.lng("ttl") : 0, req.optBool("self", false)), "InviteCreated", 10_000);
                if (r instanceof Message.InviteCreated ic) {
                    reply.done(JsonObject.builder().put("ok", true).put("url", ic.url()).put("code", ic.code()).put("expiresAt", ic.expiresAt()));
                } else if (r instanceof Message.Error e) {
                    reply.error(e.reason());
                } else {
                    reply.error("unexpected " + r.type());
                }
            }
            case "netcheck" -> {
                long t = System.nanoTime();
                Message r = link.request(new Message.Ping(t), "Pong", 10_000);
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
            .put("lastError", link.lastError());
        Message.RegisterResponse r = link.lastRegister();
        if (r != null) {
            b.put("registration", r.status());
        }
        return b;
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
            HubClient.HubKeyInfo info = HubClient.fetchHubKey(host, port, ctx, true);
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
            waitConnected(reply);
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

    private void waitConnected(Ipc.Reply reply) throws IOException, InterruptedException {
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

    /** Test hook. */
    HubLink link() {
        return link;
    }

    NodeState state() {
        return state;
    }

    @Override
    public void close() throws IOException {
        link.close();
        if (ipc != null) {
            ipc.close();
        }
    }
}
