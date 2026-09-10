package io.jailscale.node;

import io.jailscale.crypto.NoiseException;
import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.CodecException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.mux.MuxSession;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;

/**
 * The node's long-lived control connection (DESIGN.md §6, §7, §8): connect, Hello, register if
 * needed, then run the multiplexer; reconnect with backoff when it drops.
 */
final class HubLink implements AutoCloseable, MuxSession.Listener {

    private static final Log LOG = Log.get("link");
    private static final long[] BACKOFF_MS = {1000, 2000, 4000, 8000, 16000, 30000};

    /** Credentials for the next RegisterRequest; cleared once registered. */
    record Credentials(String invite, String code, String authKey, String user) {}

    /** What the daemon wants to know. */
    interface Events {
        void onConnected(HubLink link);

        void onCert(Message.CertUpdate cert);

        void onVisitor(HubLink link, MuxStream stream);
    }

    private final NodeState state;
    private final String version;
    private final Events events;
    private volatile Credentials credentials;
    private volatile boolean running;
    private volatile boolean stopReconnecting;
    private volatile MuxSession mux;
    private volatile HubClient.Connected connected;
    private volatile String lastError;
    private volatile Message.RegisterResponse lastRegister;
    private final Map<String, CompletableFuture<Message>> waiting = new ConcurrentHashMap<>();
    private Thread thread;

    HubLink(NodeState state, String version, Events events) {
        this.state = state;
        this.version = version;
        this.events = events;
    }

    synchronized void start(Credentials creds) {
        this.credentials = creds;
        this.stopReconnecting = false;
        if (running) {
            disconnect(); // reconnect with the new credentials
            return;
        }
        running = true;
        thread = Thread.ofVirtual().name("hub-link").start(this::loop);
    }

    boolean isConnected() {
        MuxSession m = mux;
        return m != null && !m.isClosed();
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

    private void loop() {
        int attempt = 0;
        while (running && !stopReconnecting) {
            try {
                connectOnce();
                attempt = 0;
                mux.run(); // returns when the session ends
            } catch (NoiseException e) {
                lastError = "hub key mismatch: the hub's key is not the pinned one (" + e.getMessage() + ")";
                LOG.error(lastError);
                stopReconnecting = true;
            } catch (IOException | RuntimeException e) {
                lastError = e.getMessage() == null ? e.toString() : e.getMessage();
                if (running && !stopReconnecting) {
                    LOG.warn("connection lost: {}", lastError);
                }
            } finally {
                disconnect();
            }
            if (!running || stopReconnecting) {
                break;
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

    private void connectOnce() throws IOException, NoiseException {
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
        Message.Hello hello = new Message.Hello(Message.PROTO, version, osName(), 0);
        HubClient.Connected c = HubClient.connect(state.hubHost, state.hubAddr, state.hubPort, ctx, verify, state.machineKey, keys, hello);
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
        connected = c;
        mux = new MuxSession(c.channel(), false, this);
        lastError = null;
        LOG.info("connected to {} (hub v{})", state.hubHost, c.hello().version());
        if (!state.registered) {
            Credentials cr = credentials;
            send(new Message.RegisterRequest(hostname(), osName(), cr == null ? null : cr.user(),
                cr == null ? null : cr.invite(), cr == null ? null : cr.code(), cr == null ? null : cr.authKey()));
        } else {
            Thread.ofVirtual().name("link-connected").start(() -> events.onConnected(this));
        }
    }

    // --- MuxSession.Listener -----------------------------------------------------------------

    @Override
    public void onControl(MuxSession session, byte[] json) throws IOException {
        Message m;
        try {
            m = Codec.decode(json);
        } catch (CodecException e) {
            throw new IOException("bad control message: " + e.getMessage());
        }
        if (!handle(m)) {
            session.close();
        }
    }

    @Override
    public void onOpen(MuxSession session, MuxStream stream) {
        Thread.ofVirtual().name("visitor-" + stream.id()).start(() -> events.onVisitor(this, stream));
    }

    @Override
    public void onClosed(MuxSession session, Throwable cause) {
        if (cause != null && running) {
            lastError = cause.getMessage();
        }
    }

    private boolean handle(Message m) throws IOException {
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
                        Thread.ofVirtual().name("link-connected").start(() -> events.onConnected(this));
                    }
                    case Message.RegisterResponse.PENDING -> LOG.info("waiting for admin approval");
                    default -> {
                        LOG.error("registration rejected: {}", r.reason());
                        stopReconnecting = true;
                        lastError = "registration rejected: " + r.reason();
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
                lastError = "hub said goodbye: " + g.reason();
                if (g.reason().equals(Message.Goodbye.REVOKED) || g.reason().equals(Message.Goodbye.UPGRADE_REQUIRED)) {
                    stopReconnecting = true;
                    if (g.reason().equals(Message.Goodbye.REVOKED)) {
                        state.registered = false;
                        state.save();
                    }
                }
                return false;
            }
            case Message.CertUpdate c -> events.onCert(c);
            case Message.Pong p -> complete("Pong", m);
            case Message.InviteCreated ic -> complete("InviteCreated", m);
            case Message.AdminLink al -> complete("AdminLink", m);
            case Message.LinkOpened lo -> complete("LinkOpened", m);
            case Message.SignResponse sr -> complete("SignResponse:" + sr.streamId(), m);
            case Message.Error e -> {
                String key = e.inReplyTo() == null ? "" : replyKeyFor(e.inReplyTo());
                if (!complete(key, m)) {
                    LOG.warn("hub error: {}", e.reason());
                }
            }
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

    /** Sends a request and waits for the reply registered under {@code replyKey} (or an Error). */
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

    void send(Message m) throws IOException {
        MuxSession s = mux;
        if (s == null || s.isClosed()) {
            throw new IOException("not connected");
        }
        s.control(Codec.encode(m));
    }

    private void disconnect() {
        MuxSession m = mux;
        HubClient.Connected c = connected;
        mux = null;
        connected = null;
        for (CompletableFuture<Message> f : waiting.values()) {
            f.completeExceptionally(new IOException("disconnected"));
        }
        waiting.clear();
        if (m != null) {
            m.close();
        }
        if (c != null) {
            try {
                c.socket().close();
            } catch (IOException ignored) {
                // closing
            }
        }
    }

    @Override
    public synchronized void close() {
        running = false;
        stopReconnecting = true;
        disconnect();
        if (thread != null) {
            thread.interrupt();
        }
    }

    static String osName() {
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (os.contains("mac")) {
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
