package io.jailscale.node;

import io.jailscale.crypto.NoiseException;
import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.CodecException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.mux.Frame;
import io.jailscale.proto.mux.MuxException;
import io.jailscale.proto.mux.NoiseChannel;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;

/**
 * The node's long-lived control connection (DESIGN.md §6, §7): connect, Hello, register if
 * needed, then serve stream-0 messages; reconnect with backoff when it drops.
 */
final class HubLink implements AutoCloseable {

    private static final Log LOG = Log.get("link");
    private static final int KEEPALIVE_SECONDS = 25;
    private static final long[] BACKOFF_MS = {1000, 2000, 4000, 8000, 16000, 30000};

    /** Credentials for the next RegisterRequest; cleared once registered. */
    record Credentials(String invite, String code, String authKey, String user) {}

    private final NodeState state;
    private final String version;
    private volatile Credentials credentials;
    private volatile boolean running;
    private volatile boolean stopReconnecting;
    private volatile NoiseChannel channel;
    private volatile HubClient.Connected connected;
    private volatile String lastError;
    private volatile Message.RegisterResponse lastRegister;
    private final Map<String, CompletableFuture<Message>> waiting = new ConcurrentHashMap<>();
    private Thread thread;

    HubLink(NodeState state, String version) {
        this.state = state;
        this.version = version;
    }

    synchronized void start(Credentials creds) {
        this.credentials = creds;
        this.stopReconnecting = false;
        if (running) {
            // Restart the connection so the new credentials are used.
            disconnect();
            return;
        }
        running = true;
        thread = Thread.ofVirtual().name("hub-link").start(this::loop);
    }

    boolean isConnected() {
        return channel != null;
    }

    String lastError() {
        return lastError;
    }

    Message.RegisterResponse lastRegister() {
        return lastRegister;
    }

    /** Waits until the pending registration has an outcome, or the timeout passes. */
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
                serve();
            } catch (NoiseException e) {
                lastError = "hub key mismatch: the hub's key is not the pinned one (" + e.getMessage() + ")";
                LOG.error(lastError);
                stopReconnecting = true;
            } catch (IOException | MuxException | RuntimeException e) {
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
        HubClient.Connected c = HubClient.connect(state.hubHost, state.hubPort, ctx, verify, state.machineKey, keys, hello);
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
        channel = c.channel();
        lastError = null;
        LOG.info("connected to {} (hub v{})", state.hubHost, c.hello().version());
        if (!state.registered) {
            Credentials cr = credentials;
            send(new Message.RegisterRequest(hostname(), osName(), cr == null ? null : cr.user(),
                cr == null ? null : cr.invite(), cr == null ? null : cr.code(), cr == null ? null : cr.authKey()));
        }
    }

    private void serve() throws IOException, MuxException {
        NoiseChannel ch = channel;
        Thread ka = Thread.ofVirtual().name("keepalive").start(() -> keepaliveLoop(ch));
        try {
            while (running) {
                Frame f;
                try {
                    f = ch.read();
                } catch (NoiseException e) {
                    throw new IOException("undecryptable frame from hub");
                } catch (SocketTimeoutException e) {
                    throw new IOException("hub idle for " + HubClient.IDLE_TIMEOUT_MS + " ms");
                }
                if (f == null) {
                    throw new IOException("hub closed the connection");
                }
                if (f.type() == Frame.KEEPALIVE) {
                    continue;
                }
                if (f.type() != Frame.CTRL || f.streamId() != Frame.CONTROL_STREAM) {
                    LOG.warn("unexpected {} on stream {}", Frame.typeName(f.type()), f.streamId());
                    continue;
                }
                Message m;
                try {
                    m = Codec.decode(f.payload());
                } catch (CodecException e) {
                    throw new IOException("bad control message: " + e.getMessage());
                }
                if (!handle(m)) {
                    return;
                }
            }
        } finally {
            ka.interrupt();
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
            case Message.Pong p -> complete("Pong", m);
            case Message.InviteCreated ic -> complete("InviteCreated", m);
            case Message.AdminLink al -> complete("AdminLink", m);
            case Message.Error e -> {
                String key = e.inReplyTo() == null ? "" : replyTypeFor(e.inReplyTo());
                if (!complete(key, m)) {
                    LOG.warn("hub error: {}", e.reason());
                }
            }
            case Message.CertUpdate c -> LOG.debug("certificate update ignored in M1");
            default -> LOG.warn("unexpected {} from hub", m.type());
        }
        return true;
    }

    private static String replyTypeFor(String request) {
        return switch (request) {
            case "InviteCreate" -> "InviteCreated";
            case "AdminLinkRequest" -> "AdminLink";
            case "Ping" -> "Pong";
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

    /** Sends a request and waits for the reply of type {@code replyType} (or an Error). */
    Message request(Message m, String replyType, long timeoutMs) throws IOException, TimeoutException {
        NoiseChannel ch = channel;
        if (ch == null) {
            throw new IOException(lastError != null ? "not connected: " + lastError : "not connected");
        }
        CompletableFuture<Message> f = new CompletableFuture<>();
        if (waiting.putIfAbsent(replyType, f) != null) {
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
            waiting.remove(replyType, f);
        }
    }

    void send(Message m) throws IOException {
        NoiseChannel ch = channel;
        if (ch == null) {
            throw new IOException("not connected");
        }
        try {
            ch.write(Frame.ctrl(Codec.encode(m)));
        } catch (NoiseException e) {
            throw new IOException("encrypt failed", e);
        }
    }

    private void keepaliveLoop(NoiseChannel ch) {
        try {
            while (channel == ch) {
                Thread.sleep(KEEPALIVE_SECONDS * 1000L);
                if (channel != ch) {
                    return;
                }
                ch.write(Frame.keepalive());
            }
        } catch (InterruptedException ignored) {
            // connection ended
        } catch (IOException | NoiseException e) {
            disconnect();
        }
    }

    private void disconnect() {
        HubClient.Connected c = connected;
        connected = null;
        channel = null;
        for (CompletableFuture<Message> f : waiting.values()) {
            f.completeExceptionally(new IOException("disconnected"));
        }
        waiting.clear();
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
