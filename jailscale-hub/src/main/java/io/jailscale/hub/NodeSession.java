package io.jailscale.hub;

import io.jailscale.crypto.KeyText;
import io.jailscale.crypto.NoiseException;
import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.CodecException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.mux.MuxSession;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.mux.NoiseChannel;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * One node's control connection after the HTTP 101 (DESIGN.md §6, §7, §8, §9.3). The
 * Hello/HelloResponse exchange rides in the Noise handshake payloads; after that a
 * {@link MuxSession} carries stream-0 control messages and visitor streams.
 */
final class NodeSession implements AutoCloseable, MuxSession.Listener {

    private static final Log LOG = Log.get("session");
    static final int MIN_PROTO = 1;
    static final int IDLE_TIMEOUT_MS = 60_000;
    static final int MAX_SIGNATURES_PER_STREAM = 4;
    static final int MAX_SIGNATURES_PER_SECOND = 50;

    /** What the hub remembers about a visitor stream it opened, for the signing checks. */
    record VisitorStream(String linkId, String sni, int signatures) {}

    private final Hub hub;
    private final Socket socket;
    private final String remoteIp;
    private MuxSession mux;
    private String mkey;
    private volatile Store.NodeRec node;
    private volatile boolean closed;
    private final Map<Long, VisitorStream> visitors = new ConcurrentHashMap<>();
    private long signWindowStart;
    private int signWindowCount;

    NodeSession(Hub hub, Socket socket) {
        this.hub = hub;
        this.socket = socket;
        this.remoteIp = socket.getInetAddress().getHostAddress();
    }

    String machineKey() {
        return mkey;
    }

    Store.NodeRec node() {
        return node;
    }

    String remoteIp() {
        return remoteIp;
    }

    /** Runs to completion on the connection's virtual thread. */
    void run(InputStream in, OutputStream out) {
        try {
            socket.setSoTimeout(IDLE_TIMEOUT_MS);
            boolean[] rejected = new boolean[1];
            NoiseChannel ch = NoiseChannel.respond(in, out, hub.keys().responders(), (p1, hs) -> {
                mkey = KeyText.format(KeyText.MACHINE, hs.remoteStatic());
                Message m;
                try {
                    m = Codec.decode(p1);
                } catch (CodecException e) {
                    throw new NoiseException("bad Hello: " + e.getMessage());
                }
                if (!(m instanceof Message.Hello hello)) {
                    throw new NoiseException("first message must be Hello, got " + m.type());
                }
                if (hello.proto() < MIN_PROTO) {
                    rejected[0] = true;
                    return Codec.encode(new Message.Goodbye(Message.Goodbye.UPGRADE_REQUIRED));
                }
                LOG.info("node {} connected from {} (v{}, {})", mkey, remoteIp, hello.version(), hello.os());
                return Codec.encode(new Message.HelloResponse(Message.PROTO, MIN_PROTO, Hub.version(), hub.config().dnsSuffix()));
            });
            if (rejected[0]) {
                return;
            }
            node = hub.store().node(mkey);
            hub.registry().attach(this);
            mux = new MuxSession(ch, true, this);
            if (node != null && hub.tls().isLoaded()) {
                send(hub.tls().certUpdate());
            }
            mux.run();
        } catch (NoiseException e) {
            LOG.warn("handshake with {} failed: {}", remoteIp, e.getMessage());
        } catch (IOException | GeneralSecurityException e) {
            if (!closed) {
                LOG.debug("session {} ended: {}", mkey, e.toString());
            }
        } finally {
            hub.links().sessionEnded(this);
            hub.registry().detach(this);
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
            LOG.info("node {} disconnected{}", mkey, cause == null ? "" : ": " + cause.getMessage());
        }
        close();
    }

    /** Returns false to end the session. */
    private boolean handle(Message m) throws IOException {
        switch (m) {
            case Message.Ping p -> send(new Message.Pong(p.id()));
            case Message.Goodbye g -> {
                LOG.info("node {} said goodbye: {}", mkey, g.reason());
                return false;
            }
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
            case Message.AdminLinkRequest a -> send(new Message.Error(a.type(), "not-implemented"));
            case Message.LinkOpen lo -> send(hub.links().open(this, lo));
            case Message.LinkClose lc -> hub.links().close(this, lc.linkId());
            case Message.SignRequest sr -> send(sign(sr));
            default -> {
                LOG.warn("node {}: unexpected {} from node", mkey, m.type());
                send(new Message.Error(m.type(), "unexpected"));
            }
        }
        return true;
    }

    /** The four conditions of DESIGN.md §9.3, then the signature. */
    private Message sign(Message.SignRequest sr) {
        VisitorStream vs = visitors.get(sr.streamId());
        MuxStream stream = mux.stream(sr.streamId());
        if (vs == null || stream == null) {
            return reject(sr, "not-your-stream");
        }
        Links.Link link = hub.links().byId(vs.linkId());
        if (link == null || link.session() != this || !link.name().equals(hub.links().nameOf(vs.sni()))) {
            return reject(sr, "name-not-yours");
        }
        if (vs.signatures() >= MAX_SIGNATURES_PER_STREAM) {
            return reject(sr, "too-many-signatures");
        }
        synchronized (this) {
            long now = System.currentTimeMillis();
            if (now - signWindowStart >= 1000) {
                signWindowStart = now;
                signWindowCount = 0;
            }
            if (++signWindowCount > MAX_SIGNATURES_PER_SECOND) {
                return reject(sr, "rate-limited");
            }
        }
        visitors.put(sr.streamId(), new VisitorStream(vs.linkId(), vs.sni(), vs.signatures() + 1));
        try {
            byte[] sig = hub.tls().sign(sr.keyId(), sr.digest());
            if (sig == null) {
                return reject(sr, "unknown-key");
            }
            return new Message.SignResponse(sr.streamId(), sig, null);
        } catch (GeneralSecurityException e) {
            return reject(sr, "sign-failed");
        }
    }

    private Message reject(Message.SignRequest sr, String reason) {
        LOG.warn("node {}: signature refused for stream {}: {}", mkey, sr.streamId(), reason);
        return new Message.SignResponse(sr.streamId(), null, reason);
    }

    /** Opens a visitor stream toward this node for {@code link}; the SNI router relays into it. */
    MuxStream openVisitor(Links.Link link, String sni, String visitorAddr, String keyId) throws IOException {
        MuxSession s = mux;
        if (s == null || closed) {
            throw new IOException("node session not ready");
        }
        JsonObject meta = JsonObject.builder().put("linkId", link.linkId()).put("sni", sni)
            .put("visitorAddr", visitorAddr).put("keyId", keyId).build();
        MuxStream stream = s.open(meta, false);
        visitors.put(stream.id(), new VisitorStream(link.linkId(), sni, 0));
        return stream;
    }

    void visitorDone(MuxStream stream) {
        visitors.remove(stream.id());
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

    /** Pushes a certificate change to a registered node. */
    void certChanged() {
        if (node != null) {
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
