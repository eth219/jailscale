package io.jailscale.hub;

import io.jailscale.crypto.KeyText;
import io.jailscale.crypto.NoiseException;
import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.CodecException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.mux.Frame;
import io.jailscale.proto.mux.MuxException;
import io.jailscale.proto.mux.NoiseChannel;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;

/**
 * One node's control connection after the HTTP 101 (DESIGN.md §6, §7, §8 stream 0). The
 * Hello/HelloResponse exchange rides in the Noise handshake payloads; everything after that
 * is CTRL frames on stream 0 plus KEEPALIVE.
 */
final class NodeSession implements AutoCloseable {

    private static final Log LOG = Log.get("session");
    static final int MIN_PROTO = 1;
    static final int IDLE_TIMEOUT_MS = 60_000;

    private final Hub hub;
    private final Socket socket;
    private final String remoteIp;
    private NoiseChannel ch;
    private String mkey;          // text form, set after the handshake
    private volatile Store.NodeRec node;
    private volatile boolean closed;

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
            ch = NoiseChannel.respond(in, out, hub.keys().responders(), (p1, hs) -> {
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
            loop();
        } catch (SocketTimeoutException e) {
            LOG.info("node {} idle for {} ms, closing", mkey, IDLE_TIMEOUT_MS);
        } catch (NoiseException e) {
            LOG.warn("handshake with {} failed: {}", remoteIp, e.getMessage());
        } catch (IOException | MuxException e) {
            if (!closed) {
                LOG.debug("session {} ended: {}", mkey, e.toString());
            }
        } finally {
            hub.registry().detach(this);
            close();
        }
    }

    private void loop() throws IOException, MuxException {
        while (!closed) {
            Frame f;
            try {
                f = ch.read();
            } catch (NoiseException e) {
                LOG.warn("node {}: undecryptable frame, closing", mkey);
                return;
            }
            if (f == null) {
                LOG.info("node {} disconnected", mkey);
                return;
            }
            switch (f.type()) {
                case Frame.KEEPALIVE -> { }
                case Frame.CTRL -> {
                    if (f.streamId() != Frame.CONTROL_STREAM) {
                        LOG.warn("node {}: CTRL on stream {}", mkey, f.streamId());
                        return;
                    }
                    Message m;
                    try {
                        m = Codec.decode(f.payload());
                    } catch (CodecException e) {
                        LOG.warn("node {}: {}", mkey, e.getMessage());
                        return;
                    }
                    if (!handle(m)) {
                        return;
                    }
                }
                default -> {
                    LOG.warn("node {}: unexpected {} in M1, closing", mkey, Frame.typeName(f.type()));
                    return;
                }
            }
        }
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
            }
            case Message.InviteCreate ic -> send(hub.invites().createForNode(this, ic));
            case Message.AdminLinkRequest a -> send(new Message.Error(a.type(), "not-implemented"));
            default -> {
                LOG.warn("node {}: unexpected {} from node", mkey, m.type());
                send(new Message.Error(m.type(), "unexpected"));
            }
        }
        return true;
    }

    /** Sends a control message; used by the loop and by other threads (admin approval, rotation). */
    void send(Message m) throws IOException {
        try {
            ch.write(Frame.ctrl(Codec.encode(m)));
        } catch (NoiseException e) {
            throw new IOException("encrypt failed", e);
        }
    }

    void sendKeepalive() {
        try {
            ch.write(Frame.keepalive());
        } catch (IOException | NoiseException e) {
            close();
        }
    }

    /** Called when a pending node is approved by an admin. */
    void approved(Store.NodeRec n) {
        node = n;
        try {
            send(Message.RegisterResponse.approved(n.id(), n.user()));
        } catch (IOException e) {
            close();
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
        try {
            socket.close();
        } catch (IOException ignored) {
            // nothing to do
        }
    }
}
