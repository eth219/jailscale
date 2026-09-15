package io.jailscale.hub;

import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.CodecException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.mux.MuxSession;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.mux.NoiseChannel;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.function.Consumer;

/**
 * The primary's side of the hub-to-hub channel (ARCHITECTURE.md §13.1): every standby that is
 * connected right now, and what each is sent.
 *
 * <p>A standby is a session like a node's, on the same {@code /v1/noise} upgrade, told apart by the
 * static key it completed Noise IK with -- this hub's own, which only a host given {@code hub.key}
 * can hold. From then on it is fed rather than served: the hub keys, the certificate with its
 * private key, a snapshot of the store, and then every event as it is appended, in order.
 */
final class Peers {

    private static final Log LOG = Log.get("peers");
    /**
     * Events waiting for a standby that is not keeping up. The store appends under its own lock
     * and must not wait on a slow socket, so events are queued and a queue this deep means the
     * peer is not reading; it is dropped and starts over from a fresh snapshot when it returns.
     */
    static final int MAX_QUEUED = 10_000;

    private final Hub hub;
    private final List<Session> sessions = new CopyOnWriteArrayList<>();

    Peers(Hub hub) {
        this.hub = hub;
    }

    List<Session> all() {
        return new ArrayList<>(sessions);
    }

    int count() {
        return sessions.size();
    }

    /** A new certificate: every connected standby gets both halves. */
    void certChanged() {
        for (Session s : sessions) {
            s.sendCert();
        }
    }

    /** The dns-01 values changed: every standby answers the same ones from now on (§13.3). */
    void challengeChanged(List<String> txt) {
        for (Session s : sessions) {
            s.enqueue(new Message.PeerChallenge(txt));
        }
    }

    /** A rotation began or completed: every connected standby gets the private keys. */
    void hubKeyChanged() {
        for (Session s : sessions) {
            s.sendHubKey();
        }
    }

    void closeAll() {
        for (Session s : sessions) {
            s.close();
        }
    }

    /** One connected standby. Runs on the connection's thread, like {@link NodeSession}. */
    final class Session implements MuxSession.Listener, AutoCloseable {

        private final String remoteIp;
        private final String name;
        /** The address the standby advertises for itself (§13.3), or null when it does not know one. */
        private final String address;
        private final LinkedBlockingDeque<Message> queue = new LinkedBlockingDeque<>();
        private final Consumer<JsonObject> listener = ev -> enqueue(new Message.PeerEvent(Json.write(ev.asMap())));
        private final long connectedAt = System.currentTimeMillis();
        private MuxSession mux;
        private volatile boolean closed;
        private final java.util.concurrent.atomic.AtomicLong eventsSent = new java.util.concurrent.atomic.AtomicLong();

        Session(String remoteIp, String peerHost, String address) {
            this.remoteIp = remoteIp;
            this.address = address;
            // A standby normally carries the primary's own name, since that is what it will serve;
            // as a label for "the other host" that says nothing, so the address is used instead.
            this.name = peerHost == null || peerHost.isBlank() || peerHost.equalsIgnoreCase(hub.config().hostname())
                ? remoteIp : peerHost;
        }

        /** What the standby called itself in its hello, or its address when it said nothing. */
        String name() {
            return name;
        }

        String remoteIp() {
            return remoteIp;
        }

        String address() {
            return address;
        }

        long connectedAt() {
            return connectedAt;
        }

        long eventsSent() {
            return eventsSent.get();
        }

        void run(NoiseChannel ch) {
            mux = new MuxSession(ch, true, this, hub.flowBudget());
            sessions.add(this);
            hub.availability().peerUp(name, System.currentTimeMillis());
            LOG.info("standby {} connected from {}", name, remoteIp);
            try {
                // Keys and certificate first, so that a standby which loses the connection right
                // after the snapshot can already sign; then the snapshot, put at the head of the
                // queue so that an event appended between subscribing and here is sent after it.
                sendHubKey();
                sendCert();
                enqueue(new Message.PeerChallenge(hub.dnsTxt()));
                String snapshot = hub.store().subscribe(listener);
                queue.addFirst(new Message.PeerSnapshot(snapshot));
                Thread.ofVirtual().name("peer-writer-" + name).start(this::writeLoop);
                mux.run();
            } finally {
                close();
            }
        }

        private void writeLoop() {
            try {
                while (!closed) {
                    Message m = queue.take();
                    mux.control(Codec.encode(m));
                    if (m instanceof Message.PeerEvent) {
                        eventsSent.incrementAndGet();
                    }
                }
            } catch (InterruptedException ignored) {
                // closing
            } catch (IOException e) {
                if (!closed) {
                    LOG.info("standby {}: write failed: {}", name, e.getMessage());
                }
                close();
            }
        }

        private void enqueue(Message m) {
            if (closed) {
                return;
            }
            if (queue.size() >= MAX_QUEUED) {
                LOG.warn("standby {} is {} events behind and not reading; dropping it to resync", name, queue.size());
                close();
                return;
            }
            queue.add(m);
        }

        void sendCert() {
            if (!hub.tls().isLoaded()) {
                return;
            }
            try {
                enqueue(hub.tls().peerCert());
            } catch (GeneralSecurityException e) {
                LOG.warn("standby {}: could not encode the certificate: {}", name, e.getMessage());
            }
        }

        void sendHubKey() {
            enqueue(new Message.PeerHubKey(hub.keys().privateText(), hub.keys().nextPrivateText()));
        }

        @Override
        public void onControl(MuxSession session, byte[] json) throws IOException {
            Message m;
            try {
                m = Codec.decode(json);
            } catch (CodecException e) {
                throw new IOException("bad control message: " + e.getMessage());
            }
            switch (m) {
                case Message.Ping p -> mux.control(Codec.encode(new Message.Pong(p.id())));
                case Message.Goodbye g -> {
                    LOG.info("standby {} said goodbye: {}", name, g.reason());
                    close();
                }
                case Message.Unknown u -> LOG.info("standby {}: ignoring {}, a message type this hub does not know", name, u.type());
                default -> LOG.warn("standby {}: unexpected {}", name, m.type());
            }
        }

        @Override
        public void onOpen(MuxSession session, MuxStream stream) {
            LOG.warn("standby {} opened stream {}; peers do not open streams", name, stream.id());
            stream.reset(2);
        }

        @Override
        public void onClosed(MuxSession session, Throwable cause) {
            if (!closed) {
                LOG.info("standby {} disconnected{}", name, cause == null ? "" : ": " + cause.getMessage());
            }
            close();
        }

        @Override
        public void close() {
            synchronized (this) {
                if (closed) {
                    return;
                }
                closed = true;
            }
            hub.store().unsubscribe(listener);
            if (sessions.remove(this)) {
                hub.availability().peerDown(name, System.currentTimeMillis());
            }
            if (mux != null) {
                mux.close();
            }
        }
    }
}
