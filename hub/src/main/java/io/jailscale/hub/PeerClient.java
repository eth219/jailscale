package io.jailscale.hub;

import io.jailscale.crypto.NoiseException;
import io.jailscale.crypto.NoiseIk;
import io.jailscale.proto.acme.AcmeKeys;
import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.CodecException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.mux.MuxSession;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.mux.NoiseChannel;
import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

/**
 * A standby's side of the hub-to-hub channel (ARCHITECTURE.md §13.1): dials the primary the way a
 * node does, authenticates with the hub key it was given a copy of, and applies what it is sent
 * -- keys, certificate, a snapshot, then events -- so that its state directory is at every moment
 * one the primary could be replaced with.
 *
 * <p>Reconnects with the node's backoff (1, 2, 4, 8, 16, 30 s). Every reconnect starts from a
 * fresh snapshot rather than resuming a tail: the state is small, and a resumable log would need
 * a position in it that survives the primary compacting the log underneath.
 */
final class PeerClient implements AutoCloseable {

    private static final Log LOG = Log.get("peer");
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    static final int IDLE_TIMEOUT_MS = 60_000;
    private static final int[] BACKOFF_SECONDS = {1, 2, 4, 8, 16, 30};

    private final Hub hub;
    private final URI primary;
    private final Path ca;
    private final String addr;
    private volatile boolean running;
    /** Test hook (§13.5): a partition, made by not dialling. The primary is up; this hub cannot reach it. */
    volatile boolean suspended;
    private volatile boolean connected;
    private volatile boolean synced;
    private volatile String lastError;
    private final java.util.concurrent.atomic.AtomicLong eventsApplied = new java.util.concurrent.atomic.AtomicLong();
    private volatile long lastEventAt;
    /** The address the primary advertises for itself (§13.3), from its hello; null until told. */
    private volatile String primaryAddress;
    /** The nodes attached to the primary, as it last said (§13.4). */
    private volatile java.util.Set<String> primaryNodes = java.util.Set.of();
    /** What a node dials to reach the primary (§13.4), from its hello. */
    private volatile String primaryEndpoint;
    private volatile MuxSession mux;
    private Thread thread;

    PeerClient(Hub hub, URI primary, Path ca, String addr) {
        this.hub = hub;
        this.primary = primary;
        this.ca = ca;
        this.addr = addr;
    }

    String primaryHost() {
        return primary.getHost();
    }

    private int primaryPort() {
        return primary.getPort() > 0 ? primary.getPort() : 443;
    }

    boolean isConnected() {
        return connected;
    }

    /** Whether a snapshot has been applied on the current connection: the store matches the primary's. */
    boolean isSynced() {
        return connected && synced;
    }

    String lastError() {
        return lastError;
    }

    long eventsApplied() {
        return eventsApplied.get();
    }

    long lastEventAt() {
        return lastEventAt;
    }

    /** What the primary said its public address is, or null. */
    String primaryAddress() {
        return primaryAddress;
    }

    java.util.Set<String> primaryNodes() {
        return primaryNodes;
    }

    String primaryEndpoint() {
        return primaryEndpoint != null ? primaryEndpoint : primaryAddress;
    }

    /** Sends {@code m} to the primary, if connected; a standby has one thing to say, which nodes it holds. */
    void send(Message m) {
        MuxSession s = mux;
        if (s != null && !s.isClosed()) {
            try {
                s.control(Codec.encode(m));
            } catch (IOException e) {
                LOG.debug("could not send {} to the primary: {}", m.type(), e.getMessage());
            }
        }
    }

    synchronized void start() {
        if (running) {
            return;
        }
        running = true;
        thread = Thread.ofVirtual().name("peer-client").start(this::loop);
    }

    /** Not an error: a primary looked at its peer and found no primary that outranks it. */
    private static final class PeerIsNotAPrimary extends IOException {
        private static final long serialVersionUID = 1L;
    }

    private void loop() {
        int attempt = 0;
        while (running) {
            try {
                if (suspended) {
                    try {
                        Thread.sleep(200);
                    } catch (InterruptedException _) {
                        return;
                    }
                    continue;
                }
                connectAndRun();
                attempt = 0;
            } catch (PeerIsNotAPrimary _) {
                attempt = BACKOFF_SECONDS.length; // look again at the longest interval
            } catch (IOException | NoiseException | GeneralSecurityException e) {
                lastError = e.getMessage();
                if (running) {
                    LOG.warn("primary {} unreachable: {}", primaryHost(), e.getMessage());
                }
            }
            if (!running) {
                return;
            }
            int wait = BACKOFF_SECONDS[Math.min(attempt, BACKOFF_SECONDS.length - 1)];
            attempt++;
            try {
                Thread.sleep(wait * 1000L);
            } catch (InterruptedException _) {
                return;
            }
        }
    }

    private void connectAndRun() throws IOException, NoiseException, GeneralSecurityException {
        String host = primaryHost();
        SSLContext ctx = Tls.clientContext(ca, false);
        SSLSocket s = Tls.connect(ctx, host, addr, primaryPort(), true, CONNECT_TIMEOUT_MS);
        NoiseChannel ch;
        try {
            Http.writeRequest(s.getOutputStream(), "POST", host, "/v1/noise",
                new Headers().add("Connection", "Upgrade").add("Upgrade", HttpFront.UPGRADE_PROTOCOL), new byte[0]);
            HttpResponse r = Http.readResponse(s.getInputStream(), 4096);
            if (r.status() != 101) {
                throw new IOException("primary refused upgrade: HTTP " + r.status() + " " + r.bodyText().strip());
            }
            // The hub key on both ends of the handshake: this side's static is the copy it was
            // given, and the responder it expects is the same key. Completing IK proves the copy.
            NoiseIk hs = NoiseIk.initiator(HubKeys.PROLOGUE, hub.keys().current(), hub.keys().current().publicKey());
            byte[][] payload2 = new byte[1][];
            Message hello = new Message.PeerHello(Message.PROTO, Hub.version(), hub.config().hostname(), hub.advertisedAddress(),
                hub.relayEndpoint(), hub.role(), hub.epoch());
            ch = NoiseChannel.initiate(s.getInputStream(), s.getOutputStream(), hs, Codec.encode(hello), payload2);
            Message m = Codec.decode(payload2[0]);
            if (m instanceof Message.Goodbye g) {
                ch.close();
                throw new IOException("primary turned us away: " + g.reason() + (g.detail() == null ? "" : " (" + g.detail() + ")"));
            }
            if (!(m instanceof Message.PeerHelloResponse hr)) {
                ch.close();
                throw new IOException("expected PeerHelloResponse, got " + m.type());
            }
            if (hr.address() != null) {
                primaryAddress = hr.address();
            }
            primaryEndpoint = hr.endpoint();
            if (!hub.isStandby()) {
                // A primary dialled its peer (§13.5). It learns one thing: whether the peer is a
                // primary that outranks it. If so it stands down and this client, on its next
                // round, follows; if not there is nothing to be fed, and it looks again later.
                ch.close();
                s.close();
                if (Role.PRIMARY.equals(hr.role()) && hub.roleFile().outrankedBy(hr.epoch(), hr.address(), hub.advertisedAddress())) {
                    hub.demote(hr.epoch(), host);
                    return;
                }
                if (Role.PRIMARY.equals(hr.role())) {
                    LOG.warn("{} is also a primary (epoch {} against our {}); it stands down when it sees us", host, hr.epoch(), hub.epoch());
                }
                throw new PeerIsNotAPrimary();
            }
            if (!Role.PRIMARY.equals(hr.role()) && hr.role() != null) {
                ch.close();
                s.close();
                throw new IOException("the peer is a " + hr.role() + " at epoch " + hr.epoch() + ", not a primary to follow; "
                    + "promote one of the two hubs");
            }
            s.setSoTimeout(IDLE_TIMEOUT_MS);
        } catch (HttpException | CodecException e) {
            s.close();
            throw new IOException("bad response from primary: " + e.getMessage(), e);
        } catch (IOException | NoiseException e) {
            s.close();
            throw e;
        }
        synced = false;
        connected = true;
        lastError = null;
        hub.availability().peerUp(host, System.currentTimeMillis());
        LOG.info("connected to primary {}", host);
        MuxSession session = new MuxSession(ch, false, new Listener(), hub.flowBudget());
        mux = session;
        try {
            // Queued before the session runs: the writer takes it as its first frame after the hello.
            send(new Message.PeerNodes(hub.registry().machineKeys()));
            hub.relaysChanged();
            session.run();
        } finally {
            mux = null;
            connected = false;
            synced = false;
            primaryNodes = java.util.Set.of();
            hub.availability().peerDown(host, System.currentTimeMillis());
            session.close();
            hub.relaysChanged();
        }
    }

    private final class Listener implements MuxSession.Listener {
        @Override
        public void onControl(MuxSession session, byte[] json) throws IOException {
            Message m;
            try {
                m = Codec.decode(json);
            } catch (CodecException e) {
                throw new IOException("bad control message: " + e.getMessage());
            }
            switch (m) {
                case Message.PeerSnapshot ps -> {
                    Store.Superseded lost = hub.store().replaceWith(ps.json());
                    synced = true;
                    lastEventAt = System.currentTimeMillis();
                    if (lost.any()) {
                        // The primary's state wins entire (§13.5), so this is the one moment anyone
                        // can be told what that cost. Normally nothing: a standby's state came from
                        // this same primary. After a partition in which this host was a primary of
                        // its own it is the joins and claims made here, and without this line the
                        // nodes holding them would find out by being strangers.
                        LOG.warn("{} is the primary and its state does not include what this host held: {}. "
                            + "Those nodes have to join again and those names are free to claim; {} "
                            + "(ARCHITECTURE.md §13.5)",
                            primaryHost(), lost, lost.kept() == null
                                ? "the state as it stood could not be written down, so this line is the whole record"
                                : "the state as it stood is kept at " + lost.kept()
                                    + " until the next time this happens");
                    }
                    LOG.info("in sync with {}: {} nodes, {} names", primaryHost(), hub.store().nodes().size(),
                        hub.store().names().size());
                }
                case Message.PeerEvent pe -> {
                    hub.store().applyReplicated(Json.parseObject(pe.json()));
                    eventsApplied.incrementAndGet();
                    lastEventAt = System.currentTimeMillis();
                }
                case Message.PeerCert pc -> installCert(pc);
                case Message.PeerHubKey pk -> hub.keys().installFromPeer(pk.current(), pk.next());
                case Message.PeerChallenge pc -> hub.challengeFromPrimary(pc.txt());
                case Message.PeerNodes pn -> primaryNodes = java.util.Set.copyOf(pn.mkeys());
                case Message.Ping p -> session.control(Codec.encode(new Message.Pong(p.id())));
                case Message.Goodbye g -> {
                    LOG.info("primary said goodbye: {}", g.reason());
                    session.close();
                }
                case Message.Unknown u -> LOG.info("ignoring {}, a message type this hub does not know", u.type());
                default -> LOG.warn("unexpected {} from primary", m.type());
            }
        }

        @Override
        public void onOpen(MuxSession session, MuxStream stream) {
            stream.reset(2);
        }

        @Override
        public void onClosed(MuxSession session, Throwable cause) {
            if (running) {
                LOG.info("primary {} disconnected{}", primaryHost(), cause == null ? "" : ": " + cause.getMessage());
            }
        }
    }

    /**
     * Installs the primary's certificate and writes it where {@link AcmeManager} keeps its own, so
     * a promoted standby restarts with it and renews it from there.
     */
    private void installCert(Message.PeerCert pc) throws IOException {
        if (hub.tls().isLoaded() && hub.tls().keyId().equals(pc.keyId())) {
            return;
        }
        try {
            String pem = String.join("", pc.chainPem());
            List<X509Certificate> chain = Pem.certificates(pem);
            PrivateKey key = Pem.privateKey(pc.keyPem());
            Path dir = hub.config().stateDir().resolve("tls");
            Files.createDirectories(dir);
            Path keyTmp = dir.resolve("wildcard.key.tmp");
            AcmeKeys.writePrivate(keyTmp, pc.keyPem());
            Path pemTmp = dir.resolve("wildcard.pem.tmp");
            Files.writeString(pemTmp, pem, StandardCharsets.UTF_8);
            if (Files.exists(dir.resolve("wildcard.key"))) {
                Files.move(dir.resolve("wildcard.key"), dir.resolve("wildcard.key.prev"), StandardCopyOption.REPLACE_EXISTING);
            }
            Files.move(keyTmp, dir.resolve("wildcard.key"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            Files.move(pemTmp, dir.resolve("wildcard.pem"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            hub.tls().install(chain, key);
            hub.certificateArrived();
        } catch (GeneralSecurityException e) {
            throw new IOException("certificate from primary unusable: " + e.getMessage(), e);
        }
    }

    /** Test hook: cut the channel and keep it cut, or let it reconnect. */
    void suspend(boolean on) {
        suspended = on;
        if (on) {
            MuxSession m = mux;
            if (m != null) {
                m.close();
            }
        }
    }

    @Override
    public synchronized void close() {
        running = false;
        MuxSession m = mux;
        if (m != null) {
            m.close();
        }
        if (thread != null) {
            thread.interrupt();
        }
    }
}
