package io.jailscale.node;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.net.DuplexThread;
import io.jailscale.proto.net.ProxyProtocol;
import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.util.Log;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import io.jailscale.proto.mux.Frame;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.security.KeyStore;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/**
 * Visitor streams on the node (ARCHITECTURE.md §9.2, §9.3): terminate TLS with the hub's
 * certificate and a remote key, connect to the local target, copy bytes both ways.
 */
final class Visitors {

    private static final Log LOG = Log.get("visitor");
    private static final int LOCAL_CONNECT_TIMEOUT_MS = 5_000;
    static final long UDP_IDLE_MS = 60_000;
    /**
     * The buffer the visitor gate reads its request head through, on gated links only. Not
     * {@link Gate#MAX_HEAD}: that is the limit on how long a head may be, enforced by a counter
     * as the head is read, and it does not have to be resident per connection. This only has to
     * be large enough that an ordinary head is one read instead of several hundred, and it is
     * memory every gated visitor holds (§15), so it is the smaller number.
     */
    private static final int GATE_BUFFER = 4 * 1024;

    private final NodeState state;
    private final SelfProbe probe = new SelfProbe();
    private final Map<String, SSLContext> contexts = new ConcurrentHashMap<>();
    private final Map<String, SSLContext> domainContexts = new ConcurrentHashMap<>();
    private final java.util.concurrent.atomic.AtomicInteger inFlight = new java.util.concurrent.atomic.AtomicInteger();
    private final java.util.concurrent.atomic.AtomicLong refused = new java.util.concurrent.atomic.AtomicLong();
    private volatile long lastRefusalLog;
    /** A visitor handshake slower than this is worth a line; healthy is single-digit milliseconds. */
    private static final long SLOW_HANDSHAKE_MS = 1_000;

    /**
     * What the shipped 64 MiB ceiling was measured to hold, and the unit the bound scales in.
     *
     * <p>Found by running {@code measure.sh SLOW=} against an unbounded node on darwin-arm64,
     * GraalVM CE 25.3, the release build. Peak RSS and whether it lived:
     *
     * <pre>
     *   400   82.1, 82.3, 83.2 MB   lives (and four more runs on the CI runner, 88.5 to 89.7)
     *   450   88.3 MB               lives
     *   500   92.3, 92.4, 93.3 MB   lives, three for three
     *   550   98.5 MB               lives
     *   600   99.6 MB               DIES, 550 of 600 admitted
     *   1000  106.6 MB              DIES, 817 of 1000 admitted, six OutOfMemoryErrors
     * </pre>
     *
     * <p>RSS climbs about 99 KB per visitor across that range, which is the per-visitor figure of
     * §15 arriving from a second direction. The cliff is between 550 and 600.
     *
     * <p><b>450 and not 550, for two reasons that are not caution.</b> Whether the heap is exhausted
     * depends on arrival rate as well as count -- FlowBudget's own measurements have the same axis
     * behaving differently at three ramp speeds -- so the counts next to the cliff are the ones a
     * slower ramp would move, and 550 lived exactly once. And the budget gate runs at 400 (§14): a
     * ceiling at 400 would refuse the harness's own ordinary visitor, the one whose latency the
     * phase reports, so the bound has to sit above the count anyone measures at, not on it.
     */
    private static final int VISITORS_PER_64MIB = 450;

    /**
     * How many visitor streams this node will serve at once (ARCHITECTURE.md §9.3): the bound that
     * the hub's {@link io.jailscale.proto.mux.FlowBudget} is for queued bytes. Derived at startup
     * from the heap this process was actually given, so the diagnosis hatch keeps working --
     * {@code -XX:MaxHeapSize=} through {@code JAILSCALE_DAEMON_OPTS} (§14) raises the ceiling, and
     * a node whose ceiling was raised should serve more visitors rather than hold the number that
     * suited 64 MiB. Linear in the ceiling because the cost is per visitor; the floor of 64 is for
     * a ceiling small enough that the arithmetic would otherwise say single digits, where a node
     * has a configuration problem this bound cannot fix.
     *
     * <p><b>A count and not a byte budget, which is the opposite of the hub's choice and for the
     * reason that made the hub's the right one there.</b> The hub bounds bytes because what a
     * visitor costs it depends entirely on the visitor's behaviour -- a thousand who read what they
     * asked for hold almost nothing, and deriving a connection count would have to assume the worst
     * case for all of them. On the node the cost is the visitor's TLS state, which is the same
     * whether it reads or stalls, so the count *is* the resource and a byte budget would be a
     * harder way to say the same number.
     *
     * <p><b>Refusing, where the hub reclaims, and the asymmetry is real rather than an
     * inconsistency.</b> The hub can pick a provably stalled stream -- one that has not consumed a
     * byte in {@code STALL_MS} -- so it frees memory from a connection that is not using it.
     * Nothing on the node is idle in that sense: a visitor's TLS state is live for as long as the
     * visitor is, so reclaiming here means choosing a victim among connections that are all making
     * progress. FlowBudget's argument against refusing still stands and is the cost of this: an
     * attacker who holds the bound's worth of connections open keeps everyone else out. What that
     * is measured against is not a healthy node, it is the node as it behaves today -- at a
     * thousand stalled readers it exhausts its heap, and the OutOfMemoryError lands on whichever
     * thread allocates next, which in the measured runs took `mux-reader` and `mux-writer` with it
     * and dropped the hub connection and every visitor on it (§14). Refusing the thousandth visitor
     * costs that visitor; not refusing it costs all of them, and the hub caps a name at
     * {@code SniRouter.MAX_PER_NAME} = 1,024 by the same kind of reasoning.
     */
    static int defaultCeiling() {
        return ceilingFor(Runtime.getRuntime().maxMemory());
    }

    /**
     * This instance's bound, and the ONLY bound anything inside this class may read. It was a
     * static field as well, holding the derived default, and the refusal log picked that one up
     * while the check used this one: a node running to a bound of 3 told its operator it was "at
     * the visitor ceiling (64800)". Nothing caught it because nothing reads the log, and a
     * measurement of something else found it by accident. There is no second number in scope now.
     * Settable so a test can reach the
     * ceiling without a heap that large, and so a host can say the number itself -- the same escape
     * {@link io.jailscale.proto.mux.FlowBudget#of} offers for the hub's byte budget, which the two
     * bounds should have in common since they are derived from the same place for the same reason.
     * Neither is wired to a flag: nothing measured so far asks for a number other than the derived
     * one, and a knob with no use is a surface to support.
     */
    private final int maxInFlight;

    /**
     * The arithmetic on its own, so the numbers above can be held against something. A heap of
     * {@link Long#MAX_VALUE} means no ceiling was set, which is a JVM run and not a shipped binary:
     * the native images are built with {@code -R:MaxHeapSize} (native.maxHeap in the poms) and
     * always give a real answer here.
     */
    static int ceilingFor(long heapBytes) {
        long heap = heapBytes == Long.MAX_VALUE ? 64L * 1024 * 1024 : heapBytes;
        long n = heap * VISITORS_PER_64MIB / (64L * 1024 * 1024);
        return (int) Math.max(64, Math.min(Integer.MAX_VALUE, n));
    }

    Visitors(NodeState state) {
        this(state, defaultCeiling());
    }

    Visitors(NodeState state, int maxInFlight) {
        if (maxInFlight <= 0) {
            throw new IllegalArgumentException("the visitor bound must be positive: " + maxInFlight);
        }
        this.state = state;
        this.maxInFlight = maxInFlight;
        RemoteSigning.install();
    }

    /** How many visitor streams this node will serve at once (ARCHITECTURE.md §9.3). */
    int maxInFlight() {
        return maxInFlight;
    }

    /** Builds the SSLContext for a certificate the hub sent. */
    void onCert(Message.CertUpdate cert) {
        try {
            StringBuilder pem = new StringBuilder();
            for (String p : cert.chainPem()) {
                pem.append(p);
            }
            List<X509Certificate> chain = Pem.certificates(pem.toString());
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(new KeyManager[] {new RemoteSigning.RemoteKeyManager(chain, cert.keyId())}, null, RemoteSigning.RANDOM);
            contexts.put(cert.keyId(), ctx);
            if (contexts.size() > 3) {
                contexts.keySet().stream().filter(k -> !k.equals(cert.keyId())).findFirst().ifPresent(contexts::remove);
            }
            LOG.info("certificate {} installed ({} until {})", cert.keyId(), chain.get(0).getSubjectX500Principal(),
                chain.get(0).getNotAfter());
        } catch (GeneralSecurityException e) {
            LOG.warn("bad certificate from hub", e);
        }
    }

    boolean hasCert(String keyId) {
        return contexts.containsKey(keyId);
    }

    /** ARCHITECTURE.md §9.2: a user domain terminates with the node's real key under keyId {@code domain:<name>}. */
    void installDomain(DomainCerts.Material m) throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        char[] pw = new char[0];
        ks.setKeyEntry("domain", m.key(), pw, m.chain().toArray(new X509Certificate[0]));
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pw);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, null);
        domainContexts.put("domain:" + m.domain(), ctx);
    }

    SelfProbe probe() {
        return probe;
    }

    void removeDomain(String domain) {
        domainContexts.remove("domain:" + domain);
    }

    /**
     * Serves one visitor stream to completion on the calling (virtual) thread, and counts it while
     * it does. The count is the node's half of the hub's {@code jailhub_visitors_in_flight}
     * (ARCHITECTURE.md §14): what a node holds per visitor is tens of kilobytes of TLS state, and
     * until now the only way to see how many it was holding was to watch RSS, which cannot say
     * whether the cause was visitors, a leak, or the heap simply expanding into its ceiling.
     */
    void serve(HubLink link, HubLink.Session session, MuxStream stream) {
        // Around the whole of it, not around the TlsEndpoint: several paths abandon a visitor
        // before the endpoint is closed, and a count that leaks on those would invent visitors that
        // are not there.
        if (inFlight.incrementAndGet() > maxInFlight) {
            inFlight.decrementAndGet();
            refuse(stream);
            return;
        }
        try {
            serveVisitor(link, session, stream);
        } finally {
            inFlight.decrementAndGet();
        }
    }

    /**
     * Turns away one visitor over {@link #maxInFlight}. Here rather than after the handshake:
     * what is being conserved is the TLS state, so the visitor has to be refused before there is
     * any. Nothing is sent back but the reset, because saying anything politer would mean
     * completing the handshake that this exists to avoid.
     */
    private void refuse(MuxStream stream) {
        long n = refused.incrementAndGet();
        stream.reset(Frame.RST_NO_CAPACITY);
        // One line a minute. A node at its ceiling refuses continuously, and a log that says so on
        // every stream buries the reason among its own symptoms.
        long now = System.currentTimeMillis();
        if (now - lastRefusalLog >= REFUSAL_LOG_MS) {
            lastRefusalLog = now;
            LOG.warn("at the visitor ceiling ({}), refusing new visitors; {} refused so far. "
                + "Raise it with -XX:MaxHeapSize= in JAILSCALE_DAEMON_OPTS (ARCHITECTURE.md §9.3)",
                maxInFlight, n);
        }
    }

    private static final long REFUSAL_LOG_MS = 60_000;

    /** Visitor streams being served right now, TLS and raw alike. */
    int inFlight() {
        return inFlight.get();
    }

    /** Visitors turned away at {@link #maxInFlight} since this daemon started. */
    long refused() {
        return refused.get();
    }

    private void serveVisitor(HubLink link, HubLink.Session session, MuxStream stream) {
        int conn = session.conn;
        String linkId = stream.meta().optString("linkId", null);
        String kind = stream.meta().optString("kind", Message.LinkOpen.HTTPS);
        if (!Message.LinkOpen.HTTPS.equals(kind)) {
            serveRaw(kind, stream, state.linkById(linkId));
            return;
        }
        byte[] proxyLine = proxyLine(stream, state.linkById(linkId));
        String keyId = stream.meta().optString("keyId", null);
        String sni = stream.meta().optString("sni", "?");
        NodeState.LinkRec target = state.linkById(linkId);
        SSLContext ctx = keyId == null ? null : keyId.startsWith("domain:") ? domainContexts.get(keyId) : contexts.get(keyId);
        if (target == null || ctx == null) {
            LOG.warn("visitor for {} refused: {}", sni, target == null ? "unknown link" : "no certificate " + keyId);
            stream.reset(4);
            return;
        }
        long tEnter = System.currentTimeMillis();
        TlsEndpoint tls = new TlsEndpoint(ctx, stream.in(), stream.out());
        try {
            // Remember that this node, and not the hub or another node, terminated it (§11.3).
            // Not after handshake(): on the server side of TLS 1.3 the exporter is not usable
            // until the peer's Finished has been processed, and that has not necessarily happened
            // when the handshake loop returns. Recording nothing would later read as a compromised
            // hub, so this waits for the first application bytes instead.
            tls.onFirstApplicationRead(() -> probe.record(SelfProbe.material(tls.session())));
            RemoteSigning.enter(new RemoteSigning.Context(link, session, HubLink.fullStreamId(conn, stream.id()), keyId, tls));
            try {
                tls.handshake();
            } finally {
                RemoteSigning.exit();
            }
        } catch (IOException e) {
            LOG.debug("TLS handshake for {} failed: {}", sni, e.getMessage());
            stream.reset(5);
            return;
        }
        // A visitor that waits seconds for its handshake is the thing §14 is chasing, and the hub
        // cannot see which side spent them: its own timing ends at the node's first byte. If the
        // handshake here is fast and the hub still saw a long wait, the time went before this
        // method ran.
        long handshakeMs = System.currentTimeMillis() - tEnter;
        if (handshakeMs >= SLOW_HANDSHAKE_MS) {
            LOG.warn("visitor handshake for {} took {} ms inside the node", sni, handshakeMs);
        }
        byte[] replay = null;
        InputStream plain = tls.plainIn();
        if (target.gateHash != null) {
            // The gate reads the request head a byte at a time looking for the blank line, and
            // every one of those single-byte reads allocates and takes the engine's lock. Buffer
            // it -- but the buffer has to be the same object the relay then reads from, because a
            // BufferedInputStream reads ahead and whatever it took past the head is the start of
            // the visitor's body. Thrown away with the wrapper, that is a truncated request.
            plain = new BufferedInputStream(plain, GATE_BUFFER);
            try {
                boolean expired = target.gateExpiresAt > 0 && System.currentTimeMillis() > target.gateExpiresAt;
                Gate.Decision d = Gate.decide(plain, target.gateHash, expired);
                switch (d) {
                    case Gate.Decision.Pass p -> replay = p.head();
                    case Gate.Decision.SetCookie sc -> {
                        HttpResponse.redirect(sc.location())
                            .header("Set-Cookie", Gate.COOKIE + "=" + sc.token() + "; Path=/; Secure; HttpOnly; SameSite=Lax")
                            .writeTo(tls.plainOut());
                        tls.close();
                        stream.close();
                        return;
                    }
                    case Gate.Decision.Refuse r -> {
                        HttpResponse.html(403, "<!doctype html><meta charset=utf-8><title>jailscale</title>"
                            + "<p>This link needs a visit link to open.</p>").writeTo(tls.plainOut());
                        tls.close();
                        stream.close();
                        return;
                    }
                }
            } catch (IOException e) {
                stream.reset(6);
                return;
            }
        }
        Socket local;
        try {
            local = connectLocal(target);
        } catch (IOException e) {
            LOG.warn("{}: local target {}:{} unreachable: {}", sni, target.host(), target.port(), e.getMessage());
            badGateway(tls, plain, target);
            try {
                stream.close();
            } catch (IOException ignored) {
                // closing
            }
            return;
        }
        relay(tls, plain, local, stream, concat(proxyLine, replay));
    }

    /** ARCHITECTURE.md §9.3: {@code --proxy-protocol} tells the local app who the visitor is, HAProxy style. */
    private static byte[] proxyLine(MuxStream stream, NodeState.LinkRec target) {
        if (target == null || !target.proxyProtocol) {
            return null;
        }
        String ip = stream.meta().optString("visitorAddr", "0.0.0.0");
        int port = stream.meta().optInt("visitorPort", 0);
        return ProxyProtocol.v1Line(ip, port, target.host(), target.port()).getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** ARCHITECTURE.md §8.4 / §9.3: raw TCP copies bytes; raw UDP maps one DGRAM stream to one local socket. */
    private static void serveRaw(String kind, MuxStream stream, NodeState.LinkRec target) {
        if (target == null || !target.kind.equals(kind)) {
            LOG.warn("{} visitor refused: unknown link", kind);
            stream.reset(4);
            return;
        }
        if (Message.LinkOpen.UDP.equals(kind) && stream.isDatagram()) {
            serveUdp(stream, target);
            return;
        }
        Socket local;
        try {
            local = connectLocal(target);
        } catch (IOException e) {
            LOG.warn("tcp: local target {}:{} unreachable: {}", target.host(), target.port(), e.getMessage());
            stream.reset(7);
            return;
        }
        byte[] proxyLine = proxyLine(stream, target);
        Thread toLocal = DuplexThread.start("raw-in", () -> {
            try {
                if (proxyLine != null) {
                    local.getOutputStream().write(proxyLine);
                }
                copy(stream.in(), local.getOutputStream());
                local.shutdownOutput();
            } catch (IOException e) {
                closeQuietly(local);
            }
        });
        try {
            copy(local.getInputStream(), stream.out());
            stream.close();
        } catch (IOException e) {
            stream.reset(1);
        } finally {
            closeQuietly(local);
        }
        try {
            toLocal.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void serveUdp(MuxStream stream, NodeState.LinkRec target) {
        DatagramSocket local;
        try {
            local = new DatagramSocket();
            local.connect(InetAddress.getByName(target.host()), target.port());
            local.setSoTimeout((int) UDP_IDLE_MS);
        } catch (IOException e) {
            LOG.warn("udp: local target {}:{} unusable: {}", target.host(), target.port(), e.getMessage());
            stream.reset(7);
            return;
        }
        Thread back = DuplexThread.start("raw-udp-back", () -> {
            byte[] buf = new byte[Frame.MAX_DATA];
            try {
                while (true) {
                    DatagramPacket p = new DatagramPacket(buf, buf.length);
                    local.receive(p);
                    stream.send(java.util.Arrays.copyOf(p.getData(), p.getLength()));
                }
            } catch (IOException e) {
                // idle timeout, stream reset or socket closed: the flow is over
                stream.reset(0);
            }
        });
        try {
            byte[] d;
            while ((d = stream.receive()) != null) {
                local.send(new DatagramPacket(d, d.length));
            }
        } catch (IOException e) {
            LOG.debug("udp flow to {}:{} ended: {}", target.host(), target.port(), e.getMessage());
            stream.reset(1);
        } finally {
            local.close();
        }
        try {
            back.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Connects to the local target. A burst of visitors can overflow a small listen backlog
     * (macOS defaults to 128), which shows up as an immediate refusal or reset; a few short
     * retries (up to ~1.5 s) turn that into a served request instead of a 502.
     *
     * <p><b>Both socket buffers are given the stream window before connecting.</b> Left to the
     * kernel they autotune to megabytes each (measured at up to 8 MB on macOS; Linux allows 6), and
     * they hold what the visitor has not read once this thread stops taking it: a visitor that
     * stalls its download stops this stream at {@link MuxStream#WINDOW} of credit, and from then
     * on every byte the app can still push lands in the kernel, on this machine, outside any figure
     * the node reports. Measured with 400 stalled visitors on loopback, these sockets held 300 to
     * 400 MB -- a megabyte each -- while the machine's network memory sat at its cap and every
     * socket on it froze, including the ones a visitor's handshake needed (ARCHITECTURE.md §14).
     * A byte this stream cannot send yet is a byte it should not have asked the app for, so the
     * kernel is told the window. What comes back differs per kernel -- macOS doubles it at connect
     * and holds it there; Linux gives the receive side the window and clamps the send side to
     * {@code net.core.wmem_max} where that is lower, 212,992 on the CI runner -- but never upwards,
     * and never growing afterwards, which is the property this needs: the lock that ends autotuning
     * is taken whether or not the value is clamped. The
     * app is on this machine or its network, where 256 KB is far past the bandwidth-delay
     * product, so this costs no throughput; the visitor-facing sockets are the hub's and are not
     * touched, because a visitor a continent away needs the kernel's pipelining.
     */
    static Socket connectLocal(NodeState.LinkRec target) throws IOException {
        IOException last = null;
        for (int attempt = 0; attempt < 5; attempt++) {
            Socket s = new Socket();
            try {
                // Before connect: the receive window is scaled from the buffer at SYN time, and an
                // explicit size is what switches the kernel's autotuning off for this socket.
                s.setReceiveBufferSize(MuxStream.WINDOW);
                s.setSendBufferSize(MuxStream.WINDOW);
                s.connect(new InetSocketAddress(target.host(), target.port()), LOCAL_CONNECT_TIMEOUT_MS);
                s.setTcpNoDelay(true);
                return s;
            } catch (java.net.SocketTimeoutException e) {
                closeQuietly(s);
                throw e;
            } catch (java.net.SocketException e) { // refused or reset: the listener's backlog is full
                last = e;
                closeQuietly(s);
                try {
                    Thread.sleep(50L << attempt);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            } catch (IOException e) {
                closeQuietly(s);
                throw e;
            }
        }
        throw last;
    }

    /**
     * {@code plain} is the visitor's plaintext, which is {@code tls.plainIn()} unless the gate
     * (§9.3) already read the request head from a buffered view of it -- in which case it is that
     * view, holding whatever the gate read past the head.
     */
    private static void relay(TlsEndpoint tls, InputStream plain, Socket local, MuxStream stream, byte[] replay) {
        Thread toLocal = DuplexThread.start("visitor-in", () -> {
            try {
                if (replay != null) {
                    local.getOutputStream().write(replay);
                    local.getOutputStream().flush();
                }
                // Straight from the engine's plaintext buffer where that is what `plain` is: a
                // buffer per visitor that exists only to be copied out of is memory this node
                // cannot spare (§15). A gated link wraps the stream to read the request head, and
                // that wrapper holds bytes of its own, so it keeps the copy.
                if (plain instanceof BufferedInputStream) {
                    copy(plain, local.getOutputStream());
                } else {
                    drain(tls, local.getOutputStream());
                }
                local.shutdownOutput();
            } catch (IOException e) {
                closeQuietly(local);
            }
        });
        try {
            copy(local.getInputStream(), tls.plainOut());
            tls.close();
            stream.close();
        } catch (IOException e) {
            stream.reset(1);
        } finally {
            closeQuietly(local);
        }
        try {
            toLocal.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void badGateway(TlsEndpoint tls, InputStream plain, NodeState.LinkRec target) {
        try {
            // Consume the request head so the browser sees a clean response, then answer.
            byte[] buf = new byte[4096];
            int n = plain.read(buf);
            if (n < 0) {
                return;
            }
            HttpResponse.html(502, "<!doctype html><meta charset=utf-8><title>jailscale</title>"
                + "<p>The node cannot reach <b>" + target.host() + ":" + target.port() + "</b>.</p>")
                .writeTo(tls.plainOut());
            tls.close();
        } catch (IOException ignored) {
            // visitor gone
        }
    }

    /** Visitor to local app, taking the plaintext where the engine left it. */
    private static void drain(TlsEndpoint tls, OutputStream out) throws IOException {
        while (tls.drainTo(out) >= 0) {
            // drainTo writes and flushes; the loop is only here to run it to end of stream
        }
    }

    static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[16 * 1024];
        int n;
        while ((n = in.read(buf)) >= 0) {
            if (n > 0) {
                out.write(buf, 0, n);
                out.flush();
            }
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // closing
        }
    }
}
