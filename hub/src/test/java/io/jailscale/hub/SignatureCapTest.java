package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Condition 5 of ARCHITECTURE.md §9.2: a visitor stream may spend at most
 * {@link NodeGroup#MAX_SIGNATURES_PER_STREAM} signatures.
 *
 * <p>The hub answers signing requests off the connection's mux reader (§12), so several requests
 * naming one {@code streamId} can be inside the check at the same time. Nothing about the protocol
 * stops a node from putting them on the wire together — the §9.2 conditions exist precisely because
 * the hub does not get to assume the node behaves — so the count has to be taken atomically. Read,
 * check and write as three steps and every racing request reads the same old count, passes, and
 * writes 1: the cap disappears for exactly the peer that goes looking for it.
 */
@Timeout(90)
class SignatureCapTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;
    private Daemon node;
    private ServerSocket app;

    @AfterEach
    void stop() throws Exception {
        if (node != null) {
            node.close();
        }
        if (hub != null) {
            hub.close();
        }
        if (app != null) {
            app.close();
        }
    }

    /** A hub with one registered node holding one open link, and a visitor stream on it. */
    private NodeGroup connectedGroup() throws Exception {
        Log.setLevel(Log.Level.INFO);
        root = TestDirs.newRoot("jsc");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.start();
        app = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        node = new Daemon(NodeConfig.in(root.resolve("node")));
        node.start();
        Path sock = root.resolve("node/jailscale.sock");
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).build()).optBool("ok", false));
        long deadline = System.currentTimeMillis() + 15_000;
        while (!node.hasCert(hub.tls().keyId()) && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        assertTrue(node.hasCert(hub.tls().keyId()), "the node never got the wildcard certificate");
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", app.getLocalPort())
            .put("name", "capped").build()).optBool("ok", false));
        NodeGroup group = hub.registry().get(node.machineKey());
        assertNotNull(group, "the node is not attached to the hub");
        return group;
    }

    /**
     * Many requests for one stream at the same instant take at most the cap between them. The
     * reservation is tested rather than a full {@code sign}, because what a racing request does to
     * the count is decided before any transcript is looked at, and a valid transcript is not
     * needed to show the count being handed out twice.
     */
    @Test
    void racingRequestsForOneStreamCannotExceedTheCap() throws Exception {
        NodeGroup group = connectedGroup();
        Links.Link link = hub.links().byName("capped");
        assertNotNull(link);

        // Repeated, with the racers on platform threads spinning on a flag. The window between
        // reading the count and writing it back is a few instructions wide, so one round released
        // by a latch usually misses it and proves nothing. Platform threads on purpose: a virtual
        // thread that spins does not release its carrier, so spinning ones starve each other and
        // the round never starts.
        //
        // They spin in two stages, and the second one is not decoration. Spinning as soon as a
        // racer is up starves the racers still starting, because the ones already spinning own
        // every core: on a 4-core windows-2025 runner that put 28.6 s of this test into waiting for
        // the sixteenth thread to start, against 0.55 s on a 4-core Linux one, and the class landed
        // within seconds of its own 90 s timeout. So each racer arrives, then waits on `armed`
        // costing nothing, and only spins once every one of them is up -- with the last one in
        // starting the race rather than this thread, which would otherwise have to win a core back
        // from fifteen spinners to do it.
        int rounds = 120;
        int racers = 16;
        for (int round = 0; round < rounds; round++) {
            MuxStream stream = group.openVisitor(link, "capped.hub.test", "203.0.113.9", 40000 + round,
                hub.tls().keyId(), false);
            long id = group.visitorIds().stream().max(Long::compare).orElseThrow();
            java.util.concurrent.atomic.AtomicBoolean go = new java.util.concurrent.atomic.AtomicBoolean();
            CountDownLatch ready = new CountDownLatch(racers);
            CountDownLatch armed = new CountDownLatch(1);
            AtomicInteger spinning = new AtomicInteger();
            CountDownLatch done = new CountDownLatch(racers);
            AtomicInteger granted = new AtomicInteger();
            for (int i = 0; i < racers; i++) {
                Thread.ofPlatform().daemon().start(() -> {
                    ready.countDown();
                    try {
                        armed.await();
                    } catch (InterruptedException e) {
                        // Nobody interrupts these, but a racer that left without starting the race
                        // would leave the other fifteen spinning on every core for the life of the
                        // JVM. Release them, and let the round fail on its count.
                        Thread.currentThread().interrupt();
                        go.set(true);
                        done.countDown();
                        return;
                    }
                    if (spinning.incrementAndGet() == racers) {
                        go.set(true);
                    } else {
                        while (!go.get()) {
                            Thread.onSpinWait();
                        }
                    }
                    if (group.reserveSignature(id)) {
                        granted.incrementAndGet();
                    }
                    done.countDown();
                });
            }
            assertTrue(ready.await(30, TimeUnit.SECONDS));
            armed.countDown();
            assertTrue(done.await(30, TimeUnit.SECONDS));
            assertEquals(NodeGroup.MAX_SIGNATURES_PER_STREAM, granted.get(),
                "round " + round + ": the cap was handed out " + granted.get() + " times to " + racers
                    + " racing requests");
            assertEquals(NodeGroup.MAX_SIGNATURES_PER_STREAM, group.signaturesUsed(id),
                "round " + round + ": the recorded count must match what was granted");
            group.visitorDone(stream);
        }
    }

    /** Sequentially, the same: the cap is spent once and then refuses. */
    @Test
    void theCapIsSpentOnceAndThenRefuses() throws Exception {
        NodeGroup group = connectedGroup();
        Links.Link link = hub.links().byName("capped");
        MuxStream stream = group.openVisitor(link, "capped.hub.test", "203.0.113.9", 40001, hub.tls().keyId(), false);
        long id = group.visitorIds().iterator().next();
        for (int i = 0; i < NodeGroup.MAX_SIGNATURES_PER_STREAM; i++) {
            assertTrue(group.reserveSignature(id), "signature " + (i + 1) + " should be granted");
            assertEquals(i + 1, group.signaturesUsed(id));
        }
        assertTrue(!group.reserveSignature(id), "past the cap the reservation must be refused");
        assertEquals(NodeGroup.MAX_SIGNATURES_PER_STREAM, group.signaturesUsed(id));
        group.visitorDone(stream);
    }

    /** A stream the hub does not have open reserves nothing, whatever the id. */
    @Test
    void anUnknownStreamReservesNothing() throws Exception {
        NodeGroup group = connectedGroup();
        assertTrue(!group.reserveSignature(0xDEADBEEFL), "an unknown stream must not be reservable");
    }

    /**
     * One connected node still completes a real visitor handshake on one signature.
     *
     * <p>The local app answers every connection rather than exactly one, which is what every other
     * end-to-end test here does and what this one did not. It failed twice on macos-15 with
     * {@code EOFException: no response} — the visitor's stream closing with nothing on it, about
     * 3 ms after the link opened, with neither the hub nor the node logging a complaint at any
     * level. Twenty runs here, including six under deliberate CPU contention, did not reproduce it.
     *
     * <p><b>So this is a robustness change on circumstantial evidence and not a diagnosis.</b> What
     * is circumstantial: a one-shot accept has nothing to answer a second local connection with, and
     * the node opens one per visitor and retries a refused or reset one five times (§9.3), so any
     * second arrival left the real visitor waiting on a socket nobody would ever write to — which is
     * the symptom. The stable siblings serve in a loop and do not flake.
     *
     * <p>The count is kept and reported so the next failure is evidence rather than another guess:
     * if it fails again with one connection seen, the single accept was never the cause.
     */
    @Test
    void anOrdinaryVisitorSpendsOneSignature() throws Exception {
        NodeGroup group = connectedGroup();
        java.util.concurrent.atomic.AtomicInteger localConnections = new java.util.concurrent.atomic.AtomicInteger();
        Thread.ofVirtual().start(() -> {
            while (!app.isClosed()) {
                try {
                    java.net.Socket c = app.accept();
                    localConnections.incrementAndGet();
                    Thread.ofVirtual().start(() -> {
                        try (c) {
                            c.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".getBytes());
                            c.getOutputStream().flush();
                        } catch (IOException e) {
                            // the assertion below reports it
                        }
                    });
                } catch (IOException e) {
                    return;
                }
            }
        });
        try (javax.net.ssl.SSLSocket s = io.jailscale.proto.tls.Tls.connect(
            io.jailscale.proto.tls.Tls.clientContext(CERT, false), "capped.hub.test", "127.0.0.1", port, true, 20_000)) {
            s.startHandshake();
            io.jailscale.proto.http.Http.writeRequest(s.getOutputStream(), "GET", "capped.hub.test", "/",
                new io.jailscale.proto.http.Headers(), null);
            try {
                assertEquals(200, io.jailscale.proto.http.Http.readResponse(s.getInputStream(), 4096).status());
            } catch (java.io.EOFException e) {
                throw new AssertionError("the visitor's stream closed with no response; the local app saw "
                    + localConnections.get() + " connection(s). One means the single accept this test "
                    + "used to do was not what was starving it, and the cause is still open.", e);
            }
        }
        assertTrue(group.peakConcurrentSignatures() >= 1, "the handshake should have needed a signature");
    }
}
