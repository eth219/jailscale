package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * ARCHITECTURE.md §9.2 and §12: the hub answers signing requests off the mux reader thread.
 *
 * <p>A signing request is not a short callback -- it hashes a transcript, signs with the wildcard
 * key, and writes the reply through the channel's write lock. Served in line on the reader, one
 * connection can only ever be inside one of them at a time, and while it is, no DATA frame on any
 * of that connection's other visitor streams is dispatched. Up to 1,024 visitors share a name
 * (§8.1) and a node may hold a single connection, so that is the whole name waiting behind one
 * handshake.
 *
 * <p>The assertion is structural rather than a measured time: with signing on the reader thread
 * the peak number in flight at once is exactly 1 and cannot be anything else, so observing 2 is
 * proof the serialisation is gone. A slow machine cannot make it pass by accident.
 *
 * <p>It could make it fail by accident, and did (#226): a burst of visitors whose handshakes each
 * finished before the next was scheduled left the peak at 1 with nothing wrong, and {@code
 * windows-2025} is slow enough to do that. Waiting for two to coincide is waiting for a
 * coincidence. So the overlap is now built instead: the first signature is held at {@link
 * NodeGroup#onSignInFlight} until a second one arrives there, which happens if and only if the hub
 * can have two in flight for one connection. Serialised on the reader the second never arrives,
 * the hold times out, and the peak is 1 -- the same red for the same reason, and no longer
 * reachable by being slow.
 */
@Timeout(120)
class SigningConcurrencyTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
    private static final int VISITORS = 64;

    private Path root;
    private Hub hub;
    private int port;
    private Daemon node;
    private ServerSocket app;
    private final AtomicInteger hits = new AtomicInteger();

    @AfterEach
    void stop() throws Exception {
        // Belt as well as braces: the overlap test resets this in a finally, and a failure inside
        // the hook itself would skip that and leave every later test holding its signatures.
        NodeGroup.onSignInFlight = NodeGroup.NO_HOOK;
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

    private void serveApp(Socket c) {
        try (c) {
            HttpRequest r = Http.readRequest(c.getInputStream(), 4096);
            hits.incrementAndGet();
            HttpResponse.text(200, "ok " + r.path()).writeTo(c.getOutputStream());
        } catch (IOException | io.jailscale.proto.http.HttpException e) {
            // visitor gone
        }
    }

    /** A hub, one node on a single control connection, and one open link. */
    private void startHubNodeAndLink() throws Exception {
        Log.setLevel(Log.Level.INFO);
        root = TestDirs.newRoot("jsg");
        java.net.ServerSocket portSocket = TestPorts.listen(1024);
        port = portSocket.getLocalPort();
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.listenOn(portSocket);
        hub.start();
        app = TestPorts.listen(512);
        Thread.ofVirtual().start(() -> {
            while (!app.isClosed()) {
                try {
                    Socket c = app.accept();
                    Thread.ofVirtual().start(() -> serveApp(c));
                } catch (IOException e) {
                    return;
                }
            }
        });
        node = new Daemon(NodeConfig.in(root.resolve("node")));
        node.start();
        Path sock = root.resolve("node/jailscale.sock");
        // One control connection on purpose: the serialisation being tested is per connection, and
        // spreading visitors over several would hide it behind the connection count.
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).put("connections", 1)
            .build()).optBool("ok", false));
        long deadline = System.currentTimeMillis() + 15_000;
        while (!node.hasCert(hub.tls().keyId()) && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        assertTrue(node.hasCert(hub.tls().keyId()), "the node never got the wildcard certificate");
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", app.getLocalPort())
            .put("name", "signing").build()).optBool("ok", false));

    }

    /**
     * How long a held signature waits for a second one before giving up and letting the run fail.
     *
     * <p>Not a timing assumption about a slow machine. With signing off the reader the second
     * request arrives while the first is held, which takes as long as reading the next frame; the
     * wait is only ever reached when there is no second request to come, so its length is how long
     * a failing run takes and not how likely one is.
     *
     * <p>It has to stay well under {@code RemoteSigning.SIGN_TIMEOUT_MS}, which is the 10 s the node
     * gives one SignRequest before it gives up on the handshake. A hold as long as that deadline
     * spends the held visitor's whole budget, so a second request arriving late leaves no time for
     * the signature itself and the run fails on the visitor count -- the symptom, not the cause,
     * which is the thing this test was rewritten to stop doing. Three seconds is a thousand times
     * what reading one frame costs and seven short of starving anybody.
     */
    private static final long HOLD_MS = 3_000;

    @Test
    void signaturesForOneConnectionOverlap() throws Exception {
        startHubNodeAndLink();

        // Two signatures are made to coincide rather than waited on. The first to arrive here
        // blocks until a second does; once two have, the latch is at zero and every later one goes
        // straight through, so this costs one rendezvous and not one per visitor.
        //
        // Serialised on the mux reader, the second cannot arrive while the first is held, so the
        // wait runs out, both proceed, and the peak stays at 1 -- which is the assertion below
        // failing for the reason it names. The bound is what keeps that a failure instead of a
        // hang; @Timeout(120) above is the backstop and HOLD_MS is well inside it.
        CountDownLatch two = new CountDownLatch(2);
        // The largest number in flight at once, taken from the count the hook is handed rather than
        // from a counter of this test's own. That count is the group's signsInFlight, which is an
        // AtomicInteger and is scoped to one node's group -- and the fixture gives that group a
        // single control connection on purpose, so "two in flight for this group" is "two in flight
        // for this connection". A test-side tally would have been scoped to neither, and two
        // connections each serialising on their own reader would have satisfied it.
        AtomicInteger metAtOnce = new AtomicInteger();
        // Which threads ran a signature. Off the reader each gets its own virtual thread named
        // sign-<streamId> (NodeSession.signOffThread); served in line they are all the one reader.
        // This needs no waiting at all and is the sharper half of the assertion below.
        Set<String> signingThreads = ConcurrentHashMap.newKeySet();
        AtomicBoolean heldOut = new AtomicBoolean();
        NodeGroup.onSignInFlight = n -> {
            metAtOnce.accumulateAndGet(n, Math::max);
            signingThreads.add(Thread.currentThread().getName());
            try {
                // await's own answer is the bit that matters: false means the hold ran out with no
                // second signature. The latch reaching zero later is not proof -- serialised, the
                // first waits out HOLD_MS, leaves, and the second counts it down afterwards. Two
                // signatures, never at the same time.
                two.countDown();
                if (!two.await(HOLD_MS, TimeUnit.MILLISECONDS)) {
                    heldOut.set(true);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
        int answered;
        try {
            // Each visitor is a fresh TLS 1.3 session, so each costs the node one signature from the
            // hub. Resumption would not, which is why every one of these is a new context.
            answered = burst();
        } finally {
            NodeGroup.onSignInFlight = NodeGroup.NO_HOOK;
            // Storing a no-op does not release a thread already parked in await -- it will not read
            // the field again. Whoever is in there is let go here, or hub.close() below runs against
            // a connection whose reader is still parked.
            two.countDown();
            two.countDown();
        }

        // The serialisation assertions first, and that order is the point. Held signing starves
        // the visitors as well, so a serialised hub fails every assertion in this method -- and the
        // first one to fail is the one whose message has to name the cause. Asserting the visitor
        // count first reported "no visitor was answered", which is true and is the symptom.
        assertTrue(peakSignatures() > 0, "no signature was requested at all; this test proved nothing");

        // Read once each: both arguments of assertTrue are evaluated before the call, and a hub
        // sign thread still arriving between the condition and the message would print a number
        // that contradicts the failure it is explaining.
        int threads = signingThreads.size();
        assertTrue(threads >= 2, () -> "signing serialised on the mux reader: every signature ran on"
            + " the same thread, " + signingThreads + ", so one visitor's handshake still blocks the"
            + " whole connection");
        int met = metAtOnce.get();
        assertTrue(met >= 2, () -> "signing did not overlap: at most " + met + " signature was in"
            + " flight at once" + (heldOut.get() ? ", and the first was held for " + HOLD_MS
            + " ms without a second arriving" : "") + ", so one visitor's handshake still blocks the"
            + " whole connection");
        int peak = peakSignatures();
        assertTrue(peak >= 2, () -> "two signatures were in flight at once but the high-water mark is "
            + peak + ", so NodeGroup is not counting what this test is holding");

        assertEquals(VISITORS, answered, "every visitor should have been answered");
        assertEquals(VISITORS, hits.get(), "every visitor should have reached the local app");
    }

    /** Fires VISITORS handshakes at the same instant and returns how many were answered. */
    private int burst() throws Exception {
        CountDownLatch go = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(VISITORS);
        AtomicInteger ok = new AtomicInteger();
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < VISITORS; i++) {
            final int n = i;
            threads.add(Thread.ofVirtual().start(() -> {
                try {
                    go.await();
                    SSLContext ctx = Tls.clientContext(CERT, false); // a fresh context: no session to resume
                    try (SSLSocket s = Tls.connect(ctx, "signing.hub.test", "127.0.0.1", port, true, 30_000)) {
                        s.startHandshake();
                        Http.writeRequest(s.getOutputStream(), "GET", "signing.hub.test", "/v" + n, new Headers(), null);
                        HttpResponse r = Http.readResponse(s.getInputStream(), 65536);
                        if (r.status() == 200) {
                            ok.incrementAndGet();
                        }
                    }
                } catch (Exception e) {
                    // counted as not answered
                } finally {
                    done.countDown();
                }
            }));
        }
        go.countDown();
        done.await();
        for (Thread t : threads) {
            t.join();
        }
        return ok.get();
    }

    private int peakSignatures() {
        int peak = 0;
        for (NodeGroup g : hub.registry().all()) {
            peak = Math.max(peak, g.peakConcurrentSignatures());
        }
        return peak;
    }

    /**
     * With the limit exhausted, requests fall back to the reader thread and every one is still
     * answered. That branch is unreachable under any legitimate load — 1,000 visitors peak at
     * about 150 in flight, and the number does not grow with the visitor count — so the limit is
     * lowered here to reach it. What it must not do is lose or deadlock a request: the fallback
     * is the code that shipped before signing moved off the reader, running where it used to run,
     * while other signatures hold the channel write lock around it.
     */
    @Test
    void anExhaustedLimitFallsBackToTheReaderAndStillAnswers() throws Exception {
        NodeSession.concurrentSignLimit = 2;
        try {
            startHubNodeAndLink();
            assertEquals(VISITORS, burst(), "every visitor should be answered through the fallback");
            int inline = hub.registry().get(node.machineKey()).all().stream()
                .mapToInt(NodeSession::signedInline).sum();
            assertTrue(inline > 0, "the fallback was never taken, so it was not tested");
            assertEquals(VISITORS, hits.get(), "every visitor should have reached the local app");
        } finally {
            NodeSession.concurrentSignLimit = NodeSession.MAX_CONCURRENT_SIGNS;
        }
    }
}
