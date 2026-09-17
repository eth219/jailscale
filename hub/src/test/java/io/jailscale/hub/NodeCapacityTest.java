package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * The node tells the hub how many visitors it will hold, and the hub stops there
 * (ARCHITECTURE.md §9.3).
 *
 * <p>What this is for is not throughput. Before it, the hub had no number for a node's capacity at
 * all: it admitted whatever its own caps allowed -- 1,024 a name, against a node holding a few
 * hundred -- opened a stream for each, and the node reset the ones it could not take. The visitor
 * was turned away either way; the difference is that the decision is now made where the hub's other
 * two admission decisions are made, before a stream exists, and that the hub can say what its nodes
 * can hold instead of printing a limit that was never a capacity.
 *
 * <p>The assertion that matters most here is the one about the node's own counter staying at zero.
 * The node keeps its bound as a backstop and always will -- an old hub, or a race between the
 * hub's check and the open, has to be survivable -- so the way to tell that the hub is really doing
 * the refusing is that the backstop never fires.
 *
 * <p>Not covered here: a node that advertises nothing, which is every build older than the field.
 * That path is the {@code ceiling > 0} guard in {@link SniRouter} and {@link NodeGroup}, and the
 * wire half of it is pinned in {@code WireFormatTest} -- a Hello without the field decodes to 0 and
 * re-encodes without inventing one. Reaching it from here would need a node built before the field.
 */
@Timeout(120)
class NodeCapacityTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
    private static final int CEILING = 3;

    private Path root;
    private Hub hub;
    private int port;
    private Daemon node;
    private ServerSocket app;
    private final CountDownLatch release = new CountDownLatch(1);
    private final AtomicInteger appHits = new AtomicInteger();

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.INFO);
        root = TestDirs.newRoot("jcap");
        java.net.ServerSocket portSocket = TestPorts.listen(1024);
        port = portSocket.getLocalPort();
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.listenOn(portSocket);
        hub.start();
        // An app that answers only once released, so visitors stay in flight and the node stays at
        // its bound while the assertions run. A responding app would free slots as fast as they
        // filled and the test would measure nothing.
        app = TestPorts.listen(64);
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
    }

    private void serveApp(Socket c) {
        try (c) {
            HttpRequest r = Http.readRequest(c.getInputStream(), 4096);
            appHits.incrementAndGet();
            release.await();
            HttpResponse.text(200, "ok " + r.path()).writeTo(c.getOutputStream());
        } catch (Exception e) {
            // visitor gone
        }
    }

    @AfterEach
    void stop() throws Exception {
        release.countDown();
        TestCloseables.closeAll(node, app, hub);
    }

    /** Joins with a node that will hold {@code CEILING} visitors and opens one link on it. */
    private void join() throws Exception {
        node = new Daemon(NodeConfig.in(root.resolve("alice")).withTuning(NodeConfig.Tuning.defaults().visitorCeiling(CEILING)));
        node.start();
        Path sock = root.resolve("alice/jailscale.sock");
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).build()).optBool("ok", false));
        long deadline = System.currentTimeMillis() + 20_000;
        while (!node.hasCert(hub.tls().keyId()) && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "open")
            .put("port", app.getLocalPort()).put("name", "cap").build()).optBool("ok", false));
    }

    /** A visitor that sends its request and then holds the connection open. */
    private Thread visitor(SSLContext ctx, CountDownLatch sent, List<String> failures, int n) {
        return Thread.ofVirtual().start(() -> {
            try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
                s.connect(new java.net.InetSocketAddress("127.0.0.1", port), 10_000);
                javax.net.ssl.SSLParameters p = s.getSSLParameters();
                p.setServerNames(List.of(new javax.net.ssl.SNIHostName("cap.hub.test")));
                s.setSSLParameters(p);
                s.setSoTimeout(60_000);
                s.startHandshake();
                Http.writeRequest(s.getOutputStream(), "GET", "cap.hub.test", "/v" + n, null, null);
                sent.countDown();
                release.await();
            } catch (Exception e) {
                failures.add("visitor " + n + ": " + e);
                sent.countDown();
            }
        });
    }

    @Test
    void theHubLearnsWhatTheNodeWillHoldAndSaysSo() throws Exception {
        join();
        NodeGroup g = hub.registry().get(node.machineKey());
        assertEquals(CEILING, g.visitorCeiling(), "the hub did not read the bound off Hello");
        assertEquals(CEILING, hub.registry().visitorCapacity());

        // The public page used to print a per-name cap as if it were a capacity. It now prints what
        // the nodes said, and the old row says plainly that the node is the other bound.
        String page = new String(hub.front().route(Http.readRequest(
            new java.io.ByteArrayInputStream("GET / HTTP/1.1\r\nHost: hub.test\r\n\r\n".getBytes()), 4096))
            .body(), java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(page.contains("no more than the node"), page);
        assertTrue(page.contains(CEILING + " together"), page);
    }

    @Test
    void pastTheBoundTheHubTurnsVisitorsAwayAndTheNodeNeverHasTo() throws Exception {
        join();
        long refusedBefore = Metrics.VISITORS_REFUSED_CAPACITY.sum();

        SSLContext ctx = Tls.clientContext(CERT, false);
        CountDownLatch sent = new CountDownLatch(CEILING);
        List<String> failures = new java.util.concurrent.CopyOnWriteArrayList<>();
        List<Thread> held = new ArrayList<>();
        for (int i = 0; i < CEILING; i++) {
            held.add(visitor(ctx, sent, failures, i));
        }
        assertTrue(sent.await(30, TimeUnit.SECONDS), "the first " + CEILING + " visitors never got through");
        assertEquals(List.of(), failures, "a visitor inside the bound should be served");
        // Waited for, not asserted: the latch above says the visitor wrote its request, and the
        // request still has to cross the hub, the node and the local socket. Asserting appHits
        // straight after the latch passed on a developer's machine and failed on both CI runners at
        // 0 of 3 -- the bound was full but the app had not been reached yet. Waiting for the app is
        // also the strongest statement of the precondition: all three visitors are established the
        // whole way through, so the node is genuinely holding its bound when the next one arrives.
        waitFor(() -> appHits.get() == CEILING);
        waitFor(() -> hub.registry().get(node.machineKey()).visitorsInFlight() == CEILING);

        // Taken here, with the bound already full, so it counts only the visitor below. VISITORS
        // moves when a visitor is admitted and about to be relayed, which is what tells the hub's
        // own early check apart from the backstop inside NodeGroup.openVisitor: both refuse and both
        // count a capacity refusal, and only the early one refuses before this moves.
        long routedBefore = Metrics.VISITORS.sum();

        // One more than the node will hold. It is refused by the hub, and the socket is closed
        // rather than answered, so this side sees the connection go without an HTTP reply.
        CountDownLatch overSent = new CountDownLatch(1);
        List<String> overFailures = new java.util.concurrent.CopyOnWriteArrayList<>();
        Thread over = visitor(ctx, overSent, overFailures, 99);
        assertTrue(overSent.await(30, TimeUnit.SECONDS));
        over.join(30_000);

        assertEquals(refusedBefore + 1, Metrics.VISITORS_REFUSED_CAPACITY.sum(),
            "the hub should have counted one capacity refusal");
        assertEquals(routedBefore, Metrics.VISITORS.sum(),
            "the refusal happened after the visitor was already admitted: the early check in "
                + "SniRouter did not fire and the backstop in NodeGroup caught it instead");
        assertEquals(CEILING, appHits.get(), "the held visitors should all have reached the app");
        assertEquals(CEILING, hub.registry().get(node.machineKey()).visitorsInFlight(),
            "a refused visitor must not occupy a slot");

        // The point of the whole change: the node's own bound is still there and did not have to
        // fire. If this moves, the hub admitted someone it should have turned away.
        JsonObject status = Ipc.call(root.resolve("alice/jailscale.sock"),
            JsonObject.builder().put("cmd", "status").build());
        assertEquals(CEILING, status.integer("visitorCeiling"));
        assertEquals(0L, status.lng("visitorsRefused"),
            "the node refused a visitor, which means the hub let one through: " + status);
        assertEquals(CEILING, status.integer("visitorsInFlight"));

        release.countDown();
        for (Thread t : held) {
            t.join(30_000);
        }
        assertEquals(CEILING, appHits.get(), "the refused visitor reached the local app anyway");
    }

    /**
     * The hub sums what its nodes claim, and nothing validates the claim -- deliberately, since a
     * node that overstates only stops the hub refusing on its behalf and then resets what it cannot
     * take. The sum is the one place a claim reaches something other than its own node, so it is a
     * long: two nodes at Integer.MAX_VALUE wrapped an int sum negative and put a negative capacity
     * on the hub's public page.
     */
    @Test
    void twoNodesClaimingEverythingCannotWrapTheHubsCapacityNegative() throws Exception {
        node = new Daemon(NodeConfig.in(root.resolve("alice")).withTuning(NodeConfig.Tuning.defaults().visitorCeiling(Integer.MAX_VALUE)));
        node.start();
        joinAs(root.resolve("alice/jailscale.sock"), "alice");
        Daemon second = new Daemon(NodeConfig.in(root.resolve("bob")).withTuning(NodeConfig.Tuning.defaults().visitorCeiling(Integer.MAX_VALUE)));
        try {
            second.start();
            joinAs(root.resolve("bob/jailscale.sock"), "bob");
            waitFor(() -> hub.registry().size() == 2);
            long capacity = hub.registry().visitorCapacity();
            assertTrue(capacity >= 2L * Integer.MAX_VALUE, "the sum wrapped: " + capacity);
        } finally {
            second.close();
        }
    }

    private void joinAs(Path sock, String user) throws Exception {
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", user).put("caFile", CERT.toString()).build()).optBool("ok", false));
    }

    private interface Check {
        boolean ok() throws Exception;
    }

    private static void waitFor(Check c) throws Exception {
        long deadline = System.currentTimeMillis() + 20_000;
        while (System.currentTimeMillis() < deadline) {
            if (c.ok()) {
                return;
            }
            Thread.sleep(50);
        }
        throw new AssertionError("condition never held");
    }
}
