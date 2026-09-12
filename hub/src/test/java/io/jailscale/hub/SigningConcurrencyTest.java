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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

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
 * proof the serialisation is gone. A slow machine can only make this test take longer, never make
 * it pass by accident.
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
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.start();
        app = new ServerSocket(0, 512, InetAddress.getLoopbackAddress());
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

    @Test
    void signaturesForOneConnectionOverlap() throws Exception {
        startHubNodeAndLink();
        // Each visitor is a fresh TLS 1.3 session, so each costs the node one signature from the hub.
        // Resumption would not, which is why every one of these is a new context.
        int peak = 0;
        int rounds = 0;
        for (int round = 0; round < 3 && peak < 2; round++) {
            rounds++;
            assertEquals(VISITORS, burst(), "every visitor of a round should have been answered");
            peak = Math.max(peak, peakSignatures());
        }
        assertEquals(VISITORS * rounds, hits.get(), "every visitor should have reached the local app");
        assertTrue(peakSignatures() > 0, "no signature was requested at all; this test proved nothing");
        assertTrue(peak >= 2,
            "signing serialised on the mux reader: peak concurrent signatures was " + peak
                + ", so one visitor's handshake still blocks the whole connection");
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
