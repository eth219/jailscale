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
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * ARCHITECTURE.md §14: 1,000 concurrent visitors through hub → node → local app, all holding their
 * connection open at the same time, then a short throughput burst. Correctness (every visitor
 * gets its answer) and timing are asserted loosely; the memory budget is measured on the native
 * binaries by {@code measure.sh LOAD=1000}, not here. Excluded from the default build:
 * {@code ./mvnw -pl hub test -Dgroups=load -Dtest.excludedGroups=}.
 */
@Tag("load")
@Timeout(300)
class LoadTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
    private static final int VISITORS = Integer.getInteger("load.visitors", 1000);

    /** The ramp, matching {@code tools/hold-visitors.py}: the two harnesses should arrive alike. */
    private static final int ARRIVAL_BATCH = Integer.getInteger("load.arrivalBatch", 100);
    private static final long ARRIVAL_PAUSE_MS = Long.getLong("load.arrivalPauseMs", 50);

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
        hub.close();
        app.close();
    }

    private void serveApp(Socket c) {
        try (c) {
            HttpRequest r = Http.readRequest(c.getInputStream(), 4096);
            hits.incrementAndGet();
            HttpResponse.text(200, "ok " + r.path()).writeTo(c.getOutputStream());
        } catch (Exception e) {
            // visitor gone
        }
    }

    /** 1,000 SYNs at once overflow a 128-entry listen backlog (macOS default); a browser would retry, so do we. */
    private SSLSocket connectWithRetry(SSLContext ctx) throws IOException {
        for (int attempt = 0; ; attempt++) {
            try {
                return Tls.connect(ctx, "loadtest.hub.test", "127.0.0.1", port, true, 30_000);
            } catch (java.net.SocketException e) {
                if (attempt == 2) {
                    throw e;
                }
                try {
                    Thread.sleep(100L << attempt);
                } catch (InterruptedException ie) {
                    throw e;
                }
            }
        }
    }

    @Test
    void thousandConcurrentVisitors() throws Exception {
        Log.setLevel(Log.Level.INFO);
        root = TestDirs.newRoot("jload");
            port = TestPorts.reserve();
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.start();
        app = TestPorts.listen(1024);
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
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).put("connections", 2).build()).optBool("ok", false));
        long deadline = System.currentTimeMillis() + 10_000;
        while (!node.hasCert(hub.tls().keyId()) && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", app.getLocalPort()).put("name", "loadtest").build())
            .optBool("ok", false));

        // Phase 1: everyone connects and handshakes, then everyone holds the connection until all are in.
        SSLContext ctx = Tls.clientContext(CERT, false);
        CountDownLatch allConnected = new CountDownLatch(VISITORS);
        CountDownLatch release = new CountDownLatch(1);
        List<Thread> threads = new ArrayList<>();
        AtomicInteger okCount = new AtomicInteger();
        List<String> failures = new java.util.concurrent.CopyOnWriteArrayList<>();
        long t0 = System.nanoTime();
        for (int i = 0; i < VISITORS; i++) {
            // Arrivals are ramped, in the same batches tools/hold-visitors.py uses for the native
            // measurement. What §14 claims is a thousand visitors HELD at once, and the two
            // harnesses should arrive alike; this one was the outlier, starting all thousand in a
            // tight loop.
            //
            // MEASURED, because this test was flaky from the day it was written and nobody saw it
            // until it went into CI: unramped it fails 3 runs in 10 on this machine, ramped 0 in
            // 10, and it failed on main the first week it was gated. The failures are connection
            // resets, terminated handshakes and "no response" EOFs, in that mixture, with the hub
            // and the node saying nothing at DEBUG beyond one "visitor -> node ended: Socket
            // closed" -- so nothing refused anything and no bound was reached.
            //
            // WHAT IS NOT ESTABLISHED is the mechanism. connectWithRetry's comment below says the
            // listen backlog overflows -- the hub asks for 1024 and the kernel caps it at
            // somaxconn, 128 on macOS -- and that is the obvious candidate, but the kernel does not
            // agree: `netstat -s -p tcp` showed "listen queue overflow" at 0 before and after a
            // failing run. So the burst is the trigger and the ramp removes it, and why is open.
            // Reproduce either way with -Dload.arrivalBatch= and -Dload.arrivalPauseMs=.
            if (i > 0 && i % ARRIVAL_BATCH == 0) {
                Thread.sleep(ARRIVAL_PAUSE_MS);
            }
            int n = i;
            threads.add(Thread.ofVirtual().start(() -> {
                try (SSLSocket s = connectWithRetry(ctx)) {
                    s.setSoTimeout(120_000);
                    s.startHandshake();
                    allConnected.countDown();
                    release.await();
                    Http.writeRequest(s.getOutputStream(), "GET", "loadtest.hub.test", "/v" + n, null, null);
                    HttpResponse r = Http.readResponse(s.getInputStream(), 4096);
                    if (r.status() == 200 && r.bodyText().equals("ok /v" + n)) {
                        okCount.incrementAndGet();
                    } else {
                        failures.add("visitor " + n + ": " + r.status());
                    }
                } catch (Exception e) {
                    allConnected.countDown();
                    failures.add("visitor " + n + ": " + e);
                }
            }));
        }
        assertTrue(allConnected.await(120, java.util.concurrent.TimeUnit.SECONDS), "not all visitors connected");
        long handshakes = (System.nanoTime() - t0) / 1_000_000;
        int open = hub.registry().get(node.machineKey()).all().stream().mapToInt(s -> s.mux().streamCount()).sum();
        release.countDown();
        for (Thread t : threads) {
            t.join();
        }
        long total = (System.nanoTime() - t0) / 1_000_000;
        System.out.printf("load: %d visitors, %d handshakes in %d ms (%.1f ms each, %d streams open at peak), all done in %d ms%n",
            VISITORS, VISITORS - failures.size(), handshakes, handshakes / (double) VISITORS, open, total);
        assertTrue(failures.isEmpty(), () -> failures.size() + " failures, first: " + failures.get(0));
        assertEquals(VISITORS, okCount.get());
        assertTrue(open >= VISITORS * 9 / 10, "expected ~" + VISITORS + " concurrent streams, saw " + open);

        // Phase 2: throughput with bounded concurrency (100 workers), each request a fresh handshake.
        int burst = VISITORS * 2;
        AtomicInteger burstOk = new AtomicInteger();
        java.util.concurrent.ConcurrentHashMap<String, Integer> burstErrors = new java.util.concurrent.ConcurrentHashMap<>();
        AtomicInteger next = new AtomicInteger();
        List<Thread> bt = new ArrayList<>();
        long b0 = System.nanoTime();
        for (int w = 0; w < 100; w++) {
            bt.add(Thread.ofVirtual().start(() -> {
                while (next.getAndIncrement() < burst) {
                    try (SSLSocket s = Tls.connect(ctx, "loadtest.hub.test", "127.0.0.1", port, true, 30_000)) {
                        Http.writeRequest(s.getOutputStream(), "GET", "loadtest.hub.test", "/b", null, null);
                        int st = Http.readResponse(s.getInputStream(), 4096).status();
                        if (st == 200) {
                            burstOk.incrementAndGet();
                        } else {
                            burstErrors.merge("HTTP " + st, 1, Integer::sum);
                        }
                    } catch (Exception e) {
                        burstErrors.merge(e.getClass().getSimpleName() + ": " + e.getMessage(), 1, Integer::sum);
                    }
                }
            }));
        }
        for (Thread t : bt) {
            t.join();
        }
        long bms = (System.nanoTime() - b0) / 1_000_000;
        System.out.printf("burst: %d/%d requests in %d ms (%.0f req/s)%n", burstOk.get(), burst, bms, burst * 1000.0 / bms);
        assertTrue(burstOk.get() >= burst * 99 / 100, "burst failures: " + (burst - burstOk.get()) + " " + burstErrors);

        // Nothing leaked: streams and visitor bookkeeping are back to idle.
        Thread.sleep(500);
        int after = hub.registry().get(node.machineKey()).all().stream().mapToInt(s -> s.mux().streamCount()).sum();
        assertTrue(after <= 2, "streams still open after load: " + after);
    }
}
