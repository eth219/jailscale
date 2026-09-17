package io.jailscale.hub;

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
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;

/**
 * Scratch measurement, not a gate: what one name saturating a node does to the other names on it.
 *
 * <p>A node serves at most {@code Visitors.MAX_IN_FLIGHT} visitors (ARCHITECTURE.md §9.3) and may
 * serve up to {@code Links.MAX_LINKS_PER_NODE} = 20 names. Nothing shares the bound between them,
 * so the hub admits first come, first served and a name that fills the node can leave the others
 * with nothing. §15 records that as a limit; what it does not say is how bad it is, because
 * "starved" here is not one behaviour. A slot comes back when a visitor finishes, so the question
 * is entirely about how long the busy name's visitors hold theirs:
 *
 * <ul>
 *   <li><b>Short</b>: the busy name serves ordinary request/response traffic and releases slots in
 *       milliseconds. The other names should see delay, not blackout.
 *   <li><b>Long</b>: the busy name holds its connections — a download, a websocket, a stalled
 *       reader. Slots do not come back and the other names should see blackout.
 * </ul>
 *
 * <p>The two are different products. One argues for doing nothing and writing the number down; the
 * other argues for reserving a few slots per name. This exists to say which one is real, and the
 * answer is in README.md beside it.
 *
 * <p>Deliberately on the JVM and outside the source root, like {@code docs/mux-saturation}. What it
 * measures is an admission rule in the hub, which is the same code the native binaries run, and the
 * visitor counts here are small enough that the node's heap never enters into it. What it therefore
 * cannot see is anything that only appears at the shipped ceiling of 450.
 *
 * <pre>
 * ./mvnw -q -pl hub -am test-compile -DskipTests
 * m=~/.m2/repository/org
 * CP=hub/target/classes:node/target/classes:proto/target/classes:crypto/target/classes
 * javac -cp "$CP" -d /tmp/sm docs/name-starvation/StarvationMeasure.java
 * (cd hub &amp;&amp; java -cp "/tmp/sm:../hub/target/classes:../node/target/classes:../proto/target/classes:../crypto/target/classes" \
 *    io.jailscale.hub.StarvationMeasure)
 * </pre>
 *
 * <p>It runs from the {@code hub} directory because it reads the test certificate from
 * {@code src/test/resources/tls}. {@code -Dstarvation.ceiling=} sets the node's bound (default 20,
 * small so that saturating it is cheap); {@code -Dstarvation.probes=} how many times the quiet name
 * is tried in each phase; {@code -Dstarvation.seconds=} how long the short phase keeps the pressure
 * up.
 */
public final class StarvationMeasure {

    private static final int CEILING = Integer.getInteger("starvation.ceiling", 20);
    private static final int PROBES = Integer.getInteger("starvation.probes", 40);
    private static final int SECONDS = Integer.getInteger("starvation.seconds", 5);

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;
    private Daemon node;

    /** A local app behind one name. Answers at once, or holds until released. */
    private static final class App {
        final ServerSocket socket;
        final AtomicInteger hits = new AtomicInteger();
        final CountDownLatch release;

        App(boolean hold) throws IOException {
            this.socket = new ServerSocket(0, 256, InetAddress.getLoopbackAddress());
            this.release = new CountDownLatch(hold ? 1 : 0);
            Thread.ofVirtual().start(() -> {
                while (!socket.isClosed()) {
                    try {
                        Socket c = socket.accept();
                        Thread.ofVirtual().start(() -> serve(c));
                    } catch (IOException e) {
                        return;
                    }
                }
            });
        }

        private void serve(Socket c) {
            try (c) {
                HttpRequest r = Http.readRequest(c.getInputStream(), 4096);
                hits.incrementAndGet();
                release.await();
                HttpResponse.text(200, "ok " + r.path()).writeTo(c.getOutputStream());
            } catch (Exception e) {
                // visitor gone
            }
        }
    }

    public static void main(String[] args) throws Exception {
        StarvationMeasure m = new StarvationMeasure();
        try {
            m.run();
        } finally {
            m.stop();
        }
    }

    private void run() throws Exception {
        Log.setLevel(Log.Level.WARN);
        root = Files.createTempDirectory(Path.of("/tmp"), "starve");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.start();

        System.out.printf("node bound %d visitors, two names on it%n%n", CEILING);

        // Phase 1: the busy name holds its visitors. Slots never come back.
        App holdHot = new App(true);
        App holdCold = new App(false);
        join(holdHot, holdCold, "hot", "cold");
        List<Thread> held = new ArrayList<>();
        CountDownLatch inFlight = new CountDownLatch(CEILING);
        for (int i = 0; i < CEILING; i++) {
            held.add(holder("hot", i, inFlight));
        }
        inFlight.await();
        waitFor(() -> holdHot.hits.get() == CEILING);
        report("long  (the busy name holds its connections)", probe("cold"));
        holdHot.release.countDown();
        for (Thread t : held) {
            t.join(10_000);
        }
        node.close();
        holdHot.socket.close();
        holdCold.socket.close();

        // Phase 2: the busy name answers and releases, continuously, on a fresh node.
        App fastHot = new App(false);
        App fastCold = new App(false);
        // Fresh names as well as a fresh node: the hub keeps a name claimed after the node that
        // opened it goes away, so reusing them here comes back "taken".
        join(fastHot, fastCold, "hot2", "cold2");
        AtomicBoolean stop = new AtomicBoolean();
        List<Thread> load = new ArrayList<>();
        for (int i = 0; i < CEILING; i++) {
            load.add(pounder("hot2", stop));
        }
        Thread.sleep(500); // let the pressure build before probing
        Result r = probe("cold2");
        stop.set(true);
        for (Thread t : load) {
            t.join(10_000);
        }
        report("short (the busy name answers and releases)", r);
        System.out.printf("%n  the busy name served %d requests during the short phase%n", fastHot.hits.get());
        fastHot.socket.close();
        fastCold.socket.close();
    }

    private record Result(int served, int refused, long minMs, long maxMs) {}

    private static void report(String label, Result r) {
        System.out.printf("  %-46s %3d/%d served, %3d refused", label, r.served(), r.served() + r.refused(), r.refused());
        if (r.served() > 0) {
            System.out.printf(", %d-%d ms", r.minMs(), r.maxMs());
        }
        System.out.println();
    }

    /** Joins a node with the given bound and opens two names on it: hot and cold. */
    private void join(App hot, App cold, String hotName, String coldName) throws Exception {
        Path home = root.resolve("n" + System.nanoTime());
        node = new Daemon(NodeConfig.in(home).withTuning(NodeConfig.Tuning.defaults().visitorCeiling(CEILING)));
        node.start();
        Path sock = home.resolve("jailscale.sock");
        ok(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "u" + System.nanoTime()).put("caFile", CERT.toString()).build()));
        waitFor(() -> node.hasCert(hub.tls().keyId()));
        ok(Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", hot.socket.getLocalPort()).put("name", hotName).build()));
        ok(Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", cold.socket.getLocalPort()).put("name", coldName).build()));
    }

    private static void ok(JsonObject r) {
        if (!r.optBool("ok", false)) {
            throw new IllegalStateException(r.toString());
        }
    }

    /** One visitor that sends its request and stays. */
    private Thread holder(String name, int n, CountDownLatch arrived) {
        return Thread.ofVirtual().start(() -> {
            try (SSLSocket s = visitorSocket(name)) {
                Http.writeRequest(s.getOutputStream(), "GET", name + ".hub.test", "/h" + n, null, null);
                arrived.countDown();
                Http.readResponse(s.getInputStream(), 4096);
            } catch (Exception e) {
                arrived.countDown();
            }
        });
    }

    /** A visitor that asks, reads the answer, and comes straight back. */
    private Thread pounder(String name, AtomicBoolean stop) {
        return Thread.ofVirtual().start(() -> {
            while (!stop.get()) {
                try (SSLSocket s = visitorSocket(name)) {
                    Http.writeRequest(s.getOutputStream(), "GET", name + ".hub.test", "/p", null, null);
                    Http.readResponse(s.getInputStream(), 4096);
                } catch (Exception e) {
                    // refused: the node is full. Come back anyway, which is what a client does.
                }
            }
        });
    }

    /** Tries the quiet name {@code PROBES} times, one at a time, and counts what happened. */
    private Result probe(String name) {
        int served = 0;
        int refused = 0;
        long min = Long.MAX_VALUE;
        long max = 0;
        long deadline = System.currentTimeMillis() + SECONDS * 1000L;
        for (int i = 0; i < PROBES && System.currentTimeMillis() < deadline; i++) {
            long t0 = System.nanoTime();
            try (SSLSocket s = visitorSocket(name)) {
                Http.writeRequest(s.getOutputStream(), "GET", name + ".hub.test", "/c" + i, null, null);
                HttpResponse r = Http.readResponse(s.getInputStream(), 4096);
                if (r.status() == 200) {
                    long ms = (System.nanoTime() - t0) / 1_000_000;
                    served++;
                    min = Math.min(min, ms);
                    max = Math.max(max, ms);
                } else {
                    refused++;
                }
            } catch (Exception e) {
                refused++;
            }
        }
        return new Result(served, refused, served == 0 ? 0 : min, max);
    }

    private SSLSocket visitorSocket(String name) throws Exception {
        SSLContext ctx = Tls.clientContext(CERT, false);
        SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket();
        s.connect(new InetSocketAddress("127.0.0.1", port), 10_000);
        SSLParameters p = s.getSSLParameters();
        p.setServerNames(List.of(new SNIHostName(name + ".hub.test")));
        s.setSSLParameters(p);
        s.setSoTimeout(15_000);
        s.startHandshake();
        return s;
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
            Thread.sleep(25);
        }
        throw new IllegalStateException("condition never held");
    }

    private void stop() {
        try {
            if (node != null) {
                node.close();
            }
            if (hub != null) {
                hub.close();
            }
        } catch (Exception e) {
            // going away
        }
    }
}
