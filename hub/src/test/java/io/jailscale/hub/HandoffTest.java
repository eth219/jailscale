package io.jailscale.hub;

import com.sun.management.HotSpotDiagnosticMXBean;
import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import io.jailscale.proto.net.TestPorts;

/**
 * ARCHITECTURE.md §13 hand-off and §5.3 multi-connection: a second hub takes over the same state
 * directory and port while a visitor stream is in flight; the stream completes through the old
 * process, the node reconnects to the new one, and new visitors are served with no failure.
 */
@Timeout(120)
class HandoffTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub old;
    private Hub fresh;
    private Path sock;
    private Daemon alice;
    private ServerSocket localApp;

    @AfterEach
    void stop() throws Exception {
        if (alice != null) {
            alice.close();
        }
        if (localApp != null) {
            localApp.close();
        }
        if (fresh != null) {
            fresh.close();
        }
        if (old != null) {
            old.close();
        }
    }

    /** A local app whose response body trickles out over ~1.5 s. */
    private void startSlowApp() throws IOException {
        localApp = TestPorts.listen(8);
        Thread.ofVirtual().start(() -> {
            while (!localApp.isClosed()) {
                try {
                    Socket c = localApp.accept();
                    Thread.ofVirtual().start(() -> {
                        try (c) {
                            Http.readRequest(c.getInputStream(), 4096);
                            OutputStream out = c.getOutputStream();
                            out.write("HTTP/1.1 200 OK\r\nContent-Length: 30\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
                            for (int i = 0; i < 6; i++) {
                                out.write("chunk".getBytes(StandardCharsets.ISO_8859_1));
                                out.flush();
                                Thread.sleep(250);
                            }
                        } catch (Exception ignored) {
                            // visitor gone
                        }
                    });
                } catch (IOException e) {
                    return;
                }
            }
        });
    }

    /**
     * The body trickles out over ~1.5 s, and a visitor arriving right after a hand-off also pays
     * for a TLS handshake with a signing round-trip. A shared CI runner stretches all of that, so
     * the per-read budget is generous; {@code @Timeout(120)} on the test still catches a real hang.
     */
    private HttpResponse visit(int port, String host) throws Exception {
        SSLContext ctx = Tls.clientContext(CERT, false);
        try (SSLSocket s = Tls.connect(ctx, host, "127.0.0.1", port, true, 30_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, "/", null, null);
            return Http.readResponse(s.getInputStream(), 65536);
        }
    }

    @Test
    void takeoverKeepsInFlightStreamsAndServesNewVisitors() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jh");
        int port;
            port = TestPorts.reserve();
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test");
        old = new Hub(cfg);
        old.exitOnDrain = false;
        old.start();
        startSlowApp();

        alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        sock = root.resolve("alice/jailscale.sock");
        JsonObject up = Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).put("connections", 2).build());
        assertTrue(up.optBool("ok", false), up.toString());
        waitFor("node never received the certificate", () -> alice.hasCert(old.tls().keyId()));
        JsonObject open = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "slow").build());
        assertTrue(open.optBool("ok", false), open.toString());
        waitFor("node did not open both connections before the hand-off",
            () -> Ipc.call(sock, JsonObject.builder().put("cmd", "status").build()).integer("connections") == 2);
        assertEquals(2, old.registry().get(Ipc.call(sock, JsonObject.builder().put("cmd", "status").build()).string("machineKey")).connections());

        // A visitor whose response is still streaming when the hand-off happens.
        Progress progress = new Progress();
        CompletableFuture<HttpResponse> inFlight = CompletableFuture.supplyAsync(() -> {
            try {
                return visitTracking(port, "slow.hub.test", progress);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        Thread.sleep(400); // the stream is open and trickling

        // The new hub takes over the same state directory and port.
        fresh = new Hub(cfg, true);
        fresh.exitOnDrain = false;
        fresh.start();
        assertTrue(old.isHandingOff());

        // The in-flight response completes through the old process.
        HttpResponse r;
        try {
            r = inFlight.get(20, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new AssertionError(state("in-flight response never finished through the draining connection ["
                + progress + "]"), e);
        }
        assertEquals(200, r.status());
        assertEquals("chunkchunkchunkchunkchunkchunk", r.bodyText());

        // The node has moved: registered with the new hub, link reopened, extras back up.
        waitFor("node did not re-register and reopen its link on the new hub",
            () -> fresh.registry().size() == 1 && fresh.links().byName("slow") != null);
        JsonObject st = Ipc.call(sock, JsonObject.builder().put("cmd", "status").build());
        assertTrue(st.optBool("connected", false), st.toString());
        waitFor("node did not restore both connections after the hand-off",
            () -> Ipc.call(sock, JsonObject.builder().put("cmd", "status").build()).integer("connections") == 2);

        // New visitors are served by the new hub; nothing failed in between.
        assertEquals(200, visit(port, "slow.hub.test").status());

        // The old process drains to zero sessions.
        waitFor("old hub never drained to zero sessions", () -> old.registry().liveSessions() == 0);
        waitFor("node still holds a draining connection",
            () -> Ipc.call(sock, JsonObject.builder().put("cmd", "status").build()).integer("draining") == 0);

        // Admin IPC now reaches the new hub.
        JsonObject status = Ipc.call(root.resolve("hub/jailhub.sock"), JsonObject.builder().put("cmd", "status").build());
        assertEquals(1, status.integer("online"));
    }

    /** How far the in-flight visitor got, for a stall that has to say where it stopped. */
    private static final class Progress {
        private volatile String stage = "not started";
        private volatile int bytes;
        private volatile long lastByteAt;

        @Override
        public String toString() {
            return stage + ", " + bytes + " byte(s) read"
                + (lastByteAt == 0 ? ", none ever arrived"
                    : ", last " + (System.currentTimeMillis() - lastByteAt) + " ms ago");
        }
    }

    /** {@link #visit} with a running tally of what came back. */
    private HttpResponse visitTracking(int port, String host, Progress p) throws Exception {
        SSLContext ctx = Tls.clientContext(CERT, false);
        try (SSLSocket s = Tls.connect(ctx, host, "127.0.0.1", port, true, 30_000)) {
            p.stage = "TLS established";
            Http.writeRequest(s.getOutputStream(), "GET", host, "/", null, null);
            p.stage = "request sent, nothing back yet";
            InputStream counted = new FilterInputStream(s.getInputStream()) {
                @Override
                public int read() throws IOException {
                    int c = super.read();
                    if (c >= 0) {
                        record(1);
                    }
                    return c;
                }

                @Override
                public int read(byte[] b, int off, int len) throws IOException {
                    int n = super.read(b, off, len);
                    if (n > 0) {
                        record(n);
                    }
                    return n;
                }

                private void record(int n) {
                    p.bytes += n;
                    p.lastByteAt = System.currentTimeMillis();
                    p.stage = "reading response";
                }
            };
            HttpResponse r = Http.readResponse(counted, 65536);
            p.stage = "complete";
            return r;
        }
    }

    private interface Check {
        boolean ok() throws Exception;
    }

    private void waitFor(String what, Check c) throws Exception {
        long deadline = System.currentTimeMillis() + 20_000;
        while (System.currentTimeMillis() < deadline) {
            if (c.ok()) {
                return;
            }
            Thread.sleep(100);
        }
        throw new AssertionError(state(what));
    }

    /**
     * Both halves of the hand-off, for a wait that ran out. A bare TimeoutException says only that
     * something stalled; this says which side still thinks it owns the stream. Adding the same kind
     * of detail to RawPortTest turned "missing field 'hubPort'" into "port-bind-failed" in one run.
     */
    private String state(String what) {
        StringBuilder b = new StringBuilder(what);
        // The JDK build decided the last stall: 25.0.0-25.0.2 lose timed virtual-thread wake-ups
        // (JDK-8370887), so a dump that does not say which JDK it came from cannot be compared.
        b.append(" | jvm ").append(System.getProperty("java.vm.version"))
            .append(" cpus=").append(Runtime.getRuntime().availableProcessors());
        try {
            b.append(" | old: handingOff=").append(old.isHandingOff())
                .append(" liveSessions=").append(old.registry().liveSessions())
                .append(" registry=").append(old.registry().size());
        } catch (Exception e) {
            b.append(" | old unreadable: ").append(e);
        }
        try {
            b.append(" | fresh: ").append(fresh == null ? "not started"
                : "registry=" + fresh.registry().size() + " slowLink=" + (fresh.links().byName("slow") != null));
        } catch (Exception e) {
            b.append(" | fresh unreadable: ").append(e);
        }
        try {
            b.append(" | node: ").append(Ipc.call(sock, JsonObject.builder().put("cmd", "status").build()));
        } catch (Exception e) {
            b.append(" | node unreadable: ").append(e);
        }
        b.append(" | stuck threads: ").append(stacks());
        return b.toString();
    }

    /**
     * Every thread whose stack touches jailscale code, virtual ones included.
     * {@code Thread.getAllStackTraces()} lists platform threads only, and everything carrying a
     * stream here is virtual, so the first version of this reported "none" and taught us nothing.
     */
    private static String stacks() {
        try {
            Path dir = Files.createTempDirectory("threaddump");
            Path out = dir.resolve("threads.txt");
            ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class)
                .dumpThreads(out.toString(), HotSpotDiagnosticMXBean.ThreadDumpFormat.TEXT_PLAIN);
            StringBuilder b = new StringBuilder();
            for (String block : Files.readString(out).split("\n\n")) {
                if (block.contains("io.jailscale")) {
                    b.append("\n    ").append(block.strip().replace("\n", "\n    "));
                }
            }
            Files.deleteIfExists(out);
            Files.deleteIfExists(dir);
            return b.length() == 0 ? "none" : b.toString();
        } catch (Exception e) {
            return "unavailable: " + e;
        }
    }
}
