package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * DESIGN.md §7.7 hand-off and §8 multi-connection: a second hub takes over the same state
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
        localApp = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
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

    private HttpResponse visit(int port, String host) throws Exception {
        SSLContext ctx = Tls.clientContext(CERT, false);
        try (SSLSocket s = Tls.connect(ctx, host, "127.0.0.1", port, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, "/", null, null);
            return Http.readResponse(s.getInputStream(), 65536);
        }
    }

    @Test
    void takeoverKeepsInFlightStreamsAndServesNewVisitors() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = Files.createTempDirectory(Path.of("/tmp"), "jh");
        int port;
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test");
        old = new Hub(cfg);
        old.exitOnDrain = false;
        old.start();
        startSlowApp();

        alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        Path sock = root.resolve("alice/jailscale.sock");
        JsonObject up = Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).put("connections", 2).build());
        assertTrue(up.optBool("ok", false), up.toString());
        waitFor(() -> alice.hasCert(old.tls().keyId()));
        JsonObject open = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "slow").build());
        assertTrue(open.optBool("ok", false), open.toString());
        waitFor(() -> Ipc.call(sock, JsonObject.builder().put("cmd", "status").build()).integer("connections") == 2);
        assertEquals(2, old.registry().get(Ipc.call(sock, JsonObject.builder().put("cmd", "status").build()).string("machineKey")).connections());

        // A visitor whose response is still streaming when the hand-off happens.
        CompletableFuture<HttpResponse> inFlight = CompletableFuture.supplyAsync(() -> {
            try {
                return visit(port, "slow.hub.test");
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
        HttpResponse r = inFlight.get(20, TimeUnit.SECONDS);
        assertEquals(200, r.status());
        assertEquals("chunkchunkchunkchunkchunkchunk", r.bodyText());

        // The node has moved: registered with the new hub, link reopened, extras back up.
        waitFor(() -> fresh.registry().size() == 1 && fresh.links().byName("slow") != null);
        JsonObject st = Ipc.call(sock, JsonObject.builder().put("cmd", "status").build());
        assertTrue(st.optBool("connected", false), st.toString());
        waitFor(() -> Ipc.call(sock, JsonObject.builder().put("cmd", "status").build()).integer("connections") == 2);

        // New visitors are served by the new hub; nothing failed in between.
        assertEquals(200, visit(port, "slow.hub.test").status());

        // The old process drains to zero sessions.
        waitFor(() -> old.registry().liveSessions() == 0);
        waitFor(() -> Ipc.call(sock, JsonObject.builder().put("cmd", "status").build()).integer("draining") == 0);

        // Admin IPC now reaches the new hub.
        JsonObject status = Ipc.call(root.resolve("hub/jailhub.sock"), JsonObject.builder().put("cmd", "status").build());
        assertEquals(1, status.integer("online"));
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
            Thread.sleep(100);
        }
        throw new AssertionError("condition not met in time");
    }
}
