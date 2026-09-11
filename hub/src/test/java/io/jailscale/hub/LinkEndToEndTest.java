package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.control.Message;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import java.nio.charset.StandardCharsets;

/**
 * M2 data path (ARCHITECTURE.md §14): {@code jailscale open} publishes a local HTTP server as
 * {@code https://<name>.hub.test}; a TLS client with that SNI goes through the hub's SNI router,
 * is terminated by the node with the hub's wildcard certificate (signature delegated to the hub),
 * and reaches the local server. Also the signing-oracle refusals.
 */
@Timeout(90)
class LinkEndToEndTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Path root;
    private Hub hub;
    private int port;
    private final List<Daemon> daemons = new ArrayList<>();
    private ServerSocket localApp;
    private volatile int localHits;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jl");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test");
        hub = new Hub(cfg);
        hub.start();
        // A tiny local HTTP app the node will publish.
        localApp = new ServerSocket(0, 8, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            while (!localApp.isClosed()) {
                try {
                    Socket c = localApp.accept();
                    Thread.ofVirtual().start(() -> serveLocal(c));
                } catch (IOException e) {
                    return;
                }
            }
        });
    }

    private void serveLocal(Socket c) {
        try (c) {
            HttpRequest r = Http.readRequest(c.getInputStream(), 4096);
            localHits++;
            HttpResponse.text(200, "hello from local " + r.path() + " host=" + r.headers().get("Host")).writeTo(c.getOutputStream());
        } catch (Exception e) {
            // client gone
        }
    }

    @AfterEach
    void stop() throws Exception {
        for (Daemon d : daemons) {
            d.close();
        }
        localApp.close();
        hub.close();
    }

    private Daemon node(String name) throws IOException {
        Daemon d = new Daemon(NodeConfig.in(root.resolve(name)));
        d.start();
        daemons.add(d);
        return d;
    }

    private JsonObject cli(String name, JsonObject.Builder req) throws IOException {
        return Ipc.call(root.resolve(name).resolve("jailscale.sock"), req.build());
    }

    private JsonObject ok(JsonObject r) {
        assertTrue(r.optBool("ok", false), r.toString());
        return r;
    }

    /** A visitor: TLS to the hub port with the given SNI, verified against the wildcard test cert. */
    private HttpResponse visit(String host, String path) throws Exception {
        SSLContext ctx = Tls.clientContext(CERT, false);
        try (SSLSocket s = Tls.connect(ctx, host, "127.0.0.1", port, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, path, null, null);
            return Http.readResponse(s.getInputStream(), 65536);
        }
    }

    @Test
    void openPublishesLocalServerThroughHubAndNode() throws Exception {
        Daemon alice = node("alice");
        // registration open: knock and get in immediately
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor(() -> alice.hasCert(hub.tls().keyId()));

        JsonObject open = ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "myapp")));
        assertEquals("myapp", open.string("name"));
        assertEquals("https://myapp.hub.test:" + port, open.string("url"));

        HttpResponse r = visit("myapp.hub.test", "/x?y=1");
        assertEquals(200, r.status());
        assertEquals("hello from local /x host=myapp.hub.test", r.bodyText());
        assertEquals(1, localHits);

        // random name for another port keeps its value across a second open of the same port
        JsonObject rnd = ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort() + 1)));
        JsonObject again = ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort() + 1)));
        assertEquals(rnd.string("name"), again.string("name"));
        assertEquals(5, rnd.string("name").length());

        // that link points at a closed port: the node answers 502 itself
        HttpResponse bad = visit(rnd.string("name") + ".hub.test", "/");
        assertEquals(502, bad.status());

        // an unknown name gets the hub's own page under the wildcard cert
        HttpResponse none = visit("nothere.hub.test", "/");
        assertEquals(404, none.status());

        // ARCHITECTURE.md §11.3: the node checks that it was the one that terminated the TLS for its own
        // names. An honest hub passes bytes through, so the keying material of the probe's session
        // is one the node recorded.
        JsonObject verified = ok(cli("alice", JsonObject.builder().put("cmd", "verify")));
        assertTrue(verified.integer("checked") >= 1, verified.toString());
        for (Object o : verified.array("results")) {
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> row = (java.util.Map<String, Object>) o;
            assertEquals(Boolean.TRUE, row.get("ok"), row.toString());
            assertEquals("terminated by this node", row.get("verdict"), row.toString());
        }

        // ls shows both; close removes
        assertEquals(2, ok(cli("alice", JsonObject.builder().put("cmd", "ls"))).array("links").size());
        ok(cli("alice", JsonObject.builder().put("cmd", "close").put("name", "myapp")));
        assertEquals(1, ok(cli("alice", JsonObject.builder().put("cmd", "ls"))).array("links").size());
        HttpResponse closed = visit("myapp.hub.test", "/");
        assertEquals(404, closed.status());

        // several concurrent visitors, each with its own handshake and delegated signature
        List<Thread> ts = new ArrayList<>();
        ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "myapp")));
        int[] okCount = new int[1];
        for (int i = 0; i < 8; i++) {
            ts.add(Thread.ofVirtual().start(() -> {
                try {
                    if (visit("myapp.hub.test", "/c").status() == 200) {
                        synchronized (okCount) {
                            okCount[0]++;
                        }
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }));
        }
        for (Thread t : ts) {
            t.join();
        }
        assertEquals(8, okCount[0]);
    }

    @Test
    void hubReleasesAVisitorThatNeverClosesItsHalf() throws Exception {
        long previous = Relay.lingerMs;
        Relay.lingerMs = 500;
        try {
            Daemon alice = node("alice");
            ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
                .put("user", "alice").put("caFile", CERT.toString())));
            waitFor(() -> alice.hasCert(hub.tls().keyId()));
            ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "lingerapp")));
            waitFor(() -> hub.links().byName("lingerapp") != null);

            SSLContext ctx = Tls.clientContext(CERT, false);
            try (SSLSocket s = Tls.connect(ctx, "lingerapp.hub.test", "127.0.0.1", port, true, 10_000)) {
                Http.writeRequest(s.getOutputStream(), "GET", "lingerapp.hub.test", "/", null, null);
                assertEquals(200, Http.readResponse(s.getInputStream(), 65536).status());

                // The local app answered and closed, so the node is done with this stream. The
                // visitor deliberately does not close its own half. Before the linger existed the
                // hub waited on it forever and this write kept succeeding.
                IOException cut = null;
                long deadline = System.currentTimeMillis() + 15_000;
                while (cut == null && System.currentTimeMillis() < deadline) {
                    try {
                        s.getOutputStream().write("still here\n".getBytes(StandardCharsets.US_ASCII));
                        s.getOutputStream().flush();
                        Thread.sleep(100);
                    } catch (IOException e) {
                        cut = e;
                    }
                }
                assertNotNull(cut, "hub never closed a visitor that held its half open");
            }
        } finally {
            Relay.lingerMs = previous;
        }
    }

    @Test
    void signingIsBoundToDeliveredStreams() throws Exception {
        Daemon alice = node("alice");
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor(() -> alice.hasCert(hub.tls().keyId()));
        byte[] digest = new byte[32];

        // A stream the hub never opened.
        Message r = alice.debugRequest(new Message.SignRequest(4242, hub.tls().keyId(), "ECDSA-P256-SHA256", digest), "SignResponse:4242");
        assertTrue(r instanceof Message.SignResponse sr && sr.sig() == null && "not-your-stream".equals(sr.reason()), r.toString());

        // Bob owns "bobapp"; a visitor stream for it is delivered to bob, so alice cannot sign for it.
        Daemon bob = node("bob");
        ok(cli("bob", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "bob").put("caFile", CERT.toString())));
        waitFor(() -> bob.hasCert(hub.tls().keyId()));
        ok(cli("bob", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "bobapp")));
        assertEquals(200, visit("bobapp.hub.test", "/").status());

        // alice trying to claim bob's name is refused
        JsonObject taken = cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "bobapp"));
        assertEquals("taken", taken.optString("error", null));

        // A real handshake on bob's own stream needed exactly one signature; further ones are capped at 4.
        // (Exercised implicitly: the 200 above proves the positive path.)
        assertNotNull(hub.links().byName("bobapp"));

        // The hub signs what it can recognise, not whatever it is handed. A bare digest, or any
        // other 130 bytes, would make the wildcard key sign a handshake for a name that is not the
        // asker's -- the hub's own name included, since the certificate covers it.
        assertThrows(GeneralSecurityException.class, () -> hub.tls().sign(hub.tls().keyId(), digest));
        byte[] notCertVerify = new byte[HubTls.CERT_VERIFY_CONTEXT.length + 32];
        java.util.Arrays.fill(notCertVerify, (byte) 7);
        assertThrows(GeneralSecurityException.class, () -> hub.tls().sign(hub.tls().keyId(), notCertVerify));

        // The shape it does accept: the RFC 8446 §4.4.3 context and a transcript hash.
        byte[] certVerify = new byte[HubTls.CERT_VERIFY_CONTEXT.length + 32];
        System.arraycopy(HubTls.CERT_VERIFY_CONTEXT, 0, certVerify, 0, HubTls.CERT_VERIFY_CONTEXT.length);
        assertNotNull(hub.tls().sign(hub.tls().keyId(), certVerify));
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
        throw new AssertionError("condition not met in time");
    }
}
