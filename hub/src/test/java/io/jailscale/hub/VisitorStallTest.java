package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * ARCHITECTURE.md §9.3: a visitor that takes a slot and then says nothing has to lose it.
 *
 * <p>The node bounds how many visitors it serves at once, and nothing used to bound how long one
 * could hold a place in that bound without finishing its handshake -- the reads underneath wait for
 * ever. So a ClientHello good enough for the hub to route, followed by silence, kept tens of
 * kilobytes of TLS state and one of {@code maxInFlight} slots for the life of the process. At the
 * hub's 64 connections per address that is eight addresses to take a 450-visitor node dark on every
 * name it serves, which is cheaper than any of the abuse §11.5 meters.
 *
 * <p>The node here holds <b>one</b> visitor, so the held slot is the whole node and a second visitor
 * being refused is the same evidence a 450th would be, without opening 450 connections. Its
 * first-byte deadline is {@link #DEADLINE_MS} rather than the shipped thirty seconds for the same
 * reason. Both come through the {@code Daemon} constructor that exists for it.
 */
@Timeout(90)
class VisitorStallTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
    /**
     * Long enough that everything before the refusal assertion -- the ClientHello, the node's
     * handshake with its signature round trip to the hub, and a second whole TLS connection --
     * cannot run past it on a loaded runner. At 1,500 that was about 300 ms of budget locally and a
     * five-times-slower window would have released the slot early, failing the assertion with a
     * message about the bound rather than about the clock. The test costs roughly this much wall
     * time, which is what it takes for the deadline itself to expire.
     */
    private static final long DEADLINE_MS = 8_000;

    private Path root;
    private Hub hub;
    private int port;
    private final List<Daemon> daemons = new ArrayList<>();
    private ServerSocket localApp;
    /** A port nothing is listening on, for the one case whose link has to answer 502 instead. */
    private int deadPort;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        root = TestDirs.newRoot("jstall");
            port = TestPorts.reserve();
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test");
        hub = new Hub(cfg);
        hub.start();
        localApp = TestPorts.listen(8);
        // After localApp is bound, not before: a port picked by binding and closing is free for
        // the kernel to hand straight back to the next bind of 0, and if that were localApp's the
        // "dead" link below would reach a server that answers.
            deadPort = TestPorts.reserve();
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

    private static void serveLocal(Socket c) {
        try (c) {
            HttpRequest r = Http.readRequest(c.getInputStream(), 4096);
            HttpResponse.text(200, "hello " + r.path()).writeTo(c.getOutputStream());
        } catch (Exception e) {
            // visitor gone
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

    @Test
    void aVisitorThatNeverFinishesItsHandshakeLosesItsSlot() throws Exception {
        Daemon alice = oneVisitorNode("alice");
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor(() -> alice.hasCert(hub.tls().keyId()));
        ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "myapp")));

        // The node serves before anything is stalled, so a failure below is the stall and not the setup.
        assertEquals(200, visit("/first").status());

        try (Socket stalled = new Socket(InetAddress.getLoopbackAddress(), port)) {
            stalled.setSoTimeout(30_000);
            stalled.getOutputStream().write(clientHello("myapp.hub.test"));
            stalled.getOutputStream().flush();
            InputStream in = stalled.getInputStream();

            // The node's half of the handshake coming back is what says the slot is taken: it has an
            // SSLEngine, a delegated signature and a place in maxInFlight, and is now waiting for a
            // Finished that will never be sent.
            assertTrue(in.read() >= 0, "the node should have answered the ClientHello");

            // While it is held, the node has nothing for anyone else. Without this the test below
            // would pass on a node that never gave the slot out in the first place.
            assertThrows(IOException.class, () -> visit("/refused"),
                "a node holding its only slot should turn the next visitor away");

            // Past the deadline the node drops the visitor it was waiting on, and the hub closes
            // what it was relaying: everything already sent, then end of stream. Without the
            // deadline this read blocks until the socket timeout above and the test fails there.
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                // the ServerHello and the rest of a handshake nobody is going to finish
            }
            assertEquals(-1, n, "the stalled visitor should have been dropped, not left connected");
        }

        // And the slot is back: the same node serves again, having done nothing but wait out one
        // visitor. A retry loop rather than one attempt, because the reset, the hub's teardown and
        // the counter going back down are three things on three threads.
        waitFor(() -> served("/after"));

        // The node counted it as what it was. Without this the test would pass on a node that lost
        // the visitor some other way -- an exception in the handshake, the hub giving up -- and say
        // nothing about the deadline having been the thing that acted.
        // Nothing here asserts visitorsInFlight is back to zero: the visit above has only just
        // closed and its relay is still unwinding, so that number races this read. That the slot
        // came back is what the visit itself proves -- a node bounded at one could not have served
        // it otherwise.
        JsonObject status = ok(cli("alice", JsonObject.builder().put("cmd", "status")));
        assertEquals(1L, status.lng("visitorsStalled"), status.toString());
        // Zero, and that is the hub working rather than the refusal above not having happened: the
        // node advertises its bound on Hello and `SniRouter` admits against it, so a visitor a full
        // node cannot take is turned away before a stream is opened and never reaches this counter
        // (§9.3). It is here so that the slot being held is measured on the path it is really held
        // on -- the node's own bound -- and not mistaken for the hub's.
        assertEquals(0L, status.lng("visitorsRefused"), status.toString());
    }

    /**
     * The same slot, held one byte later. The deadline above comes off the moment a visitor says
     * anything at all, and one answer the node writes itself reads on past that: the bad gateway,
     * on a link with no gate, has no parsed request to take a method from and so reads until the
     * method is there (RFC 9110 §9.3.2). A visitor that sends two plaintext bytes and stops is past
     * the deadline and short of the method, so an unbounded read there holds a slot of the node's
     * bound -- and the visitor's TLS state -- for the life of the process, which is the defect
     * above with one byte in front of it.
     *
     * <p>The link points at a port nothing is listening on, because that read happens only when the
     * local app is not there. Without the bound the read below blocks until this client's own
     * socket timeout and the test fails there.
     */
    @Test
    void aVisitorThatSaysTwoBytesAndStopsLosesItsSlotAsWell() throws Exception {
        Daemon alice = oneVisitorNode("alice");
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor(() -> alice.hasCert(hub.tls().keyId()));
        ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", deadPort).put("name", "dead")));

        // The page arrives for a visitor that says its whole request, so a failure below is the
        // half-spoken one and not the link.
        assertEquals(502, visit("dead.hub.test", "/first").status());
        // And its slot is back before the next one asks for it: the relay unwinds on another
        // thread, and a node bounded at one would otherwise refuse the connection this test holds.
        waitFor(() -> ok(cli("alice", JsonObject.builder().put("cmd", "status"))).lng("visitorsInFlight") == 0);

        try (SSLSocket held = Tls.connect(Tls.clientContext(CERT, false), "dead.hub.test", "127.0.0.1", port, true, 60_000)) {
            held.startHandshake();
            held.getOutputStream().write("HE".getBytes(StandardCharsets.ISO_8859_1));
            held.getOutputStream().flush();

            // While the node waits for the rest of that request line it has nothing for anyone
            // else, so this is what says the slot really is taken.
            assertThrows(IOException.class, () -> visit("dead.hub.test", "/refused"),
                "a node waiting out a half-spoken request should turn the next visitor away");

            // Past the deadline the node answers with what it was told rather than waiting for the
            // rest for ever. Two bytes are not a method, so the page comes whole.
            HttpResponse r = Http.readResponse(held.getInputStream(), 65536);
            assertEquals(502, r.status());
            assertTrue(r.body().length > 0, "the half-spoken request was answered with an empty page");
        }

        // And the slot is back, from a node that did nothing but wait one visitor out.
        waitFor(() -> visit("dead.hub.test", "/after").status() == 502);
    }

    /**
     * A real ClientHello for {@code sni} and nothing else. Written by an {@code SSLEngine} rather
     * than assembled here so that it is the same bytes a browser's first flight would be -- the hub
     * has to be able to read the SNI out of it and route, or this measures the hub refusing a
     * malformed record instead of the node holding a slot.
     */
    private static byte[] clientHello(String sni) throws Exception {
        SSLContext ctx = Tls.clientContext(CERT, false);
        SSLEngine e = ctx.createSSLEngine(sni, 443);
        e.setUseClientMode(true);
        SSLParameters p = e.getSSLParameters();
        p.setProtocols(Tls.TLS13_ONLY);
        p.setApplicationProtocols(Tls.ALPN_HTTP11);
        p.setServerNames(List.of(new SNIHostName(sni)));
        e.setSSLParameters(p);
        e.beginHandshake();
        ByteBuffer out = ByteBuffer.allocate(e.getSession().getPacketBufferSize());
        e.wrap(ByteBuffer.allocate(0), out);
        out.flip();
        byte[] hello = new byte[out.remaining()];
        out.get(hello);
        return hello;
    }

    /** A node that serves one visitor at a time and waits {@link #DEADLINE_MS} for its first word. */
    private Daemon oneVisitorNode(String name) throws IOException {
        Daemon d = new Daemon(NodeConfig.in(root.resolve(name)), 1, DEADLINE_MS);
        d.start();
        daemons.add(d);
        return d;
    }

    private HttpResponse visit(String path) throws Exception {
        return visit("myapp.hub.test", path);
    }

    private HttpResponse visit(String host, String path) throws Exception {
        SSLContext ctx = Tls.clientContext(CERT, false);
        try (SSLSocket s = Tls.connect(ctx, host, "127.0.0.1", port, true, 10_000)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, path, null, null);
            return Http.readResponse(s.getInputStream(), 65536);
        }
    }

    private boolean served(String path) {
        try {
            return visit(path).status() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    private JsonObject cli(String name, JsonObject.Builder req) throws IOException {
        return Ipc.call(root.resolve(name).resolve("jailscale.sock"), req.build());
    }

    private JsonObject ok(JsonObject r) {
        assertTrue(r.optBool("ok", false), r.toString());
        return r;
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
