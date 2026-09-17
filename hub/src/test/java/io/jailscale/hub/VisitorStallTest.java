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
        // A number nothing listens on, and nothing in this suite will be given later either:
        // reserve() registers it, so the "dead" link below cannot come to reach a server that
        // answers. That is the whole point of taking it from here rather than binding and closing.
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

    /**
     * Through {@link TestCloseables#closeAll} rather than in sequence: a daemon that throws on the
     * way out used to leave {@code localApp} and {@code hub} open, and a hub holding its port for
     * the rest of the suite surfaces as some later class failing to bind (#159).
     */
    @AfterEach
    void stop() throws Exception {
        List<AutoCloseable> all = new ArrayList<>(daemons);
        all.add(localApp);
        all.add(hub);
        TestCloseables.closeAll(all.toArray(new AutoCloseable[0]));
    }

    @Test
    void aVisitorThatNeverFinishesItsHandshakeLosesItsSlot() throws Exception {
        Daemon alice = oneVisitorNode("alice");
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor("the node never got the hub's certificate", () -> alice.hasCert(hub.tls().keyId()));
        ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "myapp")));

        // The node serves before anything is stalled, so a failure below is the stall and not the setup.
        assertEquals(200, visit("/first").status());

        // And the slot that visit took has to be back before the next one asks for it: the
        // response above is read on this thread and the slot is given back on others, so without
        // this the ClientHello below meets a node that is still full (see `slotIsBack`).
        slotIsBack("myapp");

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

        // The node counted it as what it was. Without this the test would pass on a node that lost
        // the visitor some other way -- an exception in the handshake, the hub giving up -- and say
        // nothing about the deadline having been the thing that acted.
        //
        // Read here rather than after the visit below, which is not a matter of taste: the node
        // increments `visitorsStalled` before the reset the read above just saw, so it is already
        // true, while `visitorsRefused` stops being safe to assert the moment another visitor is
        // sent. The retry below is allowed to be turned away once -- the node decrements its count
        // in a finally *after* that reset, so the hub can clear its own first, admit a retry and
        // have the node refuse it -- and that refusal would land on this counter.
        //
        // Nothing here asserts visitorsInFlight is back to zero: the visitor above has only just
        // closed and its relay is still unwinding, so that number races this read. That the slot
        // came back is what the visit below proves -- a node bounded at one could not have served
        // it otherwise.
        JsonObject status = ok(cli("alice", JsonObject.builder().put("cmd", "status")));
        assertEquals(1L, status.lng("visitorsStalled"), status.toString());
        // Zero, and that is the hub working rather than the refusal above not having happened: the
        // node advertises its bound on Hello and `SniRouter` admits against it, so a visitor a full
        // node cannot take is turned away before a stream is opened and never reaches this counter
        // (§9.3). It is here so that the slot being held is measured on the path it is really held
        // on -- the node's own bound -- and not mistaken for the hub's.
        assertEquals(0L, status.lng("visitorsRefused"), status.toString());

        // And the slot is back: the same node serves again, having done nothing but wait out one
        // visitor. A retry loop rather than one attempt, because the reset, the hub's teardown and
        // the counter going back down are three things on three threads.
        waitFor("the node never served again after the stalled visitor was dropped", () -> served("/after"));
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
        waitFor("the node never got the hub's certificate", () -> alice.hasCert(hub.tls().keyId()));
        ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", deadPort).put("name", "dead")));

        // The page arrives for a visitor that says its whole request, so a failure below is the
        // half-spoken one and not the link.
        assertEquals(502, visit("dead.hub.test", "/first").status());
        // And its slot is back before the next one asks for it -- both halves of it, for the
        // reason `slotIsBack` gives: the relay unwinds on another thread, and either ceiling still
        // holding the last visitor closes the connection below before a byte of TLS reaches it.
        slotIsBack("dead");

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

        // And the slot is back, from a node that did nothing but wait one visitor out. Through
        // `served` rather than `visit`, because the slot comes back on other threads than this one
        // and a visitor that arrives before it does is closed rather than answered: `visit` throws
        // that out of the check, which ends the wait instead of retrying it, and this is the line
        // that took this branch red on ubuntu, on the run that was meant to close #125.
        waitFor("the node never served again after the half-spoken request was answered",
            () -> served("dead.hub.test", "/after", 502));
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
        Daemon d = new Daemon(NodeConfig.in(root.resolve(name)).withTuning(NodeConfig.Tuning.defaults().visitorCeiling(1).firstByteMs(DEADLINE_MS)));
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
        return served("myapp.hub.test", path, 200);
    }

    /**
     * One visit as a condition rather than an assertion. A visitor either ceiling turns away gets a
     * closed connection, which arrives here as an exception and not as a status, and inside a
     * {@link #waitFor} that has to read as "not yet" rather than as the end of the test.
     */
    private boolean served(String host, String path, int status) {
        try {
            return visit(host, path).status() == status;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Waits until both ceilings have given the last visitor's slot back. A visit's response is read
     * on the test's thread and its slot is released on others, and there are two of them, because
     * there are two ceilings, each with its own counter and its own way of saying no:
     *
     * <ul>
     *   <li>the hub's, {@code NodeGroup.visitors}, which {@code SniRouter} admits against: a
     *       visitor over it is closed without an answer ({@code Relay.closeQuietly});
     *   <li>the node's, {@code Visitors.inFlight}, which {@code Visitors.refuse} admits against:
     *       {@code RST_NO_CAPACITY}, which reaches the visitor as the same bare close.
     * </ul>
     *
     * <p>So either one still holding the slot arrives at the next visitor's socket as a close with
     * nothing in it, which reads as the node never having answered. That is what took main red five
     * times on two platforms (#125), and the node's is the one that did it -- the CI log carries
     * {@code [visitor] at the visitor ceiling (1), refusing new visitors} nine milliseconds after
     * the link opened.
     *
     * <p>Measured on an idle darwin-arm64 laptop, on the JVM, which is the only place this test
     * runs: the hub's count is still occupied at the line that opens the next socket 40 times out
     * of 40 and clears in a mean of 86 us; the node's is still occupied <i>after the hub's has
     * cleared</i> once in every 30 visits, taking up to 2,186 us. Waiting for the hub's alone is
     * therefore not enough, and was tried: it left
     * {@link #aVisitorThatNeverFinishesItsHandshakeLosesItsSlot} failing on ubuntu, at the same
     * line and with the same message as before.
     * What had been standing in for the wait is an accident of cost -- building a ClientHello takes
     * about 877 us, so on an idle machine the slot frees itself while the test is busy. On a runner
     * where that margin closes, it does not.
     */
    private void slotIsBack(String link) throws Exception {
        try {
            waitFor("the slot the last visitor took never came back", () -> hubInFlight(link) == 0 && nodeInFlight() == 0);
        } catch (AssertionError e) {
            // Which of the two was still holding it is the whole diagnosis, and a message that does
            // not say leaves the next reader where #125 started.
            throw new AssertionError(e.getMessage() + ": the hub holds " + hubInFlight(link)
                + " for " + link + " and the node reports " + nodeInFlight());
        }
    }

    /** The hub's count for one link's node, or -1 when the link is not there at all. */
    private int hubInFlight(String link) {
        Links.Link l = hub.links().byName(link);
        return l == null ? -1 : l.group().visitorsInFlight();
    }

    /**
     * The node's own count, or -1 when the daemon did not answer. A value rather than an assertion
     * because this is polled: one status call that fails has to read as "not yet", since ending the
     * wait on it would report an IPC hiccup as the slot never having come back.
     */
    private long nodeInFlight() {
        try {
            JsonObject r = cli("alice", JsonObject.builder().put("cmd", "status"));
            return r.optBool("ok", false) ? r.lng("visitorsInFlight") : -1;
        } catch (IOException e) {
            return -1;
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

    /**
     * As in {@code StandbyTest} and {@code AutoPromoteTest}: the message is the condition, because
     * five waits in one file that all fail as "condition not met in time" say nothing about which
     * of them gave out -- and a test that exists because a flake was hard to diagnose should not
     * cost the next reader the same hour.
     */
    private static void waitFor(String what, Check c) throws Exception {
        long deadline = System.currentTimeMillis() + 20_000;
        while (System.currentTimeMillis() < deadline) {
            if (c.ok()) {
                return;
            }
            Thread.sleep(50);
        }
        throw new AssertionError(what);
    }
}
