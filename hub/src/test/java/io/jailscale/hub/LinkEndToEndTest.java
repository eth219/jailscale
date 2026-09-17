package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.Headers;
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
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import java.nio.charset.StandardCharsets;
import io.jailscale.proto.net.TestPorts;

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
        java.net.ServerSocket portSocket = TestPorts.listen(1024);
        port = portSocket.getLocalPort();
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test");
        hub = new Hub(cfg);
        hub.listenOn(portSocket);
        hub.start();
        // A tiny local HTTP app the node will publish.
        localApp = TestPorts.listen(8);
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
        assertTrue(verified.optBool("allOk", false), "names that verified: the exit status is 0");
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

    /**
     * The hub's own page counts what it is serving and names none of it. An address is public by
     * construction -- a visitor reaches one by typing it -- but `/` is the one page here meant to be
     * indexed, and a name on it is text an indexer keeps (ARCHITECTURE.md §6.3); {@code /links}
     * says `noindex` and is where the addresses are. Who opened a link and which local port it
     * reaches are on neither. Fetched the way a stranger fetches it: no session, over the real router.
     *
     * <p>One link, so this is also the singular branch of the sentence; the nine-link case below is
     * the plural one.
     */
    @Test
    void theFrontPageCountsWhatIsServedAndNamesNoneOfIt() throws Exception {
        Daemon alice = node("alice");
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor(() -> alice.hasCert(hub.tls().keyId()));

        String before = visit("hub.test", "/").bodyText();
        assertTrue(before.contains("None open right now"), before);

        ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "onlylink")));

        String after = visit("hub.test", "/").bodyText();
        assertTrue(after.contains("1 link is open right now"), after);
        assertTrue(after.contains("<a href=\"/links\">See them"), after);
        // Not the name in any form -- with the hub's port, without it, or as the bare label. The
        // link is not called "myapp" like the one below, because the page's own instructions use
        // `--name myapp` as their example and the bare-label assertion would match that instead.
        assertFalse(after.contains("onlylink"), "the name is on an indexable page: " + after);
        assertFalse(after.contains("alice"), "the owner must not be on the public page: " + after);
        assertFalse(after.contains("127.0.0.1:" + localApp.getLocalPort()),
            "the local target must not be on the public page: " + after);
        assertFalse(after.contains("mkey:"), after);
    }

    /**
     * The directory at {@code /links}, fetched the way a stranger fetches it. It has to name what
     * the hub is serving and give away no more than that: not the owner, not the local target, and
     * not how busy a link is at this moment.
     */
    @Test
    void theDirectorySaysWhatIsServedWithoutSayingWhoseOrHowBusy() throws Exception {
        Daemon alice = node("alice");
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor(() -> alice.hasCert(hub.tls().keyId()));

        String empty = visit("hub.test", "/links").bodyText();
        assertTrue(empty.contains("None open right now"), empty);

        ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "myapp")));
        waitFor(() -> hub.links().byName("myapp") != null);

        String idle = visit("hub.test", "/links").bodyText();
        assertTrue(idle.contains("<a rel=\"nofollow\" href=\"https://myapp.hub.test:" + port + "\">myapp.hub.test:" + port + "</a>"), idle);
        assertTrue(idle.contains("&middot; open "), "how long it has been open: " + idle);
        assertFalse(idle.contains("alice"), "the owner must not be on the public page: " + idle);
        assertFalse(idle.contains("127.0.0.1:" + localApp.getLocalPort()),
            "the local target must not be on the public page: " + idle);
        assertFalse(idle.contains("mkey:"), idle);

        // That a name is open is public; that somebody is on it right now is not. The page carried
        // a per-link count for a while, and a page anyone can poll turns that into a live activity
        // feed for a machine belonging to somebody else. A visitor is held open across the fetch --
        // one that finishes its handshake and then says nothing sits in the node's serve() -- so
        // this is the moment a count would appear if the page still took one.
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), "myapp.hub.test", "127.0.0.1", port, true, 10_000)) {
            s.startHandshake();
            waitFor(() -> hub.router().visitorsInFlight() == 1);
            String busy = visit("hub.test", "/links").bodyText();
            assertEquals(1, hub.router().visitorsInFlight(), "the visitor should still be held: " + busy);
            assertFalse(busy.contains("visitor"), "how busy a link is is the operator's, not the page's: " + busy);
            assertFalse(busy.matches("(?s).*&middot; [0-9]+ .*"), "no per-link figure at all: " + busy);
            // The row itself is still there, so this is not passing because the page went blank.
            assertTrue(busy.contains("<a rel=\"nofollow\" href=\"https://myapp.hub.test:" + port + "\">"), busy);
        }
    }

    /**
     * Why the directory exists, and why the front page is not a preview of it. The link list is the
     * only part of the front page with no fixed length, so it lives at {@code /links} -- and the
     * front page names none of it, because {@code /} is the one page here a crawler is asked to
     * index and an address on it is text that can be indexed whatever the row says about itself
     * (ARCHITECTURE.md §6.3). What is left is the count and a way through.
     */
    @Test
    void theFrontPageNamesNoLinkAndSendsEveryOneOfThemToTheDirectory() throws Exception {
        Daemon alice = node("alice");
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor(() -> alice.hasCert(hub.tls().keyId()));
        for (int i = 0; i < 9; i++) {
            ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "app" + i)));
        }
        waitFor(() -> hub.links().all().size() == 9);
        // The page's number comes from count() and the directory's from all(). They walk one
        // shared list of maps, so this cannot drift and this assertion is not what stops it
        // drifting -- with only named links open it would pass just as well if count() had been
        // written out by hand and dropped byDomain and byPort. It is here as the smoke test that
        // the two agree at all, and Links.live is what makes them agree for the maps this test
        // never fills.
        assertEquals(hub.links().all().size(), hub.links().count(), "count() and all() disagree");

        String home = visit("hub.test", "/").bodyText();
        // Every one of the nine, not just the ones that used to be past the cut: this used to show
        // the first eight, so asserting only that app8 is absent would pass unchanged against the
        // page that named the other eight. The bare name and not the ">app0" the rows used to be
        // written as, because the point is that the address is not on the page in any form -- an
        // <a> with the href removed would still be text a crawler keeps.
        for (int i = 0; i < 9; i++) {
            assertFalse(home.contains("app" + i + ".hub.test"), "app" + i + " is named on an indexable page: " + home);
        }
        // What replaces them: how many there are, and the way to the list.
        assertTrue(home.contains("9 links are open right now"), home);
        assertTrue(home.contains("<a href=\"/links\">See them"), home);

        String directory = visit("hub.test", "/links").bodyText();
        for (int i = 0; i < 9; i++) {
            assertTrue(directory.contains("app" + i + ".hub.test"), "app" + i + " is missing: " + directory);
        }

        // The addresses live on the page that asks not to be indexed, and only there. That meta is
        // what the front page could not have: `/` is meant to be found, which is why the rows are
        // not on it rather than being on it with a hint attached.
        assertTrue(directory.contains("content=\"noindex,nofollow\""), directory);
        assertTrue(directory.contains("<a rel=\"nofollow\" href=\"https://app0.hub.test"), directory);
        assertFalse(home.contains("rel=\"nofollow\""), "nothing on the front page needs it now: " + home);

        // A page of the directory is capped, and the cap counted rows the page then had no way to
        // show: the sentence at the top says how many there are, so every one of them has to be
        // reachable. The cursor is the row's own ordering key, and asking for one starts the list
        // there. (The cap is 200, which is more links than a test wants to open, so the cursor is
        // exercised here at a size the assertions can see; the "next" link that carries it appears
        // only past the cap.)
        String fromFive = visit("hub.test", "/links?from=app5.hub.test").bodyText();
        for (int i = 5; i < 9; i++) {
            assertTrue(fromFive.contains("app" + i + ".hub.test"), "app" + i + " is missing: " + fromFive);
        }
        for (int i = 0; i < 5; i++) {
            assertFalse(fromFive.contains("app" + i + ".hub.test"), "app" + i + " is before the cursor: " + fromFive);
        }
        // The count at the top is of everything open, not of this page, so it does not move.
        assertTrue(fromFive.contains("9 links are being served"), fromFive);
        // Nine, not the 200-row cap: the number has to be what the first page actually holds.
        assertTrue(fromFive.contains("Back to the first 9<"), fromFive);

        // A cursor is a string a visitor sends, so the page has to survive every string. A query
        // is percent-decoded per escape and a malformed one makes query() throw; nothing between
        // route() and the virtual thread catches anything but IOException, so this used to close
        // the connection with no response at all and die printing a stack trace.
        HttpResponse rubbish = visit("hub.test", "/links?from=%zz");
        assertEquals(200, rubbish.status(), "a cursor nobody can read is no cursor, not no page");
        assertTrue(rubbish.bodyText().contains("app0.hub.test"), rubbish.bodyText());

        // And one that sorts after everything open -- what a bookmarked cursor becomes once the
        // links it started from close -- says so rather than drawing an empty table under a
        // sentence that has just counted nine links.
        String past = visit("hub.test", "/links?from=zzzz").bodyText();
        assertTrue(past.contains("Nothing is open at that point"), past);
        assertFalse(past.contains("<table class=\"links\"></table>"), "an empty table instead of a reason: " + past);

        // Past the cap, which is 200 in production and more links than a test wants to open, so
        // the page size is given here instead. This is the block that carries the cursor a visitor
        // never types: the "next" link the page generates for itself, and the round trip back.
        String first = hub.front().directory(
            new HttpRequest("GET", "/links", "HTTP/1.1", new Headers(), null), 4);
        assertTrue(first.contains(">app0.hub.test") && first.contains(">app3.hub.test"), first);
        // ">" so this matches a row's anchor text and not the cursor in the "next" href.
        assertFalse(first.contains(">app4.hub.test"), "the page size was not honoured: " + first);
        assertTrue(first.contains("The next 4 of 5 remaining"), first);
        // The generated cursor has to be one the hub reads back, not just one it can print.
        Matcher m = Pattern.compile("/links\\?from=([^\"]+)").matcher(first);
        assertTrue(m.find(), first);
        String second = hub.front().directory(
            new HttpRequest("GET", "/links?from=" + m.group(1), "HTTP/1.1", new Headers(), null), 4);
        assertTrue(second.contains(">app4.hub.test") && second.contains(">app7.hub.test"), second);
        assertFalse(second.contains(">app3.hub.test"), "the cursor did not advance: " + second);
        // And the way back names the page it returns to, not the constant.
        assertTrue(second.contains("Back to the first 4"), second);
    }

    /**
     * The node's half of the hub's in-flight gauge (ARCHITECTURE.md §14). What a node holds per
     * visitor is tens of kilobytes of TLS state, and RSS was the only way to see how many it held --
     * a number that cannot tell visitors from a leak or from the heap expanding into its ceiling.
     * A visitor that finishes its handshake and then says nothing holds the node in `serve`, which
     * is what makes this deterministic: the count has to be 1 while it is there and 0 after it goes.
     */
    @Test
    void theNodeCountsTheVisitorsItIsHolding() throws Exception {
        Daemon alice = node("alice");
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor(() -> alice.hasCert(hub.tls().keyId()));
        ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "counted")));
        waitFor(() -> hub.links().byName("counted") != null);

        assertEquals(0L, nodeInFlight("alice"));
        try (SSLSocket s = Tls.connect(Tls.clientContext(CERT, false), "counted.hub.test", "127.0.0.1", port, true, 10_000)) {
            s.startHandshake(); // and then nothing: the node is in serve(), waiting for a request
            waitFor(() -> nodeInFlight("alice") == 1L);
            assertEquals(1L, nodeInFlight("alice"));
            assertEquals(1, hub.router().visitorsInFlight(), "the hub should be holding the same visitor");
            assertEquals(1, hub.router().trackedNames(), "and counting the name it is holding it for");
        }
        waitFor(() -> nodeInFlight("alice") == 0L);
        // The per-name count has to come back down too. It is acquired before the try that
        // releases it (SniRouter.acquire/release), so a path that leaves in between strands the
        // name's slot for the hub's lifetime and quietly lowers its MAX_PER_NAME. perIp is
        // released in an outer finally and has SniRouterCountersTest watching it drain; this is
        // the same guard for the other map, here because this is the only test that drives a
        // visitor far enough to be counted against a name at all.
        waitFor(() -> hub.router().trackedNames() == 0);
    }

    private long nodeInFlight(String name) throws IOException {
        return cli(name, JsonObject.builder().put("cmd", "status")).lng("visitorsInFlight");
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
        Message r = alice.debugRequest(new Message.SignRequest(4242, hub.tls().keyId(), "ECDSA-P256-SHA256", digest, null, null, null),
            "SignResponse:4242");
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

        // The signature is bound to the handshake on the stream, not just to the stream. A visitor
        // sends its ClientHello for bobapp and then stalls, so the stream stays open; bob's node
        // asks the hub to sign a CertificateVerify whose transcript does not end in that ClientHello
        // (an on-path member forging another name's handshake would look exactly like this), and
        // the hub refuses even though the stream and the name are bob's own.
        NodeGroup bobGroup = hub.links().byName("bobapp").group();
        try (Socket stalled = new Socket("127.0.0.1", port)) {
            SSLEngine hello = Tls.clientContext(CERT, false).createSSLEngine("bobapp.hub.test", port);
            hello.setUseClientMode(true);
            SSLParameters hp = hello.getSSLParameters();
            hp.setServerNames(List.of(new javax.net.ssl.SNIHostName("bobapp.hub.test")));
            hp.setProtocols(new String[] {"TLSv1.3"});
            hello.setSSLParameters(hp);
            hello.beginHandshake();
            java.nio.ByteBuffer out = java.nio.ByteBuffer.allocate(hello.getSession().getPacketBufferSize());
            hello.wrap(java.nio.ByteBuffer.allocate(0), out);
            out.flip();
            stalled.getOutputStream().write(out.array(), 0, out.remaining());
            stalled.getOutputStream().flush();
            waitFor(() -> !bobGroup.visitorIds().isEmpty());
            long streamId = bobGroup.visitorIds().iterator().next();
            // Let bob's own, honest signature for this stream finish first. The node keys a reply
            // by stream, so it can have one SignRequest in flight per stream; a forged one sent
            // alongside would be answered under that key and fail the real handshake instead of
            // being judged on its own. The signature count is not the signal for that -- it is
            // reserved before the hub signs and answers (§9.2 condition 5 has to be taken before
            // the work, not after) -- but the node's ServerHello arriving is: it cannot write its
            // flight until the signature it asked for has come back.
            waitFor(() -> bobGroup.signaturesUsed(streamId) >= 1);
            stalled.setSoTimeout(30_000);
            assertTrue(stalled.getInputStream().read() >= 0, "the node never answered the ClientHello");

            byte[] content = java.util.Arrays.copyOf(HubTls.CERT_VERIFY_CONTEXT, HubTls.CERT_VERIFY_CONTEXT.length + 32);
            java.util.Arrays.fill(content, HubTls.CERT_VERIFY_CONTEXT.length, content.length, (byte) 0x5a);
            byte[] sh = io.jailscale.proto.tls.Tls13.serverHello(new byte[32], new byte[0], 0x1301, new byte[32]);
            byte[] ee = io.jailscale.proto.tls.Tls13.encryptedExtensions(true, new int[] {0x001d}, "http/1.1", true);
            Message forged = bob.debugRequest(new Message.SignRequest(streamId, hub.tls().keyId(), "ECDSA-P256-SHA256", content, sh, ee, null),
                "SignResponse:" + streamId);
            assertTrue(forged instanceof Message.SignResponse fr && fr.sig() == null && "transcript-mismatch".equals(fr.reason()), forged.toString());
            // and one that cannot even be rebuilt (no ServerHello) is refused the same way
            Message bare = bob.debugRequest(new Message.SignRequest(streamId, hub.tls().keyId(), "ECDSA-P256-SHA256", content, null, null, null),
                "SignResponse:" + streamId);
            assertTrue(bare instanceof Message.SignResponse br && br.sig() == null && br.reason().startsWith("transcript-mismatch"), bare.toString());
        }

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

    /**
     * ARCHITECTURE.md §11.3: nobody types `jailscale verify` on an unattended node and the periodic
     * pass is half an hour from its next tick, so a node whose link has just come up checks every
     * name it holds there and then. That moment is the one the schedule is worst at: a node that
     * loses a name is usually offline when it happens, because being offline is why someone else
     * took it (§11.4).
     */
    @Test
    void aNodeComingBackChecksItsNamesWithoutBeingAsked() throws Exception {
        Daemon alice = node("alice");
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor(() -> alice.hasCert(hub.tls().keyId()));
        ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "backagain")));

        alice.close();
        daemons.remove(alice);
        waitFor(() -> hub.links().byName("backagain") == null);

        // A verdict on the node that comes back can only be this process's work: the last probe of
        // a name is not persisted, and the next ordinary tick is half an hour away.
        Daemon back = node("alice");
        waitFor(() -> back.hasCert(hub.tls().keyId()));
        waitFor(() -> "terminated by this node".equals(probeVerdict("alice", "backagain")));
    }

    /**
     * ARCHITECTURE.md §11.3: a link the hub is not routing here is not an interception, and the
     * command this section sends operators to has to say so. `down` leaves the names in the node's
     * list with nothing serving them, and the hub answers each with its own page under the wildcard
     * certificate -- which is a session this node did not terminate, and would read as a compromised
     * hub to anything comparing keying material without looking first.
     */
    @Test
    void verifyCallsAClosedLinkNotOpenRatherThanAnInterception() throws Exception {
        Daemon alice = node("alice");
        ok(cli("alice", JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1").put("port", port)
            .put("user", "alice").put("caFile", CERT.toString())));
        waitFor(() -> alice.hasCert(hub.tls().keyId()));
        ok(cli("alice", JsonObject.builder().put("cmd", "open").put("port", localApp.getLocalPort()).put("name", "goingdown")));
        ok(cli("alice", JsonObject.builder().put("cmd", "down")));
        waitFor(() -> hub.links().byName("goingdown") == null);

        // `ok` is that the check ran; the CLI prints the rows on that and nothing else. What the
        // rows concluded is `allOk`, which is what the exit status follows -- and a name nothing was
        // probed for is not one of them. This asserted the opposite until the pair of commands
        // above was noticed to be an ordinary thing to type: it left `jailscale verify` exiting 1,
        // which is the alarm §11.3 raises for a hub terminating this node's TLS, on a node being
        // off. The row is still there and still says what it says.
        JsonObject verified = ok(cli("alice", JsonObject.builder().put("cmd", "verify")));
        assertTrue(verified.optBool("allOk", false), verified.toString());
        assertEquals(0, verified.integer("checked"), "nothing was probed, and `checked` says so: " + verified);
        assertEquals(1, verified.array("results").size(), "the row is still reported: " + verified);
        for (Object o : verified.array("results")) {
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> row = (java.util.Map<String, Object>) o;
            assertEquals("link not open", row.get("verdict"), row.toString());
            // and named the way a probed row is named, so one answer does not carry two shapes
            assertEquals("goingdown.hub.test", row.get("name"), row.toString());
        }
    }

    /** What `status` says the last self-probe of one name concluded, or null when none has run. */
    private String probeVerdict(String node, String name) throws IOException {
        for (Object o : cli(node, JsonObject.builder().put("cmd", "status")).array("links")) {
            @SuppressWarnings("unchecked")
            java.util.Map<String, Object> row = (java.util.Map<String, Object>) o;
            if (name.equals(row.get("name")) && row.get("probe") != null) {
                @SuppressWarnings("unchecked")
                java.util.Map<String, Object> probe = (java.util.Map<String, Object>) row.get("probe");
                return (String) probe.get("verdict");
            }
        }
        return null;
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

    /**
     * The page the hub writes under the wildcard for a name nobody has opened. It is the widest
     * surface the hub has -- any label, at any depth, reaches it -- and it is written by a different
     * class from the pages out front, which is exactly how it came to be the one frame the first
     * pass at this forgot. Nothing else drives it, so without this test dropping
     * {@code HttpFront.secured} here leaves a green suite.
     */
    @Test
    void theNotOpenPageUnderTheWildcardIsCoveredByTheSameHeaders() throws Exception {
        HttpResponse r = visit("nobody.hub.test", "/");
        assertEquals(404, r.status());
        assertTrue(r.bodyText().contains("is not open right now"), r.bodyText());
        assertTrue(r.bodyText().contains("noindex"), r.bodyText());
        String csp = r.headers().get("Content-Security-Policy");
        assertNotNull(csp, "the wildcard page is a page in a browser too");
        assertTrue(csp.contains("default-src 'none'"), csp);
        assertEquals("nosniff", r.headers().get("X-Content-Type-Options"));
        assertEquals("no-referrer", r.headers().get("Referrer-Policy"));
        assertNull(r.headers().get("Strict-Transport-Security"), "no HSTS here either (#98)");
    }
}
