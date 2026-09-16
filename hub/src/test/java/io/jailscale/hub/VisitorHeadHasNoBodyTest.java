package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * The three responses the node writes to a visitor itself -- the gate's redirect, the gate's
 * refusal, and the bad gateway when the local app is not there -- carry no body for a HEAD
 * (RFC 9110 §9.3.2). {@code HeadHasNoBodyTest} is the same finding on the hub's own fronts; this
 * is the node's, and it is a separate class because the node reaches the same writer by a
 * different route: nothing on the visitor path parses a request, so the method comes out of the
 * head {@code Gate} reads, or out of the first bytes of the raw request.
 *
 * <p>Each case asks for the same thing twice. The GET fixes what the body is and how long it is,
 * and the HEAD then has to describe that body in Content-Length and stop at the blank line -- so a
 * response whose body was dropped rather than suppressed fails on the length, and one that still
 * writes the page fails on the byte after the head. Asserting only the HEAD would pass just as
 * well against a node that had stopped serving these pages at all.
 */
@Timeout(150)
class VisitorHeadHasNoBodyTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Hub hub;
    private int port;
    private Daemon alice;
    private Path sock;
    private ServerSocket app;
    /** A port nothing is listening on, so the link opens and every visitor to it gets the 502. */
    private int deadPort;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        Path root = TestDirs.newRoot("vhead");
        port = TestPorts.reserve();
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test"));
        hub.start();
        app = TestPorts.listen(8);
        // A number nothing listens on, and nothing in this suite will be given later either:
        // reserve() registers it, so the app cannot come to be bound on it and leave three cases
        // asserting 502 against a 200. That is the whole point of taking it from here rather than
        // binding and closing.
        deadPort = TestPorts.reserve();
        Thread.ofVirtual().start(() -> {
            while (!app.isClosed()) {
                try {
                    Socket c = app.accept();
                    Thread.ofVirtual().start(() -> serve(c));
                } catch (IOException e) {
                    return;
                }
            }
        });
        alice = new Daemon(NodeConfig.in(root.resolve("alice")));
        alice.start();
        sock = root.resolve("alice/jailscale.sock");
        JsonObject up = Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).build());
        assertTrue(up.optBool("ok", false), up.toString());
        long deadline = System.currentTimeMillis() + 10_000;
        while (!alice.hasCert(hub.tls().keyId()) && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
    }

    /** The local app, for the one case that has to get past the gate and reach something. */
    private static void serve(Socket c) {
        try (c) {
            Http.readRequest(c.getInputStream(), 65536);
            HttpResponse.text(200, "page").writeTo(c.getOutputStream());
        } catch (Exception ignored) {
            // visitor gone
        }
    }

    @AfterEach
    void stop() throws Exception {
        alice.close();
        app.close();
        hub.close();
    }

    /** A response head, and the next byte on the wire after it: -1 when the message ended there. */
    private record Head(HttpResponse resp, int next) {}

    private SSLSocket connect(String host) throws Exception {
        return Tls.connect(Tls.clientContext(CERT, false), host, "127.0.0.1", port, true, 10_000);
    }

    private Head head(String host, String target, Headers headers) throws Exception {
        try (SSLSocket s = connect(host)) {
            Http.writeRequest(s.getOutputStream(), "HEAD", host, target, headers == null ? new Headers() : headers, null);
            InputStream in = s.getInputStream();
            HttpResponse r = Http.readResponseHead(in);
            return new Head(r, in.read());
        }
    }

    private HttpResponse get(String host, String target, Headers headers) throws Exception {
        try (SSLSocket s = connect(host)) {
            Http.writeRequest(s.getOutputStream(), "GET", host, target, headers == null ? new Headers() : headers, null);
            return Http.readResponse(s.getInputStream(), 1 << 20);
        }
    }

    private static int contentLength(HttpResponse r) {
        String len = r.headers().get("Content-Length");
        assertNotNull(len, "the response described no body at all: it carried no Content-Length");
        return Integer.parseInt(len);
    }

    private String open(String name, int localPort, boolean gate) throws Exception {
        JsonObject o = Ipc.call(sock, JsonObject.builder().put("cmd", "open").put("port", localPort)
            .put("name", name).put("gate", gate).build());
        assertTrue(o.optBool("ok", false), o.toString());
        if (!gate) {
            return null;
        }
        String visit = o.string("visitUrl");
        return visit.substring(visit.indexOf("jail=") + 5);
    }

    /** The gate's 403, which is written before anything has been asked of the local app. */
    @Test
    void theGatesRefusalHasNoBodyForAHead() throws Exception {
        open("shut", app.getLocalPort(), true);
        HttpResponse g = get("shut.hub.test", "/secret", null);
        assertEquals(403, g.status());
        assertTrue(g.body().length > 0);

        Head h = head("shut.hub.test", "/secret", null);
        assertEquals(403, h.resp().status());
        assertEquals(g.body().length, contentLength(h.resp()),
            "the refused HEAD described a different page from the one a GET is refused with");
        assertEquals(-1, h.next(), "the gate's refusal page followed the headers of a HEAD");
    }

    /**
     * The gate's 302 has an empty body either way, so what this pins is not the suppression: it is
     * that deciding the method has not changed what the gate makes of the request line it is
     * decided from. A HEAD carrying the visit link still gets the cookie and the clean location.
     */
    @Test
    void aHeadCarryingTheVisitLinkIsStillGivenTheCookie() throws Exception {
        String token = open("visit", app.getLocalPort(), true);
        Head h = head("visit.hub.test", "/deep?a=1&jail=" + token, null);
        assertEquals(302, h.resp().status());
        assertEquals("/deep?a=1", h.resp().headers().get("Location"));
        String setCookie = h.resp().headers().get("Set-Cookie");
        assertNotNull(setCookie, "a HEAD through the visit link was not given the cookie");
        assertTrue(setCookie.startsWith("jail=" + token + ";"), setCookie);
        assertEquals(0, contentLength(h.resp()));
        assertEquals(-1, h.next(), "the redirect sent something after its headers");
    }

    /** The 502, on a link with no gate: nothing has read a byte of the request when it is written. */
    @Test
    void theBadGatewayPageHasNoBodyForAHead() throws Exception {
        open("gone", deadPort, false);
        HttpResponse g = get("gone.hub.test", "/", null);
        assertEquals(502, g.status());
        assertTrue(g.bodyText().contains(Integer.toString(deadPort)), g.bodyText());

        Head h = head("gone.hub.test", "/", null);
        assertEquals(502, h.resp().status());
        assertEquals(g.body().length, contentLength(h.resp()),
            "the HEAD described a different page from the one a GET gets");
        assertEquals(-1, h.next(), "the bad-gateway page followed the headers of a HEAD");
    }

    /**
     * The same 502 on a gated link, which is the other half of where the method comes from: the
     * gate has already read the head, so this answer is framed from those bytes and not from a
     * read of its own. The GET here is the case that hung before this test existed -- the request
     * was consumed, the read deadline was lifted when the gate passed, and reading the request
     * again waited for a body a GET does not send -- so the assertion that it arrives at all is
     * as much of the point as the framing of the HEAD.
     */
    @Test
    void aGatedLinkWhoseAppIsDownAnswersBothMethods() throws Exception {
        String token = open("gshut", deadPort, true);
        Headers cookie = new Headers().add("Cookie", "jail=" + token);
        HttpResponse g = get("gshut.hub.test", "/", cookie);
        assertEquals(502, g.status(), "a visitor past the gate waited instead of being told the app is down");
        assertTrue(g.body().length > 0);

        Head h = head("gshut.hub.test", "/", new Headers().add("Cookie", "jail=" + token));
        assertEquals(502, h.resp().status());
        assertEquals(g.body().length, contentLength(h.resp()));
        assertEquals(-1, h.next(), "the bad-gateway page followed the headers of a gated HEAD");
    }

    /**
     * The ungated 502 is the one answer that reads the method off the wire itself, and a read
     * there returns one TLS record's plaintext. A client is under no obligation to put the whole
     * request line in the first record, so the two bytes here are sent on their own -- which one
     * write never produces, and which is why nothing else in this class would catch a node that
     * decided the method from whatever the first read happened to return.
     */
    @Test
    void aHeadSplitAcrossTlsRecordsIsStillAHead() throws Exception {
        open("split", deadPort, false);
        byte[] req = ("HEAD / HTTP/1.1\r\nHost: split.hub.test\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
        try (SSLSocket s = connect("split.hub.test")) {
            OutputStream out = s.getOutputStream();
            out.write(req, 0, 2);
            out.flush();
            Thread.sleep(150);
            out.write(req, 2, req.length - 2);
            out.flush();
            InputStream in = s.getInputStream();
            HttpResponse r = Http.readResponseHead(in);
            assertEquals(502, r.status());
            assertTrue(Integer.parseInt(r.headers().get("Content-Length")) > 0);
            assertEquals(-1, in.read(), "a HEAD whose first record was short was answered with the page");
        }
    }

    /**
     * The method is decided by a byte compare against {@code "HEAD "} <em>including the trailing
     * space</em>, because what it is compared against is a raw buffer and not a parsed token. Drop
     * the space and every method whose name starts with those four letters -- {@code HEADER} here,
     * and whatever else a client or a crawler invents -- is answered with its body stripped. This
     * is the only case in the class that fails when the space goes: every other request here is
     * either a bare {@code HEAD} or a {@code GET}.
     */
    @Test
    void aMethodThatMerelyStartsWithHeadStillGetsItsBody() throws Exception {
        open("headish", deadPort, false);
        byte[] req = ("HEADER / HTTP/1.1\r\nHost: headish.hub.test\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
        try (SSLSocket s = connect("headish.hub.test")) {
            s.getOutputStream().write(req);
            s.getOutputStream().flush();
            InputStream in = s.getInputStream();
            HttpResponse r = Http.readResponseHead(in);
            assertEquals(502, r.status());
            assertTrue(contentLength(r) > 0);
            assertTrue(in.read() >= 0, "a method that only starts with HEAD was answered as though it were one");
        }
    }

    /**
     * A head longer than {@code Gate.MAX_HEAD} is refused without being parsed at all -- and the
     * method was still read, first, before the bytes that took it past the limit. The refusal is
     * the same 403 either way, so the method has to be carried out of a head the gate gave up on,
     * which is the case the ordinary refusal above does not reach.
     */
    @Test
    void aHeadTooLongToParseIsStillRefusedWithoutItsBody() throws Exception {
        open("big", app.getLocalPort(), true);
        String pad = "p".repeat(20_000); // > Gate.MAX_HEAD, so readHead gives up on it
        byte[] req = ("HEAD / HTTP/1.1\r\nHost: big.hub.test\r\nX-Pad: " + pad + "\r\n\r\n")
            .getBytes(StandardCharsets.ISO_8859_1);
        try (SSLSocket s = connect("big.hub.test")) {
            s.getOutputStream().write(req);
            s.getOutputStream().flush();
            InputStream in = s.getInputStream();
            HttpResponse r = Http.readResponseHead(in);
            assertEquals(403, r.status());
            assertTrue(Integer.parseInt(r.headers().get("Content-Length")) > 0);
            assertEquals(-1, in.read(), "an over-long HEAD was refused with the page after the headers");
        }
    }
}
