package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.InputStream;
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
 * A HEAD is answered with the header fields a GET would have and no body (RFC 9110 §9.3.2). All
 * three cases here go through one writer, {@code HttpResponse.writeTo}, which is where the defect
 * was; they are separate because each front decides for itself whether to tell the writer what the
 * method was, and a front that forgets looks exactly like a front that was never wired up.
 *
 * <p>Each case reads the status line and headers and then asserts the stream ends there. That is
 * the whole finding: {@code Connection: close} makes the extra bytes invisible to a client that
 * reads to EOF, and visible to anything that frames the next response by Content-Length.
 *
 * <p>Two of the three compare the Content-Length against the bytes a GET returns; the hub's page
 * carries live state, so that one asserts only that the length is not zero -- which is still the
 * direction a response whose body was dropped rather than suppressed would fail.
 */
@Timeout(120)
class HeadHasNoBodyTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();

    private Hub hub;
    private int port;

    @BeforeEach
    void start() throws Exception {
        Log.setLevel(Log.Level.DEBUG);
        Path root = TestDirs.newRoot("head");
        java.net.ServerSocket portSocket = TestPorts.listen(1024);
        port = portSocket.getLocalPort();
        // Port 0 on the plain-HTTP front: the default (80) would collide with a second test JVM,
        // and needs root besides.
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, false, HubConfig.POLICY_MEMBERS, true, "hub.test")
            .withHttp("127.0.0.1", 0));
        hub.listenOn(portSocket);
        hub.start();
    }

    @AfterEach
    void stop() throws Exception {
        hub.close();
    }

    /** A response head, and the next byte on the wire after it: -1 when the message ended there. */
    private record Head(HttpResponse resp, int next) {}

    private static Head head(Socket s, String host, String path) throws Exception {
        Http.writeRequest(s.getOutputStream(), "HEAD", host, path, new Headers(), null);
        return readHead(s);
    }

    /** The same, for a request {@link Http#writeRequest} cannot send: the bytes go out verbatim. */
    private static Head raw(Socket s, String request) throws Exception {
        s.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
        s.getOutputStream().flush();
        return readHead(s);
    }

    private static Head readHead(Socket s) throws Exception {
        InputStream in = s.getInputStream();
        HttpResponse r = Http.readResponseHead(in);
        return new Head(r, in.read());
    }

    private static HttpResponse get(Socket s, String host, String path) throws Exception {
        Http.writeRequest(s.getOutputStream(), "GET", host, path, new Headers(), null);
        return Http.readResponse(s.getInputStream(), 1 << 20);
    }

    private SSLSocket tls(String name) throws Exception {
        return Tls.connect(Tls.clientContext(CERT, false), name, "127.0.0.1", port, true, 10_000);
    }

    private static int contentLength(HttpResponse r) {
        return Integer.parseInt(r.headers().get("Content-Length"));
    }

    @Test
    void hubName() throws Exception {
        try (SSLSocket s = tls("hub.test")) {
            Head h = head(s, "hub.test", "/");
            assertEquals(200, h.resp().status());
            assertTrue(contentLength(h.resp()) > 0, "HEAD still describes the page a GET would send");
            assertEquals(-1, h.next(), "the hub's page followed the headers of a HEAD");
        }
    }

    @Test
    void portEightyChallengeFront() throws Exception {
        int expected;
        try (Socket s = new Socket("127.0.0.1", hub.httpPort())) {
            s.setSoTimeout(10_000);
            HttpResponse r = get(s, "app.example.test", "/.well-known/acme-challenge/nope");
            assertEquals(404, r.status());
            expected = r.body().length;
            assertTrue(expected > 0);
        }
        try (Socket s = new Socket("127.0.0.1", hub.httpPort())) {
            s.setSoTimeout(10_000);
            Head h = head(s, "app.example.test", "/.well-known/acme-challenge/nope");
            assertEquals(404, h.resp().status());
            assertEquals(expected, contentLength(h.resp()));
            assertEquals(-1, h.next(), "port 80 sent a body for a HEAD");
        }
    }

    @Test
    void aRejectedHeadIsAnsweredWithoutABodyToo() throws Exception {
        // None of these ever becomes an HttpRequest, so the front answers out of the exception,
        // which is the one place the method has to be carried rather than read off the request.
        // Four shapes, because they fail at different points of the parse and the method has to
        // survive each: a header line that does not parse; an absolute-form request target (RFC
        // 9112 §3.2.2 -- legal, and what a client configured for a proxy sends), rejected on the
        // request line after the method on it was read; and the two that are rejected by the split
        // of the request line itself -- more fields than three, and a version this parser does not
        // take. Those last two are thrown above the block that adds the method to everything else,
        // in the one place where it had already been read into a local.
        String badHeader = "%s / HTTP/1.1\r\nHost: hub.test\r\nNoColon\r\n";
        String badTarget = "%s http://hub.test/ HTTP/1.1\r\nHost: hub.test\r\n\r\n";
        String badFields = "%s /a b HTTP/1.1\r\nHost: hub.test\r\n\r\n";
        String badVersion = "%s / HTTP/2\r\nHost: hub.test\r\n\r\n";
        for (String malformed : new String[] {badHeader, badTarget, badFields, badVersion}) {
            try (SSLSocket s = tls("hub.test")) {
                Head h = raw(s, String.format(malformed, "HEAD"));
                assertEquals(400, h.resp().status());
                assertTrue(contentLength(h.resp()) > 0, "the reason is still described in Content-Length");
                assertEquals(-1, h.next(), "a rejected HEAD was answered with the error text");
            }
            // And the same request as a GET still gets the text: the method decides, not the error.
            try (SSLSocket s = tls("hub.test")) {
                s.getOutputStream().write(String.format(malformed, "GET").getBytes(StandardCharsets.ISO_8859_1));
                s.getOutputStream().flush();
                HttpResponse r = Http.readResponse(s.getInputStream(), 1 << 20);
                assertEquals(400, r.status());
                assertEquals(contentLength(r), r.body().length);
                assertTrue(r.body().length > 0);
            }
        }
        // The plain-HTTP front reads the method off the exception itself, and one that got that
        // wrong still passes every case above. badHeader and not badTarget, because it is
        // plaintext: badTarget is rejected with its headers still unread, and closing a socket that
        // has bytes left in its receive queue sends an RST, which would lose the answer this is
        // about to read rather than test it.
        try (Socket s = new Socket("127.0.0.1", hub.httpPort())) {
            s.setSoTimeout(10_000);
            Head h = raw(s, String.format(badHeader, "HEAD"));
            assertEquals(400, h.resp().status());
            assertEquals(-1, h.next(), "port 80 answered a rejected HEAD with the error text");
        }
    }

    @Test
    void wildcardFallbackForAnOfflineName() throws Exception {
        int expected;
        try (SSLSocket s = tls("nope.hub.test")) {
            HttpResponse r = get(s, "nope.hub.test", "/");
            assertEquals(404, r.status());
            expected = r.body().length;
            assertTrue(expected > 0);
        }
        try (SSLSocket s = tls("nope.hub.test")) {
            Head h = head(s, "nope.hub.test", "/");
            assertEquals(404, h.resp().status());
            assertEquals(expected, contentLength(h.resp()));
            assertEquals(-1, h.next(), "the offline-name page followed the headers of a HEAD");
        }
    }
}
