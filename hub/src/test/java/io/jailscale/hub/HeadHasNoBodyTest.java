package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.http.Headers;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.InputStream;
import java.net.InetAddress;
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

/**
 * A HEAD is answered with the header fields a GET would have and no body (RFC 9110 §9.3.2). All
 * four cases here go through one writer, {@code HttpResponse.writeTo}, which is where the defect
 * was; they are separate because each front decides for itself whether to tell the writer what the
 * method was, and a front that forgets looks exactly like a front that was never wired up.
 *
 * <p>Each case reads the status line and headers and then asserts the stream ends there. That is
 * the whole finding: {@code Connection: close} makes the extra bytes invisible to a client that
 * reads to EOF, and visible to anything that frames the next response by Content-Length.
 *
 * <p>Two of the four compare the Content-Length against the bytes a GET returns; the hub's page and
 * the metrics text carry live counters, so those two assert only that the length is not zero --
 * which is still the direction a response whose body was dropped rather than suppressed would fail.
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
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        // Port 0 on both extra listeners: the defaults (9090, 80) would collide with a second test
        // JVM, and 80 needs root besides.
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, false, HubConfig.POLICY_MEMBERS, true, "hub.test")
            .withMetrics("127.0.0.1", 0).withHttp("127.0.0.1", 0));
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
    void metricsListener() throws Exception {
        try (Socket s = new Socket("127.0.0.1", hub.metricsPort())) {
            s.setSoTimeout(10_000);
            Head h = head(s, "127.0.0.1", "/metrics");
            assertEquals(200, h.resp().status());
            assertTrue(contentLength(h.resp()) > 0, "HEAD still describes the metrics a GET would send");
            assertEquals(-1, h.next(), "the metrics text followed the headers of a HEAD");
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
        // This request never becomes an HttpRequest -- the request line parses and the header line
        // after it does not -- so the front answers out of the exception, which is the one place the
        // method has to be carried rather than read off the request.
        String malformed = "%s / HTTP/1.1\r\nHost: hub.test\r\nNoColon\r\n\r\n";
        try (SSLSocket s = tls("hub.test")) {
            s.getOutputStream().write(String.format(malformed, "HEAD").getBytes(StandardCharsets.ISO_8859_1));
            s.getOutputStream().flush();
            InputStream in = s.getInputStream();
            HttpResponse r = Http.readResponseHead(in);
            assertEquals(400, r.status());
            assertTrue(contentLength(r) > 0, "the reason is still described in Content-Length");
            assertEquals(-1, in.read(), "a rejected HEAD was answered with the error text");
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
