package io.jailscale.proto.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import io.jailscale.proto.net.TestPorts;

/**
 * The client side of a release download (ARCHITECTURE.md §9.4): one redirect hop, a body that is
 * streamed rather than held, and the statuses that are not a file.
 */
class HttpCallTest {

    /** A loopback server that answers each request from {@code handler}, keyed on its path. */
    private static ServerSocket serve(Function<String, String> handler) throws IOException {
        ServerSocket ss = TestPorts.listen(50);
        Thread t = new Thread(() -> {
            while (!ss.isClosed()) {
                try (Socket s = ss.accept()) {
                    HttpRequest r = Http.readRequest(s.getInputStream(), 0);
                    s.getOutputStream().write(handler.apply(r.path()).getBytes(StandardCharsets.ISO_8859_1));
                    s.getOutputStream().flush();
                } catch (Exception e) {
                    return; // the test closed the socket, or is finished with it
                }
            }
        }, "canned-http");
        t.setDaemon(true);
        t.start();
        return ss;
    }

    private static URI at(ServerSocket ss, String path) {
        return URI.create("http://" + ss.getInetAddress().getHostAddress() + ":" + ss.getLocalPort() + path);
    }

    @Test
    void followsTheHopToTheObjectStoreAndKeepsOnlyTheFile() throws Exception {
        // GitHub answers a release asset with a 302 to an object store on another host, and that
        // response has a body of its own. The 302's body being given a Content-Length here is the
        // point: a reader that streamed every body into the caller's file would produce
        // "movedhello" and a checksum failure nobody could explain.
        try (ServerSocket ss = serve(path -> switch (path) {
            case "/download" -> "HTTP/1.1 302 Found\r\nLocation: /blob\r\nContent-Length: 5\r\n\r\nmoved";
            case "/blob" -> "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n";
            default -> "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        })) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            long n = HttpCall.get(at(ss, "/download"), null, out, 5000, 1 << 20);
            assertEquals("hello", out.toString(StandardCharsets.UTF_8));
            assertEquals(5, n);
        }
    }

    @Test
    void writesTheBodyStraightToTheFile(@TempDir Path dir) throws Exception {
        byte[] payload = new byte[300_000];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) i;
        }
        String body = new String(payload, StandardCharsets.ISO_8859_1);
        try (ServerSocket ss = serve(path -> "HTTP/1.1 200 OK\r\nContent-Length: " + payload.length + "\r\n\r\n" + body)) {
            Path file = dir.resolve("jailscale-linux-amd64");
            try (OutputStream out = Files.newOutputStream(file)) {
                assertEquals(payload.length, HttpCall.get(at(ss, "/asset"), null, out, 5000, 1 << 20));
            }
            assertEquals(payload.length, Files.size(file));
            assertEquals(-1, java.util.Arrays.mismatch(payload, Files.readAllBytes(file)));
        }
    }

    @Test
    void refusesABodyOverTheCeilingBeforeReadingIt(@TempDir Path dir) throws Exception {
        try (ServerSocket ss = serve(path -> "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + "x".repeat(100))) {
            Path file = dir.resolve("too-big");
            try (OutputStream out = Files.newOutputStream(file)) {
                assertThrows(HttpException.class, () -> HttpCall.get(at(ss, "/asset"), null, out, 5000, 10));
            }
            assertEquals(0, Files.size(file)); // and nothing of it reached the file
        }
    }

    @Test
    void givesUpOnALoopAndOnAStatusThatIsNotAFile() throws Exception {
        try (ServerSocket ss = serve(path -> "HTTP/1.1 302 Found\r\nLocation: " + path + "x\r\nContent-Length: 0\r\n\r\n")) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            IOException e = assertThrows(IOException.class, () -> HttpCall.get(at(ss, "/a"), null, out, 5000, 1 << 20));
            assertTrue(e.getMessage().contains("redirects"), e.getMessage());
        }
        // The status is carried rather than written into a sentence: the release download tells
        // "this release has nothing signed" (404) apart from "try again" (503) by reading it.
        try (ServerSocket ss = serve(path -> "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            HttpException e = assertThrows(HttpException.class, () -> HttpCall.get(at(ss, "/gone"), null, out, 5000, 1 << 20));
            assertEquals(404, e.status());
        }
        try (ServerSocket ss = serve(path -> "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            assertEquals(503, assertThrows(HttpException.class,
                () -> HttpCall.get(at(ss, "/later"), null, out, 5000, 1 << 20)).status());
        }
    }

    @Test
    void aRedirectMayChangeHostButNotLeaveTls() throws Exception {
        URI from = URI.create("https://github.com/gosuda/jailscale/releases/download/v0.2.0/jailscale-linux-amd64");
        // The hop this exists for: another host, still TLS.
        assertEquals("https://objects.githubusercontent.com/x?token=1",
            HttpCall.redirect(from, "https://objects.githubusercontent.com/x?token=1").toString());
        // Relative, as a server is allowed to answer.
        assertEquals("https://github.com/y", HttpCall.redirect(from, "/y").toString());

        // "The same thing, over http" is the rest of the exchange in the clear, from a compiled-in
        // https URL. The signature would still catch a swapped binary; this catches it earlier and
        // keeps the request itself off the wire in plaintext.
        assertTrue(assertThrows(IOException.class, () -> HttpCall.redirect(from, "http://github.com/y"))
            .getMessage().contains("downgrade"));
        assertThrows(IOException.class, () -> HttpCall.redirect(from, "file:///etc/passwd"));
        assertThrows(IOException.class, () -> HttpCall.redirect(from, "javascript:0"));
        assertThrows(IOException.class, () -> HttpCall.redirect(from, null));
        assertThrows(IOException.class, () -> HttpCall.redirect(from, "  "));
        assertThrows(IOException.class, () -> HttpCall.redirect(from, "http://"));

        // A plain-http caller is not downgrading by staying on http; that is the loopback test above.
        assertEquals("http://127.0.0.1:1/y", HttpCall.redirect(URI.create("http://127.0.0.1:1/x"), "/y").toString());
    }
}
