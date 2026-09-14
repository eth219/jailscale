package io.jailscale.proto.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HttpTest {

    private static ByteArrayInputStream in(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.ISO_8859_1));
    }

    @Test
    void parsesUpgradeRequest() throws Exception {
        HttpRequest r = Http.readRequest(in("POST /v1/noise?x=1&y=a%20b HTTP/1.1\r\nHost: hub.example.com\r\n"
            + "Connection: keep-alive, Upgrade\r\nUpgrade: jailscale-control-v1\r\nContent-Length: 0\r\n\r\n"), 1024);
        assertEquals("POST", r.method());
        assertEquals("/v1/noise", r.path());
        assertEquals(Map.of("x", "1", "y", "a b"), r.query());
        assertTrue(r.wantsUpgrade("jailscale-control-v1"));
        assertFalse(r.wantsUpgrade("websocket"));
        assertEquals("hub.example.com", r.headers().get("HOST"));
        assertEquals(0, r.body().length);
    }

    @Test
    void parsesFormBodyAndBareLf() throws Exception {
        HttpRequest r = Http.readRequest(in("POST /admin/approve HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n"
            + "Content-Length: 17\n\nmkey=abc&user=w+q"), 1024);
        assertEquals(Map.of("mkey", "abc", "user", "w q"), r.form());
    }

    @Test
    void enforcesLimits() {
        assertThrows(HttpException.class, () -> Http.readRequest(in("GET / HTTP/1.1\r\nContent-Length: 2000\r\n\r\n"), 1024));
        assertThrows(HttpException.class, () -> Http.readRequest(in("GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), 1024));
        assertThrows(HttpException.class, () -> Http.readRequest(in("GARBAGE\r\n\r\n"), 1024));
        assertThrows(HttpException.class, () -> Http.readRequest(in("GET x HTTP/1.1\r\n\r\n"), 1024));
        assertThrows(HttpException.class, () -> Http.readRequest(in("GET / HTTP/1.1\r\nNoColon\r\n\r\n"), 1024));
        assertThrows(HttpException.class, () -> Http.readRequest(in("GET /" + "a".repeat(9000) + " HTTP/1.1\r\n\r\n"), 1024));
        StringBuilder many = new StringBuilder("GET / HTTP/1.1\r\n");
        for (int i = 0; i < 70; i++) {
            many.append("H").append(i).append(": v\r\n");
        }
        many.append("\r\n");
        assertThrows(HttpException.class, () -> Http.readRequest(in(many.toString()), 1024));
        assertThrows(EOFException.class, () -> Http.readRequest(in(""), 1024));
        assertThrows(EOFException.class, () -> Http.readRequest(in("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab"), 1024));
    }

    @Test
    void writesResponsesWithContentLengthAndClose() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        HttpResponse.json(200, "{\"a\":1}").writeTo(out);
        assertEquals("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\nConnection: close\r\n\r\n{\"a\":1}",
            out.toString(StandardCharsets.ISO_8859_1));

        out.reset();
        HttpResponse.upgrade("jailscale-control-v1").writeTo(out);
        assertEquals("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: jailscale-control-v1\r\n\r\n",
            out.toString(StandardCharsets.ISO_8859_1));
    }

    @Test
    void clientRoundTrip() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        Http.writeRequest(wire, "GET", "hub.example.com", "/v1/key", new Headers().add("Accept", "application/json"), null);
        assertEquals("GET /v1/key HTTP/1.1\r\nHost: hub.example.com\r\nAccept: application/json\r\n\r\n",
            wire.toString(StandardCharsets.ISO_8859_1));
        HttpRequest r = Http.readRequest(new ByteArrayInputStream(wire.toByteArray()), 0);
        assertEquals("/v1/key", r.path());

        wire.reset();
        Http.writeRequest(wire, "POST", "h", "/v1/noise", new Headers().add("Upgrade", "x"), new byte[] {1, 2});
        assertTrue(wire.toString(StandardCharsets.ISO_8859_1).contains("Content-Length: 2\r\n"));

        HttpResponse resp = Http.readResponse(in("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX: y\r\n\r\nabc"), 1024);
        assertEquals(200, resp.status());
        assertEquals("y", resp.headers().get("x"));
        assertEquals("abc", resp.bodyText());

        HttpResponse eof = Http.readResponse(in("HTTP/1.1 200 OK\r\n\r\nuntil-eof"), 1024);
        assertArrayEquals("until-eof".getBytes(), eof.body());

        HttpResponse up = Http.readResponse(in("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\nRAWBYTES"), 1024);
        assertEquals(101, up.status());

        // Chunked (as Let's Encrypt and most CDNs send), with an extension and a trailer.
        HttpResponse chunked = Http.readResponse(in("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            + "4;ext=1\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\nX-Trailer: t\r\n\r\n"), 1024);
        assertEquals("Wikipedia in\r\n\r\nchunks.", chunked.bodyText());
        assertThrows(HttpException.class, () -> Http.readResponse(in("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"), 1024));
        assertThrows(HttpException.class, () -> Http.readResponse(in("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1000\r\n"), 16));
        // A chunk size that makes the cap arithmetic overflow, which only happens once something
        // has already been counted -- the case above starts at zero and would pass either way.
        // Unchecked, this copies until the peer stops sending, with maxBody meaning nothing.
        assertThrows(HttpException.class, () -> Http.readResponse(
            in("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n7fffffffffffffff\r\n" + "x".repeat(100)), 1024));
        assertThrows(HttpException.class, () -> Http.readResponse(
            in("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nffffffffffffffff\r\n" + "x".repeat(100)), 1024));

        // HEAD: headers only, even with a Content-Length.
        HttpResponse head = Http.readResponse(in("HTTP/1.1 200 OK\r\nContent-Length: 99\r\nReplay-Nonce: n1\r\n\r\n"), 1024, true);
        assertEquals("n1", head.headers().get("Replay-Nonce"));
        assertEquals(0, head.body().length);
        assertEquals(0, up.body().length); // the raw bytes stay in the stream for the next layer

        assertThrows(HttpException.class, () -> Http.readResponse(in("NOPE\r\n\r\n"), 1024));
        assertThrows(HttpException.class, () -> Http.readResponse(in("HTTP/1.1 200 OK\r\n\r\n" + "x".repeat(2000)), 1024));
    }
}
