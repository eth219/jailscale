package io.jailscale.proto;

import static org.junit.jupiter.api.Assertions.fail;

import io.jailscale.proto.control.Codec;
import io.jailscale.proto.control.CodecException;
import io.jailscale.proto.control.Message;
import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonException;
import io.jailscale.proto.mux.Frame;
import io.jailscale.proto.mux.MuxException;
import io.jailscale.proto.net.ProxyProtocol;
import io.jailscale.proto.tls.Sni;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Mutation fuzzing of every parser that faces the network (ARCHITECTURE.md §14): valid
 * inputs get bytes flipped, inserted, deleted and truncated; the only acceptable outcomes are a
 * result or the parser's declared exception. Anything else (index errors, NPEs, negative sizes,
 * OOM-sized allocations) is a bug. Deterministic seed, ~10k cases per parser, a few seconds.
 */
@Timeout(120)
class FuzzTest {

    private static final int ROUNDS = 10_000;
    private static final Random RNG = new Random(0x6a61696c);

    /** Runs {@code parser} on mutations of {@code seeds}; {@code ok} lists the exception types a parser may throw. */
    private static void fuzz(String name, List<byte[]> seeds, Consumer<byte[]> parser, Class<?>... ok) {
        for (int i = 0; i < ROUNDS; i++) {
            byte[] seed = seeds.get(i % seeds.size());
            byte[] input = i < seeds.size() ? seed : mutate(seed);
            try {
                parser.accept(input);
            } catch (Throwable thrown) {
                Throwable t = thrown;
                if ((t.getClass() == RuntimeException.class || t instanceof java.io.UncheckedIOException) && t.getCause() != null) {
                    t = t.getCause(); // unwrapped checked exception from the parser
                }
                boolean allowed = false;
                for (Class<?> c : ok) {
                    if (c.isInstance(t)) {
                        allowed = true;
                    }
                }
                if (!allowed) {
                    fail(name + " case " + i + " threw " + t + " on " + hex(input), t);
                }
            }
        }
    }

    private static byte[] mutate(byte[] seed) {
        byte[] b = seed.clone();
        int ops = 1 + RNG.nextInt(4);
        for (int k = 0; k < ops; k++) {
            switch (RNG.nextInt(6)) {
                case 0 -> { // flip a byte
                    if (b.length > 0) {
                        b[RNG.nextInt(b.length)] = (byte) RNG.nextInt(256);
                    }
                }
                case 1 -> { // flip a bit
                    if (b.length > 0) {
                        b[RNG.nextInt(b.length)] ^= (byte) (1 << RNG.nextInt(8));
                    }
                }
                case 2 -> b = java.util.Arrays.copyOf(b, RNG.nextInt(b.length + 1)); // truncate
                case 3 -> { // insert random bytes
                    byte[] ins = new byte[1 + RNG.nextInt(8)];
                    RNG.nextBytes(ins);
                    int at = RNG.nextInt(b.length + 1);
                    byte[] n = new byte[b.length + ins.length];
                    System.arraycopy(b, 0, n, 0, at);
                    System.arraycopy(ins, 0, n, at, ins.length);
                    System.arraycopy(b, at, n, at + ins.length, b.length - at);
                    b = n;
                }
                case 4 -> { // delete a run
                    if (b.length > 1) {
                        int at = RNG.nextInt(b.length);
                        int len = 1 + RNG.nextInt(Math.min(8, b.length - at));
                        byte[] n = new byte[b.length - len];
                        System.arraycopy(b, 0, n, 0, at);
                        System.arraycopy(b, at + len, n, at, b.length - at - len);
                        b = n;
                    }
                }
                default -> { // set a length-ish field to an extreme
                    if (b.length > 1) {
                        int at = RNG.nextInt(b.length - 1);
                        b[at] = (byte) (RNG.nextBoolean() ? 0xff : 0);
                        b[at + 1] = (byte) (RNG.nextBoolean() ? 0xff : 0);
                    }
                }
            }
        }
        return b;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(b.length, 64); i++) {
            sb.append(String.format("%02x", b[i]));
        }
        return sb + (b.length > 64 ? "…(" + b.length + ")" : "");
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static void unchecked(ThrowingParser p, byte[] in) {
        try {
            p.parse(in);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        } catch (HttpException | MuxException | CodecException e) {
            throw new RuntimeException(e);
        }
    }

    interface ThrowingParser {
        void parse(byte[] in) throws IOException, HttpException, MuxException, CodecException;
    }

    @Test
    void sniClientHello() throws Exception {
        // A real-shaped TLS 1.3 ClientHello with an SNI extension, plus small variants.
        byte[] hello = clientHello("demo.hub.example.com");
        fuzz("sni", List.of(hello, clientHello("a"), clientHello("x".repeat(250))),
            in -> unchecked(b -> Sni.peek(new ByteArrayInputStream(b)), in), IOException.class);
    }

    @Test
    void httpRequestsAndResponses() {
        List<byte[]> reqs = List.of(
            ascii("GET /v1/key HTTP/1.1\r\nHost: hub\r\nAccept: application/json\r\n\r\n"),
            ascii("POST /v1/noise HTTP/1.1\r\nHost: hub\r\nConnection: Upgrade\r\nUpgrade: jailscale-control-v1\r\nContent-Length: 3\r\n\r\nabc"),
            ascii("POST /admin/approve HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\n\r\ncsrf=1&x=%41"),
            ascii("GET /?jail=abc HTTP/1.0\r\nCookie: jail=x; a=b\r\n\r\n"));
        fuzz("http-request", reqs, in -> unchecked(b -> Http.readRequest(new ByteArrayInputStream(b), 4096), in),
            IOException.class, HttpException.class);
        List<byte[]> resps = List.of(
            ascii("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"),
            ascii("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n0\r\n\r\n"),
            ascii("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n"),
            ascii("HTTP/1.1 302 Found\r\nLocation: /admin\r\nSet-Cookie: a=b; Path=/\r\n\r\n"));
        fuzz("http-response", resps, in -> unchecked(b -> Http.readResponse(new ByteArrayInputStream(b), 4096), in),
            IOException.class, HttpException.class);
    }

    @Test
    void muxFrames() {
        List<byte[]> frames = List.of(
            Frame.data(7, new byte[100]).encode(),
            Frame.ctrl(ascii("{\"t\":\"Ping\",\"id\":1}")).encode(),
            Frame.window(3, 65536).encode(),
            Frame.rst(9, 2).encode(),
            Frame.keepalive().encode(),
            new Frame(4, Frame.OPEN, Frame.FLAG_DGRAM, ascii("{\"linkId\":\"l_1\"}")).encode());
        fuzz("mux-frame", frames, in -> unchecked(b -> Frame.decode(b), in), MuxException.class);
    }

    @Test
    void jsonAndControlMessages() {
        List<byte[]> docs = List.of(
            ascii("{\"a\":1,\"b\":[true,false,null,1.5e3,\"s\\u00e9\\n\"],\"c\":{\"d\":{}}}"),
            ascii("[1,2,3,[[[]]],\"\\\"\"]"),
            ascii("{\"t\":\"Hello\",\"proto\":1,\"version\":\"0.1\",\"os\":\"macos\",\"conn\":0}"),
            ascii("{\"t\":\"LinkOpen\",\"kind\":\"https\",\"name\":\"demo\",\"local\":\"127.0.0.1:3000\",\"chainPem\":[\"x\"]}"),
            ascii("{\"t\":\"SignRequest\",\"streamId\":16777217,\"keyId\":\"k\",\"alg\":\"NONEwithECDSA\",\"digest\":\"AAECAw==\"}"));
        fuzz("json", docs, in -> Json.parse(in), JsonException.class);
        fuzz("codec", docs, in -> unchecked(b -> Codec.decode(b), in), CodecException.class, JsonException.class);
        // Encode/decode round trip must hold for every message the codec produces.
        try {
            Message m = Codec.decode(Codec.encode(new Message.Hello(1, "v", "os", 2)));
            if (!(m instanceof Message.Hello h) || h.conn() != 2) {
                fail("round trip");
            }
        } catch (CodecException e) {
            fail(e);
        }
    }

    @Test
    void proxyProtocolHeaders() {
        byte[] v2 = new byte[16 + 12];
        System.arraycopy(new byte[] {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, 0x21, 0x11, 0, 12}, 0, v2, 0, 16);
        fuzz("proxy", List.of(ascii("PROXY TCP4 203.0.113.5 10.0.0.1 51234 443\r\n"), ascii("PROXY TCP6 2001:db8::1 ::1 1 2\r\n"), v2),
            in -> unchecked(b -> ProxyProtocol.read(new ByteArrayInputStream(b)), in), IOException.class);
    }

    /** TLS 1.2-style ClientHello record carrying only an SNI extension (enough for the peek). */
    static byte[] clientHello(String name) throws IOException {
        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        byte[] host = name.getBytes(StandardCharsets.US_ASCII);
        int listLen = 3 + host.length;
        ext.write(new byte[] {0, 0, (byte) ((listLen + 2) >> 8), (byte) (listLen + 2), (byte) (listLen >> 8), (byte) listLen, 0,
            (byte) (host.length >> 8), (byte) host.length});
        ext.write(host);
        byte[] exts = ext.toByteArray();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(new byte[] {3, 3});
        body.write(new byte[32]);
        body.write(0);                                  // session id
        body.write(new byte[] {0, 2, 0x13, 0x01});      // cipher suites
        body.write(new byte[] {1, 0});                  // compression
        body.write(new byte[] {(byte) (exts.length >> 8), (byte) exts.length});
        body.write(exts);
        byte[] hs = body.toByteArray();
        ByteArrayOutputStream rec = new ByteArrayOutputStream();
        int hsLen = hs.length + 4;
        rec.write(new byte[] {0x16, 3, 1, (byte) (hsLen >> 8), (byte) hsLen, 1, (byte) (hs.length >> 16), (byte) (hs.length >> 8), (byte) hs.length});
        rec.write(hs);
        return rec.toByteArray();
    }
}
