package io.jailscale.proto.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.Test;
import io.jailscale.proto.net.TestPorts;

class SniTest {

    /** Builds a minimal ClientHello record with the given server_name (null for none). */
    static byte[] clientHello(String sni) {
        ByteArrayOutputStream ext = new ByteArrayOutputStream();
        if (sni != null) {
            byte[] name = sni.getBytes(StandardCharsets.US_ASCII);
            int listLen = 3 + name.length;
            ext.write(0); ext.write(0);                     // type server_name
            ext.write((listLen + 2) >> 8); ext.write(listLen + 2);
            ext.write(listLen >> 8); ext.write(listLen);
            ext.write(0);                                   // host_name
            ext.write(name.length >> 8); ext.write(name.length);
            ext.writeBytes(name);
        }
        ext.write(0); ext.write(0x0a); ext.write(0); ext.write(2); ext.write(0); ext.write(0); // dummy extension
        byte[] exts = ext.toByteArray();
        ByteArrayOutputStream hs = new ByteArrayOutputStream();
        hs.write(3); hs.write(3);                           // version
        hs.writeBytes(new byte[32]);                        // random
        hs.write(0);                                        // session id
        hs.write(0); hs.write(2); hs.write(0x13); hs.write(0x01); // cipher suites
        hs.write(1); hs.write(0);                           // compression
        hs.write(exts.length >> 8); hs.write(exts.length);
        hs.writeBytes(exts);
        byte[] body = hs.toByteArray();
        ByteArrayOutputStream rec = new ByteArrayOutputStream();
        rec.write(0x16); rec.write(3); rec.write(1);
        int len = body.length + 4;
        rec.write(len >> 8); rec.write(len);
        rec.write(1); rec.write(0); rec.write(body.length >> 8); rec.write(body.length);
        rec.writeBytes(body);
        return rec.toByteArray();
    }

    @Test
    void parsesServerName() throws Exception {
        byte[] hello = clientHello("MyApp.Hub.Test");
        Sni.Peek p = Sni.peek(new ByteArrayInputStream(hello));
        assertEquals("myapp.hub.test", p.serverName());
        assertArrayEquals(hello, p.consumed());
        assertNull(Sni.peek(new ByteArrayInputStream(clientHello(null))).serverName());
    }

    @Test
    void rejectsNonTls() {
        assertThrows(IOException.class, () -> Sni.peek(new ByteArrayInputStream("GET / HTTP/1.1\r\n".getBytes())));
        assertThrows(IOException.class, () -> Sni.peek(new ByteArrayInputStream(new byte[] {0x16, 3, 1, 0x7f, (byte) 0xff})));
        assertThrows(IOException.class, () -> Sni.peek(new ByteArrayInputStream(new byte[0])));
        byte[] truncated = java.util.Arrays.copyOf(clientHello("a.b"), 20);
        assertThrows(IOException.class, () -> Sni.peek(new ByteArrayInputStream(truncated)));
    }

    /**
     * The record arrives in pieces, which is the normal case on a socket and the whole reason the
     * read is a loop. A one-shot read would return a short buffer here and the parse would fail
     * on a ClientHello that is perfectly good.
     */
    @Test
    void assemblesARecordDeliveredOneByteAtATime() throws Exception {
        byte[] hello = clientHello("dribbled.hub.test");
        Sni.Peek p = Sni.peek(new DribblingStream(hello, 1));
        assertEquals("dribbled.hub.test", p.serverName());
        assertArrayEquals(hello, p.consumed());
        // And in pieces that do not line up with the 5-byte header either.
        for (int chunk : new int[] {2, 3, 7, 4096}) {
            assertEquals("dribbled.hub.test", Sni.peek(new DribblingStream(hello, chunk)).serverName());
        }
    }

    /** Ending part-way through the header and part-way through the body are both refused. */
    @Test
    void refusesEveryTruncationPoint() {
        byte[] hello = clientHello("a.b");
        for (int cut : new int[] {1, 2, 4, 5, 6, 20, hello.length - 1}) {
            byte[] partial = java.util.Arrays.copyOf(hello, cut);
            assertThrows(IOException.class, () -> Sni.peek(new ByteArrayInputStream(partial)),
                "a record cut at " + cut + " bytes must not parse");
        }
    }

    /** A server_name outside the allowed characters is refused, precompiled pattern or not. */
    @Test
    void refusesServerNamesWithCharactersOutsideTheAllowedSet() throws Exception {
        for (String bad : new String[] {"a b.hub.test", "a_b.hub.test", "a/b.hub.test", "a b", "a\u0000b", "a:1.hub.test"}) {
            assertThrows(IOException.class, () -> Sni.peek(new ByteArrayInputStream(clientHello(bad))),
                bad + " should be refused");
        }
        // The characters that are allowed still are, including the dash and dot at every position
        // the label rules leave open -- that check belongs to the hub, not to this parser.
        assertEquals("a-b.c-d.hub.test",
            Sni.peek(new ByteArrayInputStream(clientHello("A-B.C-D.Hub.Test"))).serverName());
    }

    /** An InputStream that hands out at most {@code chunk} bytes per read, like a socket does. */
    private static final class DribblingStream extends java.io.InputStream {
        private final byte[] data;
        private final int chunk;
        private int pos;

        DribblingStream(byte[] data, int chunk) {
            this.data = data;
            this.chunk = chunk;
        }

        @Override
        public int read() {
            return pos < data.length ? data[pos++] & 0xff : -1;
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (pos >= data.length) {
                return -1;
            }
            int n = Math.min(Math.min(len, chunk), data.length - pos);
            System.arraycopy(data, pos, b, off, n);
            pos += n;
            return n;
        }
    }

    @Test
    void parsesARealJdkClientHello() throws Exception {
        try (ServerSocket ss = TestPorts.listen(1)) {
            Thread client = Thread.ofVirtual().start(() -> {
                try {
                    SSLSocket s = (SSLSocket) SSLContext.getDefault().getSocketFactory().createSocket();
                    s.connect(new java.net.InetSocketAddress(InetAddress.getLoopbackAddress(), ss.getLocalPort()), 2000);
                    SSLParameters p = s.getSSLParameters();
                    p.setServerNames(List.of(new SNIHostName("real.hub.test")));
                    s.setSSLParameters(p);
                    s.startHandshake();
                } catch (IOException | java.security.NoSuchAlgorithmException ignored) {
                    // the server never answers; we only want the ClientHello
                }
            });
            try (Socket srv = ss.accept()) {
                srv.setSoTimeout(5000);
                Sni.Peek p = Sni.peek(srv.getInputStream());
                assertEquals("real.hub.test", p.serverName());
            }
            client.interrupt();
        }
    }
}
