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

    @Test
    void parsesARealJdkClientHello() throws Exception {
        try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
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
