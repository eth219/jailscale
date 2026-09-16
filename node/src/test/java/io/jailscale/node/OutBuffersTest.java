package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.tls.Tls;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import io.jailscale.proto.net.TestPorts;

/**
 * The shared wrap buffers of {@link TlsEndpoint} (ARCHITECTURE.md §15). A buffer that moves between
 * connections is only safe while every read out of it is bounded by what {@code wrap} just put
 * there; the bytes past that limit are the previous borrower's ciphertext. These drive real TLS
 * sessions through the endpoint and check that each one gets its own bytes and nobody else's.
 */
@Timeout(120)
class OutBuffersTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
    private static final String HOST = "pooled.hub.test";

    private static SSLContext server;

    @BeforeAll
    static void material() throws Exception {
        List<X509Certificate> chain = Pem.certificates(Files.readString(CERT));
        PrivateKey key = Pem.privateKey(Files.readString(KEY));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("k", key, new char[0], chain.toArray(new X509Certificate[0]));
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        server = SSLContext.getInstance("TLS");
        server.init(kmf.getKeyManagers(), null, null);
    }

    /**
     * One session: the node side is a {@link TlsEndpoint}, which echoes back a body built from
     * {@code tag} so that a response carrying another session's bytes cannot pass for this one.
     * The sizes straddle a TLS record, so a session writes several records through the buffer.
     */
    private String roundTrip(String tag, int bodySize) throws Exception {
        try (ServerSocket ss = TestPorts.listen(1)) {
            Thread node = Thread.ofVirtual().start(() -> {
                try (Socket s = ss.accept()) {
                    TlsEndpoint tls = new TlsEndpoint(server, s.getInputStream(), s.getOutputStream());
                    tls.handshake();
                    InputStream in = tls.plainIn();
                    byte[] req = new byte[64];
                    in.read(req);
                    OutputStream out = tls.plainOut();
                    // A distinctive body: every byte of it identifies this session.
                    byte[] body = new byte[bodySize];
                    byte fill = (byte) tag.charAt(0);
                    java.util.Arrays.fill(body, fill);
                    out.write(("HTTP/1.1 200 OK\r\nContent-Length: " + bodySize + "\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                    out.write(body);
                    out.flush();
                    tls.close();
                } catch (Exception e) {
                    // the client sees it as a broken session and the assertion below fails
                }
            });
            SSLContext cc = Tls.clientContext(CERT, false);
            try (SSLSocket s = (SSLSocket) cc.getSocketFactory().createSocket("127.0.0.1", ss.getLocalPort())) {
                SSLParameters p = s.getSSLParameters();
                p.setServerNames(List.of(new SNIHostName(HOST)));
                p.setProtocols(new String[] {"TLSv1.3"});
                s.setSSLParameters(p);
                s.startHandshake();
                s.getOutputStream().write(("GET /" + tag + " HTTP/1.1\r\nHost: " + HOST + "\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
                s.getOutputStream().flush();
                byte[] all = s.getInputStream().readAllBytes();
                node.join();
                return new String(all, StandardCharsets.ISO_8859_1);
            }
        }
    }

    /** The body a session is supposed to have got back: bodySize copies of its own tag character. */
    private static void assertOwnBody(String tag, int bodySize, String response) {
        int sep = response.indexOf("\r\n\r\n");
        assertTrue(sep > 0, "no response head for " + tag + ": " + response.substring(0, Math.min(80, response.length())));
        String body = response.substring(sep + 4);
        assertEquals(bodySize, body.length(), "wrong body length for " + tag);
        for (int i = 0; i < body.length(); i++) {
            assertEquals(tag.charAt(0), body.charAt(i),
                "session " + tag + " got a byte that is not its own at offset " + i);
        }
    }

    /**
     * Sessions one after another, so each reuses the buffer the last one returned. A buffer that
     * is not cleared, or a read that is not bounded by what wrap produced, shows up here as a
     * session receiving bytes it never sent.
     */
    @Test
    void sequentialSessionsReusingABufferEachGetTheirOwnBytes() throws Exception {
        // Sizes around the 16 KiB record boundary, alternating small and large: a small record
        // followed by a large one is what catches a buffer whose limit was left where it was.
        int[] sizes = {40_000, 10, 33_000, 5, 17_000, 1, 40_000};
        String tags = "abcdefg";
        for (int i = 0; i < sizes.length; i++) {
            String tag = String.valueOf(tags.charAt(i));
            assertOwnBody(tag, sizes[i], roundTrip(tag, sizes[i]));
        }
    }

    /** Concurrent sessions, contending for the same pool, must not cross bytes either. */
    @Test
    void concurrentSessionsDoNotCrossBytes() throws Exception {
        // Raise with -Doutbuffers.sessions=N to lean on the pool harder than the default.
        int n = Integer.getInteger("outbuffers.sessions", 24);
        CountDownLatch go = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        ConcurrentLinkedQueue<String> failures = new ConcurrentLinkedQueue<>();
        AtomicInteger ok = new AtomicInteger();
        for (int i = 0; i < n; i++) {
            String tag = String.valueOf((char) ('A' + (i % 26)));
            int size = 8_000 + i * 1_500;
            Thread.ofVirtual().start(() -> {
                try {
                    go.await();
                    assertOwnBody(tag, size, roundTrip(tag, size));
                    ok.incrementAndGet();
                } catch (Throwable t) {
                    failures.add(tag + ": " + t);
                } finally {
                    done.countDown();
                }
            });
        }
        go.countDown();
        assertTrue(done.await(90, TimeUnit.SECONDS), "sessions did not finish");
        assertTrue(failures.isEmpty(), "sessions failed: " + failures);
        assertEquals(n, ok.get());
    }

    /**
     * The pool keeps at most MAX_IDLE buffers, whatever the traffic was. Without the cap the
     * retained set would grow to the high-water concurrency and stay there, which is the shape of
     * the per-connection allocation this replaced.
     */
    @Test
    void thePoolRetainsNoMoreThanItsCap() throws Exception {
        concurrentSessionsDoNotCrossBytes();
        assertTrue(TlsEndpoint.pooledBuffers() <= TlsEndpoint.maxIdleBuffers(),
            "pool kept " + TlsEndpoint.pooledBuffers() + " buffers, cap is " + TlsEndpoint.maxIdleBuffers());
        // And it does keep some: a pool that never reuses anything would be the old allocation
        // per wrap, only with extra bookkeeping.
        assertTrue(TlsEndpoint.pooledBuffers() > 0, "nothing was returned to the pool");
    }
}
