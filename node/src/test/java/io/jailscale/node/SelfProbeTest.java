package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * DESIGN.md §12.3. The two ends of a TLS 1.3 session derive the same RFC 5705 keying material and
 * nobody else can, so a node can tell whether it was the one that terminated a session carrying
 * its own name. The §12.1 signing conditions do not answer this: the hub enforces those.
 */
@Timeout(60)
class SelfProbeTest {

    /** A throwaway CN=localhost pair; the test trusts exactly it and checks no hostname. */
    private static SSLContext context() throws Exception {
        char[] pw = "changeit".toCharArray();
        Certificate cert;
        try (InputStream in = SelfProbeTest.class.getResourceAsStream("/tls/hub-test.crt")) {
            cert = CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        String pem;
        try (InputStream in = SelfProbeTest.class.getResourceAsStream("/tls/hub-test.key")) {
            pem = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[A-Z ]+-----", ""));
        var key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(der));
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, pw);
        ks.setKeyEntry("k", key, pw, new Certificate[] {cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(ks, pw);
        KeyStore ts = KeyStore.getInstance("PKCS12");
        ts.load(null, pw);
        ts.setCertificateEntry("c", cert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ts);
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    /**
     * One TLS session; returns the keying material each side derived, server first.
     *
     * <p>The server exports only after reading application data. On the server side of TLS 1.3
     * the exporter is not usable until the peer's Finished has been processed, and that has not
     * necessarily happened when {@code startHandshake} returns. The node does the same thing for
     * the same reason (see {@code Visitors}).
     *
     * <p>Server-side failures are carried out rather than swallowed. A null here used to mean
     * "something went wrong somewhere", which said nothing on the one platform where it did.
     */
    private static String[] session(SSLContext ctx) throws Exception {
        try (SSLServerSocket ss = (SSLServerSocket) ctx.getServerSocketFactory()
            .createServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            String[] out = new String[2];
            String[] detail = new String[1];
            Thread server = Thread.ofVirtual().start(() -> {
                try (SSLSocket s = (SSLSocket) ss.accept()) {
                    s.startHandshake();
                    int b = s.getInputStream().read();
                    detail[0] = "protocol=" + s.getSession().getProtocol()
                        + " suite=" + s.getSession().getCipherSuite() + " firstByte=" + b;
                    out[0] = SelfProbe.material(s.getSession());
                    s.getOutputStream().write(2);
                    s.getOutputStream().flush();
                } catch (Exception e) {
                    detail[0] = "server threw " + e;
                    out[0] = null;
                }
            });
            try (SSLSocket c = (SSLSocket) ctx.getSocketFactory()
                .createSocket(InetAddress.getLoopbackAddress(), ss.getLocalPort())) {
                var p = c.getSSLParameters();
                p.setEndpointIdentificationAlgorithm(null);
                c.setSSLParameters(p);
                c.startHandshake();
                c.getOutputStream().write(1);
                c.getOutputStream().flush();
                c.getInputStream().read();
                out[1] = SelfProbe.material(c.getSession());
            }
            server.join();
            lastDetail = detail[0];
            return out;
        }
    }

    /** What the server side saw in the most recent {@link #session}, for failure messages. */
    private static volatile String lastDetail;

    @Test
    void bothEndsOfOneSessionDeriveTheSameMaterial() throws Exception {
        String[] s = session(context());
        assertNotNull(s[0], "server side produced no keying material: " + lastDetail);
        assertNotNull(s[1], "client side produced no keying material: " + lastDetail);
        assertEquals(s[0], s[1], "the two ends of one session must agree");
        assertEquals(SelfProbe.LENGTH * 2, s[0].length(), "expected " + SelfProbe.LENGTH + " bytes as hex");
    }

    @Test
    void aDifferentSessionDerivesDifferentMaterial() throws Exception {
        SSLContext ctx = context();
        // Same certificate, same key, same peers: only the session differs. That is exactly a hub
        // that terminates with the wildcard key and opens its own session onward to the node.
        assertFalse(session(ctx)[0].equals(session(ctx)[0]), "two sessions must not share material");
    }

    @Test
    void recognisesWhatItTerminatedAndRejectsWhatItDidNot() throws Exception {
        SSLContext ctx = context();
        SelfProbe probe = new SelfProbe();
        String[] mine = session(ctx);
        probe.record(mine[0]);

        assertTrue(probe.terminatedHere(mine[1]), "a probe of its own session must be recognised: " + lastDetail);
        assertFalse(probe.terminatedHere(session(ctx)[1]), "a session it never terminated must not be");
        assertFalse(probe.terminatedHere(null), "no material means no claim");
        assertEquals(1, probe.size());
    }

    @Test
    void forgetsOldSessionsSoTheSetStaysBounded() {
        SelfProbe probe = new SelfProbe();
        for (int i = 0; i < SelfProbe.MAX_KEPT + 50; i++) {
            probe.record(String.format("%064x", i));
        }
        assertTrue(probe.size() <= SelfProbe.MAX_KEPT, "kept " + probe.size());
        assertFalse(probe.terminatedHere(String.format("%064x", 0)), "the oldest should have been dropped");
    }
}
