package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.tls.Tls13;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * ARCHITECTURE.md §9.2: at the moment JSSE asks for a CertificateVerify signature, the node must be
 * able to rebuild the handshake messages the transcript hash covers, and the hub must get the same
 * hash from the ClientHello it delivered. Run against JSSE itself, with a local key standing in for
 * the hub's, so that a JDK that starts writing its ServerHello or EncryptedExtensions differently
 * fails here and not in production.
 */
@Timeout(60)
class TranscriptTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
    private static final String HOST = "myapp.hub.test";

    /** What the signer saw: JSSE's content, and the reconstruction made from the endpoint's state. */
    record Signed(byte[] content, Transcript.Reconstructed t, List<byte[]> clientMessages, Exception failure) {}

    private static final AtomicReference<TlsEndpoint> ENDPOINT = new AtomicReference<>();
    private static final AtomicReference<Signed> SIGNED = new AtomicReference<>();
    private static List<X509Certificate> chain;
    private static byte[] certificateMessage;
    private static PrivateKey realKey;

    /** A key JSSE cannot use itself, so that the provider below is chosen, as for the hub's key. */
    static final class LocalKey implements PrivateKey {
        private static final long serialVersionUID = 1L;
        public String getAlgorithm() { return "EC"; }
        public String getFormat() { return null; }
        public byte[] getEncoded() { return null; }
    }

    public static final class Signer extends SignatureSpi {
        private final ByteArrayOutputStream content = new ByteArrayOutputStream();
        @Override protected void engineInitVerify(PublicKey k) throws InvalidKeyException { throw new InvalidKeyException(); }
        @Override protected void engineInitSign(PrivateKey k) { content.reset(); }
        @Override protected void engineUpdate(byte b) { content.write(b); }
        @Override protected void engineUpdate(byte[] b, int off, int len) { content.write(b, off, len); }
        @Override protected boolean engineVerify(byte[] s) { return false; }
        @Override @SuppressWarnings("deprecation") protected void engineSetParameter(String p, Object v) {}
        @Override @SuppressWarnings("deprecation") protected Object engineGetParameter(String p) { return null; }

        @Override
        protected byte[] engineSign() throws SignatureException {
            byte[] bytes = content.toByteArray();
            TlsEndpoint tls = ENDPOINT.get();
            Transcript.Reconstructed t = null;
            Exception failure = null;
            try {
                t = Transcript.reconstruct(tls.clientMessages(), tls.serverMessages(), RemoteSigning.RANDOM.draws(),
                    tls.handshakeSession().getCipherSuite(), certificateMessage, bytes);
            } catch (GeneralSecurityException e) {
                failure = e;
            }
            SIGNED.set(new Signed(bytes, t, tls.clientMessages(), failure));
            try {
                Signature real = Signature.getInstance("SHA256withECDSA", "SunEC");
                real.initSign(realKey);
                real.update(bytes);
                return real.sign();
            } catch (GeneralSecurityException e) {
                throw new SignatureException(e);
            }
        }
    }

    static final class LocalProvider extends Provider {
        private static final long serialVersionUID = 1L;
        LocalProvider() {
            super("TranscriptTestLocal", "1", "");
            putService(new Provider.Service(this, "Signature", "SHA256withECDSA", Signer.class.getName(), List.of(), Map.of()) {
                @Override public Object newInstance(Object p) { return new Signer(); }
                @Override public boolean supportsParameter(Object p) { return p instanceof LocalKey; }
            });
        }
    }

    static final class LocalKeyManager extends X509ExtendedKeyManager {
        private final X509Certificate[] c = chain.toArray(new X509Certificate[0]);
        public String[] getClientAliases(String a, Principal[] b) { return null; }
        public String chooseClientAlias(String[] a, Principal[] b, Socket c) { return null; }
        public String[] getServerAliases(String a, Principal[] b) { return new String[] {"k"}; }
        public String chooseServerAlias(String a, Principal[] b, Socket c) { return "k"; }
        @Override public String chooseEngineServerAlias(String a, Principal[] b, SSLEngine e) { return "k"; }
        public X509Certificate[] getCertificateChain(String a) { return c; }
        public PrivateKey getPrivateKey(String a) { return new LocalKey(); }
    }

    @BeforeAll
    static void material() throws Exception {
        chain = Pem.certificates(Files.readString(CERT));
        realKey = Pem.privateKey(Files.readString(KEY));
        certificateMessage = Tls13.certificateMessage(chain);
        Security.addProvider(new LocalProvider());
    }

    @AfterAll
    static void cleanup() {
        Security.removeProvider("TranscriptTestLocal");
    }

    /** One handshake: the node side through {@link TlsEndpoint}, a JSSE client configured by {@code client}. */
    private Signed handshake(java.util.function.Consumer<SSLParameters> client, String[] alpn) throws Exception {
        SSLContext server = SSLContext.getInstance("TLS");
        server.init(new KeyManager[] {new LocalKeyManager()}, null, RemoteSigning.RANDOM);
        SIGNED.set(null);
        try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread node = Thread.ofVirtual().start(() -> {
                try (Socket s = ss.accept()) {
                    TlsEndpoint tls = new TlsEndpoint(server, s.getInputStream(), s.getOutputStream());
                    ENDPOINT.set(tls);
                    RemoteSigning.enter(new RemoteSigning.Context(null, null, 1, "k", tls));
                    try {
                        tls.handshake();
                    } finally {
                        RemoteSigning.exit();
                    }
                    tls.plainOut().write("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".getBytes());
                    tls.plainOut().flush();
                    tls.plainIn().read();
                } catch (Exception e) {
                    // the client sees the failure as a broken handshake
                }
            });
            SSLContext cc = Tls.clientContext(CERT, false);
            try (SSLSocket s = (SSLSocket) cc.getSocketFactory().createSocket("127.0.0.1", ss.getLocalPort())) {
                SSLParameters p = s.getSSLParameters();
                p.setServerNames(List.of(new SNIHostName(HOST)));
                p.setApplicationProtocols(alpn);
                p.setProtocols(new String[] {"TLSv1.3"});
                client.accept(p);
                s.setSSLParameters(p);
                s.startHandshake();
                s.getOutputStream().write("GET / HTTP/1.1\r\nHost: x\r\n\r\n".getBytes());
                s.getOutputStream().flush();
                assertTrue(s.getInputStream().read() > 0);
            }
            node.join();
        }
        Signed signed = SIGNED.get();
        assertNotNull(signed, "JSSE never asked for a signature");
        return signed;
    }

    /** What the hub does with the request: its own copy of the ClientHello(s) plus what the node sent. */
    private static byte[] hubSide(List<byte[]> clientHellos, Transcript.Reconstructed t, byte[] content) throws Exception {
        return Tls13.transcriptHash(Tls13.hashAlgorithmOf(content), clientHellos, t.helloRetryRequest(), t.serverHello(),
            t.encryptedExtensions(), certificateMessage);
    }

    @Test
    void plainHandshakeIsReconstructedAndTheHubGetsTheSameHash() throws Exception {
        Signed s = handshake(p -> { }, new String[] {"h2", "http/1.1"});
        assertNull(s.failure(), String.valueOf(s.failure()));
        assertEquals(1, s.clientMessages().size());
        assertNull(s.t().helloRetryRequest());
        assertArrayEquals(Tls13.transcriptHashIn(s.content()), hubSide(s.clientMessages(), s.t(), s.content()));
        // the EncryptedExtensions carried the one group and the ALPN choice
        assertArrayEquals(Tls13.encryptedExtensions(true, TlsEndpoint.GROUP_IDS, "http/1.1", true), s.t().encryptedExtensions());
    }

    @Test
    void retryHandshakeIsReconstructedWithTheMessageHashRule() throws Exception {
        // JSSE's client sends key shares for its first four groups; with X25519 fifth it offers
        // none the server takes, and gets a HelloRetryRequest for X25519.
        Signed s = handshake(p -> p.setNamedGroups(new String[] {"secp256r1", "secp384r1", "secp521r1", "ffdhe2048", "x25519"}),
            new String[] {"http/1.1"});
        assertNull(s.failure(), String.valueOf(s.failure()));
        assertEquals(2, s.clientMessages().size(), "two ClientHellos around the retry");
        assertNotNull(s.t().helloRetryRequest());
        assertTrue(Tls13.isHelloRetryRequest(s.t().helloRetryRequest()));
        assertArrayEquals(Tls13.transcriptHashIn(s.content()), hubSide(s.clientMessages(), s.t(), s.content()));
    }

    @Test
    void otherSuitesAndNoAlpnStillReconstruct() throws Exception {
        Signed s = handshake(p -> p.setCipherSuites(new String[] {"TLS_AES_128_GCM_SHA256"}), new String[0]);
        assertNull(s.failure(), String.valueOf(s.failure()));
        assertEquals("SHA-256", Tls13.hashAlgorithmOf(s.content()));
        assertArrayEquals(Tls13.transcriptHashIn(s.content()), hubSide(s.clientMessages(), s.t(), s.content()));
        assertArrayEquals(Tls13.encryptedExtensions(true, TlsEndpoint.GROUP_IDS, "http/1.1", false), s.t().encryptedExtensions());
        Signed chacha = handshake(p -> p.setCipherSuites(new String[] {"TLS_CHACHA20_POLY1305_SHA256"}), new String[] {"http/1.1"});
        assertNull(chacha.failure(), String.valueOf(chacha.failure()));
        assertArrayEquals(Tls13.transcriptHashIn(chacha.content()), hubSide(chacha.clientMessages(), chacha.t(), chacha.content()));
    }

    @Test
    void aSignatureIsBoundToTheClientHelloTheHubDelivered() throws Exception {
        // Two independent visitors. The hub holding visitor A's ClientHello must not produce the
        // hash of visitor B's handshake from B's ServerHello and EncryptedExtensions: that is the
        // on-path member's forged handshake, and it is what the check exists to refuse.
        Signed a = handshake(p -> { }, new String[] {"http/1.1"});
        Signed b = handshake(p -> { }, new String[] {"http/1.1"});
        assertNull(a.failure());
        assertNull(b.failure());
        byte[] forged = hubSide(a.clientMessages(), b.t(), b.content());
        assertFalse(Arrays.equals(forged, Tls13.transcriptHashIn(b.content())));
        // and the reconstruction itself refuses when its inputs are not this handshake's
        assertThrows(GeneralSecurityException.class, () -> Transcript.reconstruct(a.clientMessages(), List.of(), List.of(new byte[32]),
            "TLS_AES_256_GCM_SHA384", certificateMessage, b.content()));
    }
}
