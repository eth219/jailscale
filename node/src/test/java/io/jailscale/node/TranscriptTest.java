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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
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
 *
 * <p><strong>What this is protecting, and why it is not a redundant assertion about JSSE.</strong>
 * {@code Tls13.serverHello} and {@code Tls13.encryptedExtensions} do not read those messages off
 * the wire — JSSE never shows them — they *predict* their bytes, down to the order of the
 * extensions. A JDK that writes the same handshake a different way makes every hub-signed
 * handshake fail at the node until the prediction is updated. It cannot weaken the binding, since
 * the hub recomputes the hash itself, but it is an outage on somebody else's release schedule, and
 * this class is the only thing that catches it before the toolchain pin moves (issue #78;
 * CONTRIBUTING.md says to run it when the pin does move). So it must not be simplified into "the
 * handshake succeeded": the handshake succeeds whether or not the reconstruction matched, because
 * the signature is made from the real key either way.
 *
 * <p>Two different things can fail here and the messages keep them apart. A <em>changed
 * encoding</em> is the risk above and shows up as a reconstruction that no longer matches; a
 * <em>changed handshake</em> is a JDK that negotiates differently — other key shares by default,
 * so no HelloRetryRequest — which breaks this test's setup rather than the prediction, and is
 * fixed here rather than in {@code Tls13}.
 */
@Timeout(60)
class TranscriptTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
    private static final String HOST = "myapp.hub.test";

    /** What the signer saw: JSSE's content, the reconstruction, and every input it was made from. */
    record Signed(byte[] content, Transcript.Reconstructed t, List<byte[]> clientMessages, List<byte[]> serverMessages,
        List<byte[]> randomChunks, String cipherSuite, Exception failure) {}

    /**
     * What a reconstruction failure in this class means. Spelled out at each assertion because the
     * message is most of the value of the failure: whoever sees it is moving a toolchain pin.
     */
    private static final String ENCODING_CHANGED = "this JDK no longer writes the ServerHello or EncryptedExtensions "
        + "the way Tls13 predicts, so every hub-signed handshake is down until the prediction is updated "
        + "(ARCHITECTURE.md §9.2). The reconstruction said: ";

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
            // Snapshots, taken where the node takes them: before its own flight is on the wire.
            List<byte[]> clientMessages = tls.clientMessages();
            List<byte[]> serverMessages = tls.serverMessages();
            List<byte[]> draws = RemoteSigning.RANDOM.draws();
            String suite = tls.handshakeSession().getCipherSuite();
            Transcript.Reconstructed t = null;
            Exception failure = null;
            try {
                t = Transcript.reconstruct(clientMessages, serverMessages, draws, suite, certificateMessage, bytes);
            } catch (GeneralSecurityException e) {
                failure = e;
            }
            SIGNED.set(new Signed(bytes, t, clientMessages, serverMessages, draws, suite, failure));
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

    /**
     * What the hub does with the request: its own copy of the ClientHello(s) plus what the node
     * sent. The two server messages are parameters because the refusal test below asks for the same
     * recipe with a differently written pair, and the hub's transcript should exist here once.
     */
    private static byte[] hubSide(List<byte[]> clientHellos, byte[] hrr, byte[] serverHello, byte[] encryptedExtensions,
        byte[] content) throws GeneralSecurityException {
        return Tls13.transcriptHash(Tls13.hashAlgorithmOf(content), clientHellos, hrr, serverHello, encryptedExtensions,
            certificateMessage);
    }

    private static byte[] hubSide(List<byte[]> clientHellos, Transcript.Reconstructed t, byte[] content)
        throws GeneralSecurityException {
        return hubSide(clientHellos, t.helloRetryRequest(), t.serverHello(), t.encryptedExtensions(), content);
    }

    @Test
    void plainHandshakeIsReconstructedAndTheHubGetsTheSameHash() throws Exception {
        Signed s = handshake(p -> { }, new String[] {"h2", "http/1.1"});
        assertNull(s.failure(), ENCODING_CHANGED + s.failure());
        assertEquals(1, s.clientMessages().size(),
            "more than one ClientHello without a retry being asked for. That is a changed handshake and not a changed "
                + "encoding: this JDK's client is negotiating differently, so fix the expectation, not Tls13");
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
        assertNull(s.failure(), ENCODING_CHANGED + s.failure());
        assertEquals(2, s.clientMessages().size(),
            "no HelloRetryRequest happened, so the retry path was not exercised. That is a changed handshake and not a "
                + "changed encoding: this JDK's client offered a key share the server took. Fix the setup above, do not "
                + "delete the test -- the message_hash rule of RFC 8446 §4.4.1 is covered nowhere else");
        assertNotNull(s.t().helloRetryRequest());
        assertTrue(Tls13.isHelloRetryRequest(s.t().helloRetryRequest()));
        assertArrayEquals(Tls13.transcriptHashIn(s.content()), hubSide(s.clientMessages(), s.t(), s.content()));
    }

    @Test
    void otherSuitesAndNoAlpnStillReconstruct() throws Exception {
        Signed s = handshake(p -> p.setCipherSuites(new String[] {"TLS_AES_128_GCM_SHA256"}), new String[0]);
        assertNull(s.failure(), ENCODING_CHANGED + s.failure());
        assertEquals("SHA-256", Tls13.hashAlgorithmOf(s.content()));
        assertArrayEquals(Tls13.transcriptHashIn(s.content()), hubSide(s.clientMessages(), s.t(), s.content()));
        assertArrayEquals(Tls13.encryptedExtensions(true, TlsEndpoint.GROUP_IDS, "http/1.1", false), s.t().encryptedExtensions());
        Signed chacha = handshake(p -> p.setCipherSuites(new String[] {"TLS_CHACHA20_POLY1305_SHA256"}), new String[] {"http/1.1"});
        assertNull(chacha.failure(), ENCODING_CHANGED + chacha.failure());
        assertArrayEquals(Tls13.transcriptHashIn(chacha.content()), hubSide(chacha.clientMessages(), chacha.t(), chacha.content()));
    }

    @Test
    void aSignatureIsBoundToTheClientHelloTheHubDelivered() throws Exception {
        // Two independent visitors. The hub holding visitor A's ClientHello must not produce the
        // hash of visitor B's handshake from B's ServerHello and EncryptedExtensions: that is the
        // on-path member's forged handshake, and it is what the check exists to refuse.
        Signed a = handshake(p -> { }, new String[] {"http/1.1"});
        Signed b = handshake(p -> { }, new String[] {"http/1.1"});
        assertNull(a.failure(), ENCODING_CHANGED + a.failure());
        assertNull(b.failure(), ENCODING_CHANGED + b.failure());
        byte[] forged = hubSide(a.clientMessages(), b.t(), b.content());
        assertFalse(Arrays.equals(forged, Tls13.transcriptHashIn(b.content())));
        // and the reconstruction itself refuses when its inputs are not this handshake's
        assertThrows(GeneralSecurityException.class, () -> Transcript.reconstruct(a.clientMessages(), List.of(), List.of(new byte[32]),
            "TLS_AES_256_GCM_SHA384", certificateMessage, b.content()));
    }

    @Test
    void aChangedEncodingOfTheSameHandshakeIsWhatThisFails() throws Exception {
        // The direction the tests above cannot show. They run against one JDK and assert that its
        // encoding was predicted; none of them says what happens when a JDK predicts it *wrongly*,
        // and a reconstruction that had quietly stopped comparing would pass every one of them.
        // So: keep this handshake exactly as JSSE negotiated it -- same ClientHello, same random
        // draws, same suite -- and ask for the transcript of the same handshake written some other
        // way. Each must be refused.
        Signed s = handshake(p -> { }, new String[] {"http/1.1"});
        assertNull(s.failure(), ENCODING_CHANGED + s.failure());
        byte[] sh = s.t().serverHello();
        byte[] ee = s.t().encryptedExtensions();
        // Both variants below reorder a pair, so a parser that found fewer than two would make the
        // reordering a no-op and the refusal vacuous. This is the same guard `refuses` applies to
        // the bytes, one level up, and it is what stops a mis-parse from reading as a pass.
        assertEquals(2, extensionsOf(sh).size(), "the ServerHello should carry supported_versions and key_share");
        assertEquals(2, extensionsOf(ee).size(), "EncryptedExtensions should carry supported_groups and ALPN here");

        // The control. Synthesising a CertificateVerify content from the reconstruction JSSE itself
        // agreed with must reconstruct; without it, the refusals below would only be saying that
        // this test builds its inputs wrongly.
        assertNotNull(reconstructAsIf(s, sh, ee), "the unperturbed encoding must still reconstruct");

        // What these hold to their word is the strictness of Transcript.reconstruct, one direction
        // each. A single perturbed hash byte would show that it compares *at all*; it would not
        // show that it refuses an EncryptedExtensions with an SNI acknowledgement, because against
        // a corrupted hash a reconstruction lenient in exactly that way still finds nothing and
        // still throws. Measured, by making Transcript accept that one pair: the bit-flip version
        // of this test passes and the fourth line below fails.
        //
        // What they do NOT do, since each is derived from Tls13's own output: say that the
        // prediction is right. Reverse the order in Tls13.serverHello and the first variant simply
        // reverses the new order and is refused just the same. Only the live handshakes above can
        // fail for that, and they do.
        refuses(s, rewriteExtensions(sh, TranscriptTest::reversed), ee, "the ServerHello's extensions in the other order");
        refuses(s, legacyVersion(sh, 0x0304), ee, "a ServerHello carrying 0x0304 rather than the legacy 0x0303");
        refuses(s, sh, rewriteExtensions(ee, TranscriptTest::reversed), "EncryptedExtensions with ALPN before supported_groups");
        refuses(s, sh, rewriteExtensions(ee, e -> added(e, new byte[] {0, 0, 0, 0})),
            "EncryptedExtensions that acknowledge SNI with an empty server_name");
    }

    /**
     * {@link Transcript#reconstruct} against the content a JDK writing {@code sh} and {@code ee}
     * would hand over. The HelloRetryRequest comes from the server messages rather than from the
     * reconstruction, because that is where {@code reconstruct} will read it from: taking it from
     * two places makes the control compare transcripts built from different retries, which is
     * invisible today only because this test's handshake has none.
     */
    private static Transcript.Reconstructed reconstructAsIf(Signed s, byte[] sh, byte[] ee) throws GeneralSecurityException {
        byte[] hash = hubSide(s.clientMessages(), helloRetryRequestIn(s.serverMessages()), sh, ee, s.content());
        byte[] content = Arrays.copyOf(Tls13.CERT_VERIFY_CONTEXT, Tls13.CERT_VERIFY_CONTEXT.length + hash.length);
        System.arraycopy(hash, 0, content, Tls13.CERT_VERIFY_CONTEXT.length, hash.length);
        return Transcript.reconstruct(s.clientMessages(), s.serverMessages(), s.randomChunks(), s.cipherSuite(),
            certificateMessage, content);
    }

    private static void refuses(Signed s, byte[] sh, byte[] ee, String what) {
        assertFalse(Arrays.equals(sh, s.t().serverHello()) && Arrays.equals(ee, s.t().encryptedExtensions()),
            what + ": the variant changed no bytes, so it can prove nothing");
        assertThrows(GeneralSecurityException.class, () -> reconstructAsIf(s, sh, ee),
            "a JDK writing " + what + " must leave the reconstruction with nothing that hashes to what it asked to have "
                + "signed. That it reconstructed anyway means this test can no longer fail in the direction it claims");
    }

    // --- writing the same handshake differently ----------------------------------------------

    /** The HelloRetryRequest among the node's messages, found the way {@link Transcript#reconstruct} finds it. */
    private static byte[] helloRetryRequestIn(List<byte[]> serverMessages) {
        byte[] hrr = null;
        for (byte[] m : serverMessages) {
            if (Tls13.isHelloRetryRequest(m)) {
                hrr = m;
            }
        }
        return hrr;
    }

    /**
     * The extensions of a ServerHello or EncryptedExtensions, each with its own four-byte header.
     * Both message bodies end in a {@code u16} length and that block; what differs is the prefix
     * ahead of it, which for a ServerHello is version, random, echoed session id, suite and
     * compression, and for EncryptedExtensions is nothing.
     */
    private static List<byte[]> extensionsOf(byte[] message) {
        byte[] body = Arrays.copyOfRange(message, 4, message.length);
        return extensionsIn(body, prefixLength(message[0] & 0xff, body));
    }

    private static List<byte[]> extensionsIn(byte[] body, int from) {
        int end = from + 2 + u16(body, from);
        List<byte[]> exts = new ArrayList<>();
        for (int i = from + 2; i + 4 <= end; ) {
            int len = u16(body, i + 2);
            exts.add(Arrays.copyOfRange(body, i, i + 4 + len));
            i += 4 + len;
        }
        return exts;
    }

    /** The same message with its extension block replaced by {@code f}'s answer. */
    private static byte[] rewriteExtensions(byte[] message, UnaryOperator<List<byte[]>> f) {
        byte[] body = Arrays.copyOfRange(message, 4, message.length);
        int prefix = prefixLength(message[0] & 0xff, body);
        ByteArrayOutputStream block = new ByteArrayOutputStream();
        for (byte[] e : f.apply(extensionsIn(body, prefix))) {
            block.writeBytes(e);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(body, 0, prefix);
        out.write(block.size() >> 8);
        out.write(block.size());
        out.writeBytes(block.toByteArray());
        return Tls13.message(message[0] & 0xff, out.toByteArray());
    }

    private static int prefixLength(int type, byte[] body) {
        if (type == Tls13.ENCRYPTED_EXTENSIONS) {
            return 0;
        }
        assertEquals(Tls13.SERVER_HELLO, type, "only a ServerHello or EncryptedExtensions has a prefix here");
        return 34 + 1 + (body[34] & 0xff) + 2 + 1; // version, random | session id | suite, compression
    }

    /** The ServerHello with a different {@code legacy_version}, which is otherwise 0x0303 forever. */
    private static byte[] legacyVersion(byte[] serverHello, int version) {
        byte[] m = serverHello.clone();
        m[4] = (byte) (version >> 8);
        m[5] = (byte) version;
        return m;
    }

    private static List<byte[]> reversed(List<byte[]> exts) {
        List<byte[]> l = new ArrayList<>(exts);
        Collections.reverse(l);
        return l;
    }

    private static List<byte[]> added(List<byte[]> exts, byte[] extension) {
        List<byte[]> l = new ArrayList<>(exts);
        l.add(extension);
        return l;
    }

    private static int u16(byte[] b, int i) {
        return ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
    }
}
