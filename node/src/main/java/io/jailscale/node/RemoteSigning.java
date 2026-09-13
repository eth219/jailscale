package io.jailscale.node;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.tls.Tls13;
import io.jailscale.proto.util.Log;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * The node's half of ARCHITECTURE.md §9.2: a JCE provider whose {@code SHA256withECDSA} accepts an
 * opaque {@link RemotePrivateKey} and obtains the signature from the hub over the control
 * channel. JSSE picks it up through delayed provider selection, the same path PKCS#11 keys use.
 *
 * <p>The handshake that needs the signature runs on the visitor stream's thread; that thread
 * sets a {@link Context} (which stream, which key) before driving the handshake so the
 * signature request can be bound to the stream the hub delivered.
 */
final class RemoteSigning {

    private static final Log LOG = Log.get("signing");
    static final String PROVIDER_NAME = "JailscaleRemote";
    static final String ALGORITHM = "SHA256withECDSA";
    static final long SIGN_TIMEOUT_MS = 10_000;
    /** A signature slower than this is worth a line: the visitor is waiting on it (ARCHITECTURE.md §9.2). */
    static final long SLOW_SIGN_MS = 1_000;

    /**
     * Who signs for the current thread: the stream's full id, the connection it arrived on, and
     * the endpoint whose handshake it is, which holds the wire bytes the transcript is rebuilt from.
     */
    record Context(HubLink link, HubLink.Session session, long streamId, String keyId, TlsEndpoint tls) {}

    private static final ThreadLocal<Context> CONTEXT = new ThreadLocal<>();

    /**
     * The randomness JSSE draws from for the visitor contexts. It records, per handshake thread,
     * what it handed out: the ServerHello random and the X25519 scalar are in there, and they
     * are the only parts of the ServerHello the node cannot otherwise know when JSSE asks for the
     * signature ({@link Transcript}). Recording only happens between {@link #enter} and
     * {@link #exit}, and the record is dropped at exit.
     */
    static final RecordingRandom RANDOM = new RecordingRandom();

    static final class RecordingRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final transient SecureRandom inner = new SecureRandom();
        private final transient ThreadLocal<List<byte[]>> draws = new ThreadLocal<>();

        @Override
        public void nextBytes(byte[] bytes) {
            inner.nextBytes(bytes);
            List<byte[]> l = draws.get();
            if (l != null && l.size() < 64) {
                l.add(bytes.clone());
            }
        }

        void begin() {
            draws.set(new ArrayList<>(4));
        }

        List<byte[]> draws() {
            List<byte[]> l = draws.get();
            return l == null ? List.of() : List.copyOf(l);
        }

        void end() {
            draws.remove();
        }
    }

    private RemoteSigning() {}

    static void enter(Context c) {
        CONTEXT.set(c);
        RANDOM.begin();
    }

    static void exit() {
        RANDOM.end();
        CONTEXT.remove();
    }

    /** Registers the provider once (idempotent). No reflection: services are added by instance. */
    static synchronized void install() {
        if (Security.getProvider(PROVIDER_NAME) == null) {
            Security.addProvider(new RemoteProvider());
        }
    }

    /**
     * A private key that only knows which hub key it stands for, and the Certificate message of
     * the chain it goes with (part of the transcript). Not an ECPrivateKey on purpose.
     */
    static final class RemotePrivateKey implements PrivateKey {
        private static final long serialVersionUID = 1L;
        private final String keyId;
        private final transient byte[] certificateMessage;

        RemotePrivateKey(String keyId, byte[] certificateMessage) {
            this.keyId = keyId;
            this.certificateMessage = certificateMessage;
        }

        String keyId() {
            return keyId;
        }

        byte[] certificateMessage() {
            return certificateMessage;
        }

        @Override
        public String getAlgorithm() {
            return "EC";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }

    static final class RemoteProvider extends java.security.Provider {
        private static final long serialVersionUID = 1L;

        RemoteProvider() {
            super(PROVIDER_NAME, "1", "ECDSA signatures produced by the jailscale hub");
            putService(new RemoteService(this));
        }
    }

    static final class RemoteService extends java.security.Provider.Service {
        RemoteService(java.security.Provider p) {
            super(p, "Signature", ALGORITHM, RemoteSignature.class.getName(), List.of(), Map.of());
        }

        @Override
        public Object newInstance(Object constructorParameter) {
            return new RemoteSignature();
        }

        @Override
        public boolean supportsParameter(Object parameter) {
            return parameter instanceof RemotePrivateKey;
        }
    }

    static final class RemoteSignature extends SignatureSpi {
        /**
         * A TLS 1.3 CertificateVerify content is 98 bytes of context and a transcript hash. The cap
         * is what stops an unexpected caller streaming something large through the hub; the hub
         * checks the shape as well, and is the side that matters.
         */
        static final int MAX_CONTENT = 1024;

        private final ByteArrayOutputStream content = new ByteArrayOutputStream(160);
        private RemotePrivateKey key;

        @Override
        protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
            throw new InvalidKeyException("remote keys only sign");
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            if (!(privateKey instanceof RemotePrivateKey k)) {
                throw new InvalidKeyException("not a remote key");
            }
            key = k;
            content.reset();
        }

        @Override
        protected void engineUpdate(byte b) {
            content.write(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) {
            content.write(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            Context ctx = CONTEXT.get();
            if (ctx == null) {
                throw new SignatureException("no signing context on this thread");
            }
            // The bytes, not their hash: the hub hashes them itself so that it can see what it is
            // being asked to sign (§9.2). It cannot check a digest against anything.
            byte[] bytes = content.toByteArray();
            content.reset();
            if (bytes.length > MAX_CONTENT) {
                throw new SignatureException("too much to sign remotely: " + bytes.length + " bytes");
            }
            // The hub signs only a hash it can recompute from the ClientHello it delivered on this
            // stream, so the messages that hash covers go with the request (§9.2). They are rebuilt
            // here and checked against the hash first: a JDK that writes them differently fails
            // the handshake with this message rather than with a refusal from the hub.
            Transcript.Reconstructed t;
            try {
                SSLSession hs = ctx.tls().handshakeSession();
                t = Transcript.reconstruct(ctx.tls().clientMessages(), ctx.tls().serverMessages(), RANDOM.draws(),
                    hs == null ? null : hs.getCipherSuite(), key.certificateMessage(), bytes);
            } catch (GeneralSecurityException e) {
                LOG.warn("{}", e.getMessage());
                throw new SignatureException(e.getMessage(), e);
            }
            Message reply;
            long asked = System.currentTimeMillis();
            try {
                reply = ctx.link().requestOn(ctx.session(), new Message.SignRequest(ctx.streamId(), key.keyId(), ALGORITHM, bytes,
                    t.serverHello(), t.encryptedExtensions(), t.helloRetryRequest()), "SignResponse:" + ctx.streamId(), SIGN_TIMEOUT_MS);
            } catch (IOException | TimeoutException e) {
                throw new SignatureException("hub did not sign: " + e.getMessage(), e);
            }
            // One signature is one visitor's handshake, so a slow one is a visitor waiting with
            // nothing on screen and no other trace that it happened: `verify` and the hub's counters
            // both say it succeeded. The threshold is well above a healthy round trip (single-digit
            // milliseconds on loopback, tens over the internet) so a quiet hub says nothing.
            long took = System.currentTimeMillis() - asked;
            if (took >= SLOW_SIGN_MS) {
                LOG.warn("the hub took {} ms to sign for stream {}; the visitor waited that long for "
                    + "the handshake", took, ctx.streamId());
            }
            if (reply instanceof Message.SignResponse r && r.sig() != null) {
                return r.sig();
            }
            String reason = reply instanceof Message.SignResponse r ? r.reason() : reply.type();
            throw new SignatureException("hub refused to sign: " + reason);
        }

        @Override
        protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
            throw new SignatureException("remote keys only sign");
        }

        @Override
        @SuppressWarnings("deprecation")
        protected void engineSetParameter(String param, Object value) {
            throw new UnsupportedOperationException();
        }

        @Override
        @SuppressWarnings("deprecation")
        protected Object engineGetParameter(String param) {
            throw new UnsupportedOperationException();
        }
    }

    /** Serves one certificate chain with a remote key to JSSE. */
    static final class RemoteKeyManager extends X509ExtendedKeyManager {
        private static final String ALIAS = "hub-wildcard";
        private final X509Certificate[] chain;
        private final RemotePrivateKey key;

        RemoteKeyManager(List<X509Certificate> chain, String keyId) throws java.security.cert.CertificateEncodingException {
            this.chain = chain.toArray(new X509Certificate[0]);
            this.key = new RemotePrivateKey(keyId, Tls13.certificateMessage(chain));
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return "EC".equals(keyType) ? ALIAS : null;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return "EC".equals(keyType) ? ALIAS : null;
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return "EC".equals(keyType) ? new String[] {ALIAS} : null;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return ALIAS.equals(alias) ? chain.clone() : null;
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return ALIAS.equals(alias) ? key : null;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return null;
        }
    }
}
