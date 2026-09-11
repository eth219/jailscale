package io.jailscale.node;

import io.jailscale.proto.control.Message;
import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLEngine;
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

    static final String PROVIDER_NAME = "JailscaleRemote";
    static final String ALGORITHM = "SHA256withECDSA";
    static final long SIGN_TIMEOUT_MS = 10_000;

    /** Who signs for the current thread: the stream's full id and the connection it arrived on. */
    record Context(HubLink link, HubLink.Session session, long streamId, String keyId) {}

    private static final ThreadLocal<Context> CONTEXT = new ThreadLocal<>();

    private RemoteSigning() {}

    static void enter(Context c) {
        CONTEXT.set(c);
    }

    static void exit() {
        CONTEXT.remove();
    }

    /** Registers the provider once (idempotent). No reflection: services are added by instance. */
    static synchronized void install() {
        if (Security.getProvider(PROVIDER_NAME) == null) {
            Security.addProvider(new RemoteProvider());
        }
    }

    /** A private key that only knows which hub key it stands for. Not an ECPrivateKey on purpose. */
    static final class RemotePrivateKey implements PrivateKey {
        private static final long serialVersionUID = 1L;
        private final String keyId;

        RemotePrivateKey(String keyId) {
            this.keyId = keyId;
        }

        String keyId() {
            return keyId;
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
        private final MessageDigest sha256;
        private RemotePrivateKey key;

        RemoteSignature() {
            try {
                sha256 = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

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
            sha256.reset();
        }

        @Override
        protected void engineUpdate(byte b) {
            sha256.update(b);
        }

        @Override
        protected void engineUpdate(byte[] b, int off, int len) {
            sha256.update(b, off, len);
        }

        @Override
        protected byte[] engineSign() throws SignatureException {
            Context ctx = CONTEXT.get();
            if (ctx == null) {
                throw new SignatureException("no signing context on this thread");
            }
            byte[] digest = sha256.digest();
            Message reply;
            try {
                reply = ctx.link().requestOn(ctx.session(), new Message.SignRequest(ctx.streamId(), key.keyId(), "ECDSA-P256-SHA256", digest),
                    "SignResponse:" + ctx.streamId(), SIGN_TIMEOUT_MS);
            } catch (IOException | TimeoutException e) {
                throw new SignatureException("hub did not sign: " + e.getMessage(), e);
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

        RemoteKeyManager(List<X509Certificate> chain, String keyId) {
            this.chain = chain.toArray(new X509Certificate[0]);
            this.key = new RemotePrivateKey(keyId);
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
