package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLContext;

/**
 * The hub's wildcard certificate and private key (DESIGN.md §6.3, §9.3). The key never leaves
 * this class: nodes get the chain via {@link #certUpdate()} and ask {@link #sign} for
 * handshake signatures. Previous keys are kept for a day so in-flight handshakes finish.
 */
final class HubTls {

    private static final Log LOG = Log.get("tls");
    private static final long PREVIOUS_KEY_TTL_MS = 24 * 3600 * 1000L;

    private record Material(String keyId, List<X509Certificate> chain, PrivateKey key, SSLContext context, long retiredAt) {}

    private volatile Material current;
    private final Map<String, Material> byKeyId = new ConcurrentHashMap<>();
    private final String hostname;

    HubTls(String hostname) {
        this.hostname = hostname;
    }

    /** Loads PEM files (the {@code --tls-cert/--tls-key} path). */
    void load(Path certPem, Path keyPem) throws IOException, GeneralSecurityException {
        install(Pem.certificates(Files.readString(certPem)), Pem.privateKey(Files.readString(keyPem)));
    }

    /** Installs a new certificate and key; the previous one stays usable for a day. */
    synchronized void install(List<X509Certificate> chain, PrivateKey key) throws GeneralSecurityException {
        X509Certificate leaf = chain.get(0);
        if (!"EC".equals(key.getAlgorithm())) {
            throw new GeneralSecurityException("the hub certificate key must be ECDSA (DESIGN.md §6.3), got " + key.getAlgorithm());
        }
        boolean wild = false;
        try {
            var sans = leaf.getSubjectAlternativeNames();
            if (sans != null) {
                for (List<?> san : sans) {
                    if (Integer.valueOf(2).equals(san.get(0)) && ("*." + hostname).equalsIgnoreCase(String.valueOf(san.get(1)))) {
                        wild = true;
                    }
                }
            }
        } catch (GeneralSecurityException e) {
            throw e;
        }
        if (!wild) {
            LOG.warn("certificate has no *.{} SAN; links will not be reachable by name", hostname);
        }
        String keyId = keyId(leaf);
        Material m = new Material(keyId, List.copyOf(chain), key, Tls.serverContext(chain, key), 0);
        Material old = current;
        current = m;
        byKeyId.put(keyId, m);
        if (old != null && !old.keyId().equals(keyId)) {
            byKeyId.put(old.keyId(), new Material(old.keyId(), old.chain(), old.key(), old.context(), System.currentTimeMillis()));
        }
        LOG.info("certificate installed: {} (keyId {}, expires {})", leaf.getSubjectX500Principal(), keyId, leaf.getNotAfter());
    }

    boolean isLoaded() {
        return current != null;
    }

    String keyId() {
        return current.keyId();
    }

    SSLContext context() {
        return current.context();
    }

    X509Certificate leaf() {
        return current.chain().get(0);
    }

    /** The message that gives nodes the public half. */
    Message.CertUpdate certUpdate() throws GeneralSecurityException {
        List<String> pem = new ArrayList<>();
        for (X509Certificate c : current.chain()) {
            pem.add(Pem.encode(c));
        }
        return new Message.CertUpdate(pem, current.keyId());
    }

    /**
     * ECDSA over a precomputed SHA-256 digest, DER encoded (what TLS CertificateVerify carries).
     * Returns null if the keyId is unknown or retired.
     */
    byte[] sign(String keyId, byte[] digest) throws GeneralSecurityException {
        Material m = byKeyId.get(keyId);
        if (m == null) {
            return null;
        }
        if (m.retiredAt() > 0 && System.currentTimeMillis() - m.retiredAt() > PREVIOUS_KEY_TTL_MS) {
            byKeyId.remove(keyId);
            return null;
        }
        if (digest.length != 32) {
            throw new GeneralSecurityException("digest must be SHA-256");
        }
        Signature sig = Signature.getInstance("NONEwithECDSA");
        sig.initSign(m.key());
        sig.update(digest);
        return sig.sign();
    }

    static String keyId(X509Certificate leaf) throws GeneralSecurityException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return "sha256:" + HexFormat.of().formatHex(md.digest(leaf.getEncoded())).substring(0, 16);
    }
}
