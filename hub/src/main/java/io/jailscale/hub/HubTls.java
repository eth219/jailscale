package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.tls.Pem;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.tls.Tls13;
import io.jailscale.proto.util.Log;
import io.jailscale.proto.util.Sha256;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.SSLContext;

/**
 * The hub's wildcard certificate and private key (ARCHITECTURE.md §7.2, §9.2). The key never leaves
 * this class: nodes get the chain via {@link #certUpdate()} and ask {@link #sign} for
 * handshake signatures. Previous keys are kept for a day so in-flight handshakes finish.
 */
final class HubTls {

    private static final Log LOG = Log.get("tls");
    private static final long PREVIOUS_KEY_TTL_MS = 24 * 3600 * 1000L;

    private record Material(String keyId, List<X509Certificate> chain, PrivateKey key, SSLContext context, long retiredAt,
        byte[] certificateMessage) {}

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
            throw new GeneralSecurityException("the hub certificate key must be ECDSA (ARCHITECTURE.md §7.2), got " + key.getAlgorithm());
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
        Material m = new Material(keyId, List.copyOf(chain), key, Tls.serverContext(chain, key), 0, Tls13.certificateMessage(chain));
        Material old = current;
        current = m;
        byKeyId.put(keyId, m);
        if (old != null && !old.keyId().equals(keyId)) {
            byKeyId.put(old.keyId(), new Material(old.keyId(), old.chain(), old.key(), old.context(), System.currentTimeMillis(),
                old.certificateMessage()));
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
        // Not a stream: Pem.encode throws a checked GeneralSecurityException, and the try/catch a
        // lambda would need to swallow it in is longer than the loop.
        List<String> pem = new ArrayList<>();
        for (X509Certificate c : current.chain()) {
            pem.add(Pem.encode(c));
        }
        return new Message.CertUpdate(pem, current.keyId());
    }

    /** The 98 bytes every TLS 1.3 server CertificateVerify signature begins with (RFC 8446 §4.4.3). */
    static final byte[] CERT_VERIFY_CONTEXT = Tls13.CERT_VERIFY_CONTEXT;

    /**
     * The TLS 1.3 Certificate message a node sends for this key's chain, or null for an unknown
     * or retired key. Part of the transcript the hub rebuilds before signing (§9.2).
     */
    byte[] certificateMessage(String keyId) {
        Material m = live(keyId);
        return m == null ? null : m.certificateMessage();
    }

    private Material live(String keyId) {
        Material m = byKeyId.get(keyId);
        if (m == null) {
            return null;
        }
        if (m.retiredAt() > 0 && System.currentTimeMillis() - m.retiredAt() > PREVIOUS_KEY_TTL_MS) {
            byKeyId.remove(keyId);
            return null;
        }
        return m;
    }

    /**
     * ECDSA over what the node is answering a visitor with, DER encoded. The node sends the bytes
     * rather than their hash so that this side can see them: with a bare digest the hub signs
     * whatever 32 bytes it is handed, which makes it a signing oracle for its own wildcard key and
     * puts every name on the certificate — the hub's own included — within reach of any member
     * that can get a visitor to talk to it (§9.2). This confines the key to being a TLS 1.3
     * server; {@link NodeGroup#sign} is what ties the hash to one visitor's handshake first.
     * Returns null if the keyId is unknown or retired.
     */
    byte[] sign(String keyId, byte[] content) throws GeneralSecurityException {
        Material m = live(keyId);
        if (m == null) {
            return null;
        }
        if (Tls13.hashAlgorithmOf(content) == null) {
            throw new GeneralSecurityException("not a TLS 1.3 server CertificateVerify");
        }
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(m.key());
        sig.update(content);
        return sig.sign();
    }

    static String keyId(X509Certificate leaf) throws GeneralSecurityException {
        return "sha256:" + Sha256.hex(leaf.getEncoded()).substring(0, 16);
    }
}
