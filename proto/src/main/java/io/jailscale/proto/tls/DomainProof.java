package io.jailscale.proto.tls;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Locale;

/**
 * The node's proof that it holds the private key of the certificate it claims a domain with
 * (ARCHITECTURE.md §8.3). A certificate chain is public — every visitor is handed one and CT logs
 * keep copies — so presenting a chain shows only that the presenter has seen the site, not that
 * they run it. The key is what the CA bound to the domain, so the key is what has to answer.
 *
 * <p>The signed bytes carry the Noise handshake hash of the connection the claim travels on. Both
 * ends derive it and nobody else can, so a proof cannot be lifted off one connection and replayed
 * on another, and no round trip is needed to agree a nonce.
 */
public final class DomainProof {

    private static final byte[] CONTEXT = "jailscale domain claim v1".getBytes(StandardCharsets.US_ASCII);

    private DomainProof() {
    }

    /** The bytes both sides sign and verify. */
    public static byte[] content(byte[] handshakeHash, String domain) {
        byte[] name = domain.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.US_ASCII);
        return ByteBuffer.allocate(CONTEXT.length + handshakeHash.length + name.length)
            .put(CONTEXT).put(handshakeHash).put(name).array();
    }

    /** Signs with the certificate's private key. */
    public static byte[] sign(PrivateKey key, byte[] handshakeHash, String domain) throws GeneralSecurityException {
        Signature sig = Signature.getInstance(algorithm(key.getAlgorithm()));
        sig.initSign(key);
        sig.update(content(handshakeHash, domain));
        return sig.sign();
    }

    /** Verifies against the public key of the presented leaf certificate. */
    public static boolean verify(PublicKey key, byte[] handshakeHash, String domain, byte[] proof)
        throws GeneralSecurityException {
        Signature sig = Signature.getInstance(algorithm(key.getAlgorithm()));
        sig.initVerify(key);
        sig.update(content(handshakeHash, domain));
        return sig.verify(proof);
    }

    /** The signature algorithm for a certificate key, or a failure naming the one we cannot use. */
    public static String algorithm(String keyAlgorithm) throws GeneralSecurityException {
        return switch (keyAlgorithm) {
            case "EC" -> "SHA256withECDSA";
            case "RSA" -> "SHA256withRSA";
            case "EdDSA", "Ed25519" -> "Ed25519";
            default -> throw new GeneralSecurityException("cannot sign a domain claim with a " + keyAlgorithm + " key");
        };
    }
}
