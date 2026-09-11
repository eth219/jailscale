package io.jailscale.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/**
 * X25519 (RFC 7748) over the JDK's XDH provider, exposed with the raw 32-byte little-endian
 * encodings every Noise/WireGuard-family protocol uses on the wire.
 *
 * <p>The JDK represents the public u-coordinate as a {@link BigInteger} and the private
 * scalar as raw bytes; this class hides the conversions. The provider clamps the scalar and
 * rejects small-order peer points (all-zero shared secret) by itself.
 */
public final class X25519 {

    public static final int KEY_LEN = 32;

    private static final NamedParameterSpec PARAMS = NamedParameterSpec.X25519;
    private static final byte[] BASE_POINT = basePoint();

    private X25519() {}

    /** A fresh random key pair, as raw bytes. */
    public static Keypair generate() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("X25519");
            g.initialize(PARAMS);
            KeyPair kp = g.generateKeyPair();
            byte[] priv = ((XECPrivateKey) kp.getPrivate()).getScalar().orElseThrow();
            byte[] pub = encodePublic(((XECPublicKey) kp.getPublic()).getU());
            return new Keypair(priv, pub);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 unavailable in this JDK", e);
        }
    }

    /** Public key for a raw private scalar: X25519(k, 9). */
    public static byte[] publicKey(byte[] privateKey) {
        return dh(privateKey, BASE_POINT);
    }

    /**
     * X25519(k, u). Throws {@link IllegalArgumentException} if the peer point is invalid or
     * has small order (the shared secret would be all zeros).
     */
    public static byte[] dh(byte[] privateKey, byte[] peerPublicKey) {
        checkLen(privateKey);
        checkLen(peerPublicKey);
        try {
            KeyFactory kf = KeyFactory.getInstance("X25519");
            PrivateKey priv = kf.generatePrivate(new XECPrivateKeySpec(PARAMS, privateKey));
            PublicKey pub = kf.generatePublic(new XECPublicKeySpec(PARAMS, decodePublic(peerPublicKey)));
            KeyAgreement ka = KeyAgreement.getInstance("X25519");
            ka.init(priv);
            ka.doPhase(pub, true);
            byte[] shared = ka.generateSecret();
            if (shared.length != KEY_LEN) {
                throw new IllegalStateException("unexpected shared secret length " + shared.length);
            }
            return shared;
        } catch (java.security.spec.InvalidKeySpecException | java.security.InvalidKeyException e) {
            throw new IllegalArgumentException("invalid X25519 key", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 unavailable in this JDK", e);
        }
    }

    /** Raw private scalar and public u-coordinate. Zero the private half when done. */
    public record Keypair(byte[] privateKey, byte[] publicKey) {
        public Keypair {
            checkLen(privateKey);
            checkLen(publicKey);
        }

        public void destroy() {
            Arrays.fill(privateKey, (byte) 0);
        }
    }

    private static byte[] basePoint() {
        byte[] u = new byte[KEY_LEN];
        u[0] = 9;
        return u;
    }

    /** RFC 7748 §5: little-endian, most significant bit of the last byte masked off. */
    private static BigInteger decodePublic(byte[] raw) {
        byte[] be = new byte[KEY_LEN];
        for (int i = 0; i < KEY_LEN; i++) {
            be[i] = raw[KEY_LEN - 1 - i];
        }
        be[0] &= 0x7f;
        return new BigInteger(1, be);
    }

    private static byte[] encodePublic(BigInteger u) {
        byte[] be = u.toByteArray();
        byte[] out = new byte[KEY_LEN];
        int n = Math.min(be.length, KEY_LEN);
        for (int i = 0; i < n; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private static void checkLen(byte[] k) {
        if (k == null || k.length != KEY_LEN) {
            throw new IllegalArgumentException("X25519 keys are " + KEY_LEN + " bytes");
        }
    }
}
