package io.jailscale.crypto;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * ChaCha20-Poly1305 (RFC 8439) over the JDK's SunJCE provider, with the Noise nonce layout:
 * 96-bit IV = 32 zero bits || 64-bit little-endian counter.
 *
 * <p>{@link Cipher} instances are expensive to create and are not thread safe, so one is kept
 * per thread and re-initialised on every call. Nonce uniqueness is the caller's job
 * ({@link CipherState} counts); SunJCE's own (key, nonce) reuse check is worked around because
 * it also fires on legitimate reuse such as decrypting and then re-encrypting one message.
 */
public final class ChaChaPoly {

    public static final int KEY_LEN = 32;
    public static final int TAG_LEN = 16;
    public static final int NONCE_LEN = 12;

    private static final ThreadLocal<Cipher> CIPHER = ThreadLocal.withInitial(ChaChaPoly::newCipher);

    private static Cipher newCipher() {
        try {
            return Cipher.getInstance("ChaCha20-Poly1305");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ChaCha20-Poly1305 unavailable in this JDK", e);
        }
    }

    private ChaChaPoly() {}

    /** Ciphertext || 16-byte tag. */
    public static byte[] encrypt(byte[] key, long nonce, byte[] ad, byte[] plaintext) {
        return run(Cipher.ENCRYPT_MODE, key, nonce(nonce), ad, plaintext, 0, plaintext.length);
    }

    /** Ciphertext || tag with a caller-supplied 96-bit nonce (used for non-Noise contexts). */
    public static byte[] encrypt(byte[] key, byte[] nonce12, byte[] ad, byte[] plaintext) {
        return run(Cipher.ENCRYPT_MODE, key, nonce12, ad, plaintext, 0, plaintext.length);
    }

    /** Plaintext, or throws {@link AEADBadTagException} if authentication fails. */
    public static byte[] decrypt(byte[] key, long nonce, byte[] ad, byte[] ciphertext)
        throws AEADBadTagException {
        return decrypt(key, nonce, ad, ciphertext, 0, ciphertext.length);
    }

    public static byte[] decrypt(byte[] key, long nonce, byte[] ad, byte[] ciphertext, int off, int len)
        throws AEADBadTagException {
        if (len < TAG_LEN) {
            throw new AEADBadTagException("ciphertext shorter than tag");
        }
        try {
            return run(Cipher.DECRYPT_MODE, key, nonce(nonce), ad, ciphertext, off, len);
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof AEADBadTagException bad) {
                throw bad;
            }
            throw e;
        }
    }

    public static byte[] decrypt(byte[] key, byte[] nonce12, byte[] ad, byte[] ciphertext)
        throws AEADBadTagException {
        if (ciphertext.length < TAG_LEN) {
            throw new AEADBadTagException("ciphertext shorter than tag");
        }
        try {
            return run(Cipher.DECRYPT_MODE, key, nonce12, ad, ciphertext, 0, ciphertext.length);
        } catch (IllegalStateException e) {
            if (e.getCause() instanceof AEADBadTagException bad) {
                throw bad;
            }
            throw e;
        }
    }

    /** Noise nonce encoding: 4 zero bytes then the 64-bit counter, little-endian. */
    public static byte[] nonce(long counter) {
        byte[] n = new byte[NONCE_LEN];
        for (int i = 0; i < 8; i++) {
            n[4 + i] = (byte) (counter >>> (8 * i));
        }
        return n;
    }

    private static byte[] run(int mode, byte[] key, byte[] nonce12, byte[] ad, byte[] in, int off, int len) {
        if (key.length != KEY_LEN) {
            throw new IllegalArgumentException("key must be " + KEY_LEN + " bytes");
        }
        if (nonce12.length != NONCE_LEN) {
            throw new IllegalArgumentException("nonce must be " + NONCE_LEN + " bytes");
        }
        try {
            Cipher c = CIPHER.get();
            SecretKeySpec k = new SecretKeySpec(key, "ChaCha20");
            IvParameterSpec iv = new IvParameterSpec(nonce12);
            try {
                c.init(mode, k, iv);
            } catch (InvalidKeyException reuse) {
                // SunJCE refuses to re-initialise one instance with the (key, nonce) it last used.
                // That is legitimate here (decrypt then encrypt the same message, or both sides of a
                // rekey in one process); nonce discipline is enforced by CipherState, not by JCE.
                c = newCipher();
                CIPHER.set(c);
                c.init(mode, k, iv);
            }
            if (ad != null && ad.length > 0) {
                c.updateAAD(ad);
            }
            return c.doFinal(in, off, len);
        } catch (AEADBadTagException e) {
            throw new IllegalStateException(e.getMessage(), e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("ChaCha20-Poly1305 failed", e);
        }
    }
}
