package io.jailscale.crypto;

import java.util.Arrays;
import javax.crypto.AEADBadTagException;

/**
 * Noise CipherState (§5.1): a key and a 64-bit nonce counter. Used both inside the handshake
 * and, after {@code Split()}, as one direction of the transport.
 *
 * <p>Not thread safe. A transport direction is driven by exactly one thread.
 */
public final class CipherState {

    /** Nonce value reserved by the Noise spec; reaching it means the key must be replaced. */
    public static final long MAX_NONCE = -1L; // 2^64 - 1 as unsigned

    private byte[] k;
    private long n;

    CipherState() {}

    public boolean hasKey() {
        return k != null;
    }

    void initializeKey(byte[] key) {
        destroy();
        k = key == null ? null : key.clone();
        n = 0;
    }

    /** Current nonce (the value the next message will use). */
    public long nonce() {
        return n;
    }

    /**
     * Skips the nonce counter to {@code value}. Only for receivers on lossy transports; the
     * control channel is a stream and never needs it.
     */
    public void setNonce(long value) {
        n = value;
    }

    public byte[] encryptWithAd(byte[] ad, byte[] plaintext) throws NoiseException {
        if (k == null) {
            return plaintext.clone();
        }
        long nonce = takeNonce();
        return ChaChaPoly.encrypt(k, nonce, ad, plaintext);
    }

    public byte[] decryptWithAd(byte[] ad, byte[] ciphertext) throws NoiseException {
        return decryptWithAd(ad, ciphertext, 0, ciphertext.length);
    }

    public byte[] decryptWithAd(byte[] ad, byte[] ciphertext, int off, int len) throws NoiseException {
        if (k == null) {
            return Arrays.copyOfRange(ciphertext, off, off + len);
        }
        if (n == MAX_NONCE) {
            throw new NoiseException("nonce exhausted");
        }
        try {
            byte[] pt = ChaChaPoly.decrypt(k, n, ad, ciphertext, off, len);
            n++; // only advance after a successful decryption (Noise §5.1)
            return pt;
        } catch (AEADBadTagException e) {
            throw new NoiseException("authentication failed", e);
        }
    }

    /** Rekey() from Noise §4.2: k = ENCRYPT(k, 2^64-1, zerolen, zeros[32]) truncated to 32. */
    public void rekey() {
        if (k == null) {
            throw new IllegalStateException("no key");
        }
        byte[] out = ChaChaPoly.encrypt(k, MAX_NONCE, new byte[0], new byte[ChaChaPoly.KEY_LEN]);
        initializeKey(Arrays.copyOf(out, ChaChaPoly.KEY_LEN));
        Arrays.fill(out, (byte) 0);
    }

    public void destroy() {
        if (k != null) {
            Arrays.fill(k, (byte) 0);
            k = null;
        }
    }

    private long takeNonce() throws NoiseException {
        if (n == MAX_NONCE) {
            throw new NoiseException("nonce exhausted");
        }
        return n++;
    }
}
