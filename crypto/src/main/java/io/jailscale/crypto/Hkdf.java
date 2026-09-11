package io.jailscale.crypto;

import java.util.Arrays;

/**
 * HMAC and HKDF over BLAKE2s-256, as the Noise Protocol Framework defines them
 * (HMAC per RFC 2104 with a 64-byte block, HKDF per Noise §4.3).
 *
 * <p>Noise's HKDF is not the RFC 5869 one: there is no salt/info split, the "info" is the
 * output counter byte, and up to three outputs are chained.
 */
public final class Hkdf {

    public static final int HASH_LEN = Blake2s.MAX_DIGEST_BYTES;
    private static final int BLOCK = Blake2s.BLOCK_BYTES;

    private Hkdf() {}

    /** HMAC-BLAKE2s-256(key, data). Keys longer than one block are hashed first. */
    public static byte[] hmac(byte[] key, byte[]... data) {
        byte[] k = key.length > BLOCK ? Blake2s.hash(key) : key;
        byte[] ipad = new byte[BLOCK];
        byte[] opad = new byte[BLOCK];
        for (int i = 0; i < BLOCK; i++) {
            int b = i < k.length ? k[i] & 0xff : 0;
            ipad[i] = (byte) (b ^ 0x36);
            opad[i] = (byte) (b ^ 0x5c);
        }
        Blake2s inner = new Blake2s(HASH_LEN).update(ipad);
        for (byte[] d : data) {
            inner.update(d);
        }
        byte[] innerHash = inner.digest();
        byte[] out = new Blake2s(HASH_LEN).update(opad).update(innerHash).digest();
        Arrays.fill(ipad, (byte) 0);
        Arrays.fill(opad, (byte) 0);
        Arrays.fill(innerHash, (byte) 0);
        return out;
    }

    /**
     * Noise HKDF(chaining_key, input_key_material, num_outputs), {@code numOutputs} in 1..3.
     * Returns {@code numOutputs} arrays of {@link #HASH_LEN} bytes.
     */
    public static byte[][] hkdf(byte[] chainingKey, byte[] inputKeyMaterial, int numOutputs) {
        if (numOutputs < 1 || numOutputs > 3) {
            throw new IllegalArgumentException("numOutputs must be 1..3");
        }
        byte[] tempKey = hmac(chainingKey, inputKeyMaterial);
        byte[][] out = new byte[numOutputs][];
        out[0] = hmac(tempKey, new byte[] {1});
        if (numOutputs > 1) {
            out[1] = hmac(tempKey, out[0], new byte[] {2});
        }
        if (numOutputs > 2) {
            out[2] = hmac(tempKey, out[1], new byte[] {3});
        }
        Arrays.fill(tempKey, (byte) 0);
        return out;
    }
}
