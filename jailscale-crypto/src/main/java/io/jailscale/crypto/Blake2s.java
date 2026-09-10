package io.jailscale.crypto;

import java.util.Arrays;

/**
 * BLAKE2s (RFC 7693), the hash used by the Noise_IK handshake in WireGuard.
 *
 * <p>Supports the two configurations the protocol needs: unkeyed BLAKE2s-256 for the
 * handshake hash and HMAC construction, and keyed BLAKE2s-128 for the {@code mac1}/{@code mac2}
 * fields of handshake messages.
 *
 * <p>Instances are stateful and not thread safe.
 */
public final class Blake2s {

    public static final int BLOCK_BYTES = 64;
    public static final int MAX_DIGEST_BYTES = 32;
    public static final int MAX_KEY_BYTES = 32;

    private static final int[] IV = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    private static final byte[][] SIGMA = {
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
        { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
        {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
        {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
        {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
        { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
        { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
        {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
        { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
    };

    private final int digestLength;
    private final int[] h = new int[8];
    private final byte[] buf = new byte[BLOCK_BYTES];
    private final int[] v = new int[16];
    private final int[] m = new int[16];
    private int bufLen;
    private long counter;
    private boolean finished;

    public Blake2s(int digestLength) {
        this(digestLength, null, 0, 0);
    }

    public Blake2s(int digestLength, byte[] key) {
        this(digestLength, key, 0, key == null ? 0 : key.length);
    }

    public Blake2s(int digestLength, byte[] key, int keyOff, int keyLen) {
        if (digestLength < 1 || digestLength > MAX_DIGEST_BYTES) {
            throw new IllegalArgumentException("digestLength must be 1.." + MAX_DIGEST_BYTES);
        }
        if (key == null) {
            keyLen = 0;
        } else if (keyLen > MAX_KEY_BYTES) {
            throw new IllegalArgumentException("key must be at most " + MAX_KEY_BYTES + " bytes");
        }
        this.digestLength = digestLength;
        System.arraycopy(IV, 0, h, 0, 8);
        // Parameter block word 0: digest length | key length | fanout=1 | depth=1.
        h[0] ^= 0x01010000 ^ (keyLen << 8) ^ digestLength;
        if (keyLen > 0) {
            // A keyed hash processes the zero-padded key as a full first block.
            byte[] block = new byte[BLOCK_BYTES];
            System.arraycopy(key, keyOff, block, 0, keyLen);
            update(block, 0, BLOCK_BYTES);
            Arrays.fill(block, (byte) 0);
        }
    }

    public Blake2s update(byte[] in) {
        return update(in, 0, in.length);
    }

    public Blake2s update(byte[] in, int off, int len) {
        if (finished) {
            throw new IllegalStateException("digest already computed");
        }
        if (len <= 0) {
            return this;
        }
        // BLAKE2 must never compress the final block early, so a full buffer is held back
        // until we know at least one more byte follows.
        int fill = BLOCK_BYTES - bufLen;
        if (len > fill) {
            System.arraycopy(in, off, buf, bufLen, fill);
            bufLen = 0;
            counter += BLOCK_BYTES;
            compress(buf, 0, false);
            off += fill;
            len -= fill;
            while (len > BLOCK_BYTES) {
                counter += BLOCK_BYTES;
                compress(in, off, false);
                off += BLOCK_BYTES;
                len -= BLOCK_BYTES;
            }
        }
        System.arraycopy(in, off, buf, bufLen, len);
        bufLen += len;
        return this;
    }

    public byte[] digest() {
        byte[] out = new byte[digestLength];
        digest(out, 0);
        return out;
    }

    public void digest(byte[] out, int outOff) {
        if (finished) {
            throw new IllegalStateException("digest already computed");
        }
        finished = true;
        counter += bufLen;
        Arrays.fill(buf, bufLen, BLOCK_BYTES, (byte) 0);
        compress(buf, 0, true);
        for (int i = 0; i < digestLength; i++) {
            out[outOff + i] = (byte) (h[i >>> 2] >>> (8 * (i & 3)));
        }
        Arrays.fill(h, 0);
        Arrays.fill(buf, (byte) 0);
        Arrays.fill(v, 0);
        Arrays.fill(m, 0);
    }

    private void compress(byte[] block, int off, boolean last) {
        for (int i = 0; i < 16; i++) {
            m[i] = (block[off + i * 4] & 0xff)
                | (block[off + i * 4 + 1] & 0xff) << 8
                | (block[off + i * 4 + 2] & 0xff) << 16
                | (block[off + i * 4 + 3] & 0xff) << 24;
        }
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= (int) counter;
        v[13] ^= (int) (counter >>> 32);
        if (last) {
            v[14] = ~v[14];
        }
        for (int r = 0; r < 10; r++) {
            byte[] s = SIGMA[r];
            g(0, 4,  8, 12, m[s[0]],  m[s[1]]);
            g(1, 5,  9, 13, m[s[2]],  m[s[3]]);
            g(2, 6, 10, 14, m[s[4]],  m[s[5]]);
            g(3, 7, 11, 15, m[s[6]],  m[s[7]]);
            g(0, 5, 10, 15, m[s[8]],  m[s[9]]);
            g(1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(2, 7,  8, 13, m[s[12]], m[s[13]]);
            g(3, 4,  9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    private void g(int a, int b, int c, int d, int x, int y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Integer.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Integer.rotateRight(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y;
        v[d] = Integer.rotateRight(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = Integer.rotateRight(v[b] ^ v[c], 7);
    }

    /** Unkeyed BLAKE2s-256 over the concatenation of {@code inputs}. */
    public static byte[] hash(byte[]... inputs) {
        Blake2s b = new Blake2s(MAX_DIGEST_BYTES);
        for (byte[] in : inputs) {
            b.update(in, 0, in.length);
        }
        return b.digest();
    }

    /** Keyed BLAKE2s with the given output size, over the concatenation of {@code inputs}. */
    public static byte[] keyedHash(byte[] key, int digestLength, byte[]... inputs) {
        Blake2s b = new Blake2s(digestLength, key);
        for (byte[] in : inputs) {
            b.update(in, 0, in.length);
        }
        return b.digest();
    }
}
