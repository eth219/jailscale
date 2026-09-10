package io.jailscale.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Random;
import org.junit.jupiter.api.Test;

class Blake2sTest {

    private static final HexFormat HEX = HexFormat.of();

    /** Key 00..1f used by the official BLAKE2 known-answer tests (blake2s-kat.txt). */
    private static final byte[] KAT_KEY = new byte[32];

    static {
        for (int i = 0; i < KAT_KEY.length; i++) {
            KAT_KEY[i] = (byte) i;
        }
    }

    @Test
    void rfc7693AppendixB_abc() {
        assertArrayEquals(
            HEX.parseHex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"),
            Blake2s.hash("abc".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void unkeyedEmptyInput() {
        assertArrayEquals(
            HEX.parseHex("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
            Blake2s.hash());
    }

    @Test
    void keyedKnownAnswers() {
        assertArrayEquals(
            HEX.parseHex("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49"),
            Blake2s.keyedHash(KAT_KEY, 32));
        assertArrayEquals(
            HEX.parseHex("40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1"),
            Blake2s.keyedHash(KAT_KEY, 32, new byte[] {0}));
        assertArrayEquals(
            HEX.parseHex("6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803"),
            Blake2s.keyedHash(KAT_KEY, 32, new byte[] {0, 1}));
    }

    /**
     * The block buffering logic (hold back a full block until more input arrives) is where
     * BLAKE2 implementations usually break. Feed every length from 0 to 3 blocks in random
     * chunk sizes and require the same digest as the one-shot computation.
     */
    @Test
    void incrementalUpdatesMatchOneShot() {
        Random rnd = new Random(7);
        for (int len = 0; len <= 3 * Blake2s.BLOCK_BYTES + 5; len++) {
            byte[] in = new byte[len];
            rnd.nextBytes(in);
            for (int digestLen : new int[] {16, 32}) {
                for (byte[] key : new byte[][] {null, KAT_KEY, new byte[] {1, 2, 3}}) {
                    byte[] expected = key == null
                        ? new Blake2s(digestLen).update(in).digest()
                        : new Blake2s(digestLen, key).update(in).digest();
                    Blake2s b = key == null ? new Blake2s(digestLen) : new Blake2s(digestLen, key);
                    int off = 0;
                    while (off < len) {
                        int n = Math.min(len - off, 1 + rnd.nextInt(Blake2s.BLOCK_BYTES + 3));
                        b.update(in, off, n);
                        off += n;
                    }
                    assertArrayEquals(expected, b.digest(), "len=" + len + " digestLen=" + digestLen);
                }
            }
        }
    }

    @Test
    void exactBlockBoundaryIsNotCompressedEarly() {
        // 64 bytes fed at once must equal 64 bytes fed as 63 + 1 and as 64 + nothing.
        byte[] block = new byte[Blake2s.BLOCK_BYTES];
        new Random(3).nextBytes(block);
        byte[] oneShot = Blake2s.hash(block);
        assertArrayEquals(oneShot, new Blake2s(32).update(block, 0, 63).update(block, 63, 1).digest());
        assertArrayEquals(oneShot, new Blake2s(32).update(block).update(new byte[0]).digest());
    }

    @Test
    void rejectsInvalidParameters() {
        assertThrows(IllegalArgumentException.class, () -> new Blake2s(0));
        assertThrows(IllegalArgumentException.class, () -> new Blake2s(33));
        assertThrows(IllegalArgumentException.class, () -> new Blake2s(32, new byte[33]));
        Blake2s b = new Blake2s(32);
        b.digest();
        assertThrows(IllegalStateException.class, () -> b.update(new byte[1]));
        assertThrows(IllegalStateException.class, b::digest);
    }
}
