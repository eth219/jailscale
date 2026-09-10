package io.jailscale.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Random;
import org.junit.jupiter.api.Test;

/**
 * There is no published HMAC-BLAKE2s vector, so the construction is checked against a literal
 * transcription of RFC 2104 here; the end-to-end check is the Noise vector in NoiseIkTest.
 */
class HkdfTest {

    private static byte[] naiveHmac(byte[] key, byte[] msg) {
        byte[] k = key.length > 64 ? Blake2s.hash(key) : key;
        byte[] kPad = new byte[64];
        System.arraycopy(k, 0, kPad, 0, k.length);
        byte[] ipad = new byte[64];
        byte[] opad = new byte[64];
        for (int i = 0; i < 64; i++) {
            ipad[i] = (byte) (kPad[i] ^ 0x36);
            opad[i] = (byte) (kPad[i] ^ 0x5c);
        }
        return Blake2s.hash(opad, Blake2s.hash(ipad, msg));
    }

    @Test
    void hmacMatchesRfc2104Transcription() {
        Random rnd = new Random(11);
        for (int keyLen : new int[] {0, 1, 32, 63, 64, 65, 200}) {
            for (int msgLen : new int[] {0, 1, 64, 100}) {
                byte[] key = new byte[keyLen];
                byte[] msg = new byte[msgLen];
                rnd.nextBytes(key);
                rnd.nextBytes(msg);
                assertArrayEquals(naiveHmac(key, msg), Hkdf.hmac(key, msg), "key=" + keyLen + " msg=" + msgLen);
            }
        }
    }

    @Test
    void hmacConcatenatesDataParts() {
        byte[] key = {1, 2, 3};
        assertArrayEquals(Hkdf.hmac(key, new byte[] {4, 5, 6}), Hkdf.hmac(key, new byte[] {4}, new byte[] {5, 6}));
    }

    @Test
    void hkdfFollowsNoiseChaining() {
        byte[] ck = new byte[32];
        byte[] ikm = {9, 9, 9};
        byte[] temp = Hkdf.hmac(ck, ikm);
        byte[][] out = Hkdf.hkdf(ck, ikm, 3);
        assertArrayEquals(Hkdf.hmac(temp, new byte[] {1}), out[0]);
        assertArrayEquals(Hkdf.hmac(temp, out[0], new byte[] {2}), out[1]);
        assertArrayEquals(Hkdf.hmac(temp, out[1], new byte[] {3}), out[2]);
        assertEquals(2, Hkdf.hkdf(ck, ikm, 2).length);
        assertThrows(IllegalArgumentException.class, () -> Hkdf.hkdf(ck, ikm, 0));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.hkdf(ck, ikm, 4));
    }
}
