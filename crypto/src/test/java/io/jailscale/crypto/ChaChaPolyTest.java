package io.jailscale.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Test;

class ChaChaPolyTest {

    private static final HexFormat HEX = HexFormat.of();

    // RFC 8439 §2.8.2
    private static final byte[] KEY = HEX.parseHex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    private static final byte[] NONCE = HEX.parseHex("070000004041424344454647");
    private static final byte[] AAD = HEX.parseHex("50515253c0c1c2c3c4c5c6c7");
    private static final byte[] PLAINTEXT = (
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for "
        + "the future, sunscreen would be it.").getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CIPHERTEXT_AND_TAG = HEX.parseHex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        + "3ff4def08e4b7a9de576d26586cec64b6116"
        + "1ae10b594f09e26a7e902ecbd0600691");

    @Test
    void rfc8439Section282Encrypt() {
        assertArrayEquals(CIPHERTEXT_AND_TAG, ChaChaPoly.encrypt(KEY, NONCE, AAD, PLAINTEXT));
    }

    @Test
    void rfc8439Section282Decrypt() throws Exception {
        assertArrayEquals(PLAINTEXT, ChaChaPoly.decrypt(KEY, NONCE, AAD, CIPHERTEXT_AND_TAG));
    }

    @Test
    void tamperedCiphertextOrAadFails() {
        byte[] flipped = CIPHERTEXT_AND_TAG.clone();
        flipped[10] ^= 1;
        assertThrows(AEADBadTagException.class, () -> ChaChaPoly.decrypt(KEY, NONCE, AAD, flipped));
        byte[] badAad = AAD.clone();
        badAad[0] ^= 1;
        assertThrows(AEADBadTagException.class, () -> ChaChaPoly.decrypt(KEY, NONCE, badAad, CIPHERTEXT_AND_TAG));
        assertThrows(AEADBadTagException.class, () -> ChaChaPoly.decrypt(KEY, NONCE, AAD, new byte[15]));
    }

    @Test
    void noiseNonceLayoutIsLittleEndianAfterFourZeroBytes() {
        assertArrayEquals(HEX.parseHex("000000000100000000000000"), ChaChaPoly.nonce(1));
        assertArrayEquals(HEX.parseHex("00000000ffffffffffffffff"), ChaChaPoly.nonce(-1L));
        assertArrayEquals(HEX.parseHex("000000000807060504030201"), ChaChaPoly.nonce(0x0102030405060708L));
    }

    @Test
    void counterNonceRoundTripAndEmptyPayload() throws Exception {
        byte[] key = new byte[32];
        key[0] = 7;
        byte[] ct = ChaChaPoly.encrypt(key, 42L, new byte[0], new byte[0]);
        assertArrayEquals(new byte[0], ChaChaPoly.decrypt(key, 42L, new byte[0], ct));
        assertThrows(AEADBadTagException.class, () -> ChaChaPoly.decrypt(key, 43L, new byte[0], ct));
    }
}
