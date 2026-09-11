package io.jailscale.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** Vectors copied from RFC 7748 §5.2 and §6.1. */
class X25519Test {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    void rfc7748Section52Vector1() {
        byte[] out = X25519.dh(
            HEX.parseHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            HEX.parseHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"));
        assertArrayEquals(HEX.parseHex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"), out);
    }

    @Test
    void rfc7748Section52Vector2() {
        byte[] out = X25519.dh(
            HEX.parseHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            HEX.parseHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"));
        assertArrayEquals(HEX.parseHex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"), out);
    }

    @Test
    void rfc7748Section61AliceAndBob() {
        byte[] a = HEX.parseHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] aPub = HEX.parseHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        byte[] b = HEX.parseHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] bPub = HEX.parseHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] k = HEX.parseHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        assertArrayEquals(aPub, X25519.publicKey(a));
        assertArrayEquals(bPub, X25519.publicKey(b));
        assertArrayEquals(k, X25519.dh(a, bPub));
        assertArrayEquals(k, X25519.dh(b, aPub));
    }

    @Test
    void generatedKeypairAgrees() {
        X25519.Keypair x = X25519.generate();
        X25519.Keypair y = X25519.generate();
        assertEquals(32, x.privateKey().length);
        assertEquals(32, x.publicKey().length);
        assertArrayEquals(x.publicKey(), X25519.publicKey(x.privateKey()));
        assertArrayEquals(X25519.dh(x.privateKey(), y.publicKey()), X25519.dh(y.privateKey(), x.publicKey()));
        assertFalse(java.util.Arrays.equals(x.publicKey(), y.publicKey()));
    }

    @Test
    void smallOrderPeerPointIsRejected() {
        byte[] priv = X25519.generate().privateKey();
        assertThrows(IllegalArgumentException.class, () -> X25519.dh(priv, new byte[32]));
        byte[] one = new byte[32];
        one[0] = 1;
        assertThrows(IllegalArgumentException.class, () -> X25519.dh(priv, one));
    }

    @Test
    void highBitOfPublicKeyIsIgnored() {
        // RFC 7748 §5: the most significant bit of the last byte must be masked when decoding.
        byte[] a = HEX.parseHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bPub = HEX.parseHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        byte[] bPubHigh = bPub.clone();
        bPubHigh[31] |= (byte) 0x80;
        assertArrayEquals(X25519.dh(a, bPub), X25519.dh(a, bPubHigh));
    }

    @Test
    void rejectsWrongLengths() {
        assertThrows(IllegalArgumentException.class, () -> X25519.dh(new byte[31], new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> X25519.publicKey(new byte[33]));
    }
}
