package io.jailscale.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class NoiseIkTest {

    private static final HexFormat HEX = HexFormat.of();

    /**
     * Noise_IK_25519_ChaChaPoly_BLAKE2s vector from the noise-c test suite
     * (tests/vector/noise-c-basic.txt, MIT). Static and ephemeral fields are private keys;
     * init_remote_static is the responder's static public key.
     */
    private static final byte[] V_PROLOGUE = HEX.parseHex("50726f6c6f677565313233");
    private static final byte[] V_INIT_STATIC = HEX.parseHex(
        "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
    private static final byte[] V_INIT_EPHEMERAL = HEX.parseHex(
        "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a");
    private static final byte[] V_INIT_REMOTE_STATIC = HEX.parseHex(
        "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62");
    private static final byte[] V_RESP_STATIC = HEX.parseHex(
        "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
    private static final byte[] V_RESP_EPHEMERAL = HEX.parseHex(
        "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b");
    private static final byte[] V_HANDSHAKE_HASH = HEX.parseHex(
        "45e34c56ca0de9c348e104edcf503035e5559ceed661ac22916f6f171696d994");
    private static final String[][] V_MESSAGES = {
        {"4c756477696720766f6e204d69736573",
         "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440b03ddc7aac5123d06a1b23b71670e32e76c28239a7ca4ac8f784de7e44c1adb78f2058771dfd4229fbdc85c5fba3b587b1d171ce368229c7b752ac25b8faf4e7b2fab7326f0d6fa1fdbef58de623245"},
        {"4d757272617920526f746862617264",
         "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d9b5a8927f0ac9655ef76833bc7e55269c081ec38c61031f76fe15b2aaaad5"},
        {"462e20412e20486179656b", "2c256ed08fcd08c2980f954ee4beaccb61c9581340f5dd2fd1cf3b"},
        {"4361726c204d656e676572", "d6033f70eee20945c7c9dba304e397ee3b284ff5e00fd9efb095d3"},
        {"4a65616e2d426170746973746520536179", "a9c068ca5d8babf72560652d8e851adbfac35c8a66e810d560863173e96adf4cfe"},
        {"457567656e2042f6686d20766f6e2042617765726b",
         "2a09d8f459e5927e40fdd2eddc99bdafb04e13a26f145cb5cfe9e6ba34c94331ebc17d5156"},
    };

    private static X25519.Keypair kp(byte[] priv) {
        return new X25519.Keypair(priv, X25519.publicKey(priv));
    }

    @Test
    void noiseCVectorHandshakeAndTransport() throws Exception {
        assertArrayEquals(V_INIT_REMOTE_STATIC, X25519.publicKey(V_RESP_STATIC), "vector self-consistency");

        NoiseIk init = NoiseIk.withEphemeral(true, V_PROLOGUE, kp(V_INIT_STATIC), V_INIT_REMOTE_STATIC,
            kp(V_INIT_EPHEMERAL));
        NoiseIk resp = NoiseIk.withEphemeral(false, V_PROLOGUE, kp(V_RESP_STATIC), null, kp(V_RESP_EPHEMERAL));

        byte[] m1 = init.writeMessage(HEX.parseHex(V_MESSAGES[0][0]));
        assertArrayEquals(HEX.parseHex(V_MESSAGES[0][1]), m1, "message 1");
        assertArrayEquals(HEX.parseHex(V_MESSAGES[0][0]), resp.readMessage(m1));
        assertArrayEquals(X25519.publicKey(V_INIT_STATIC), resp.remoteStatic());

        byte[] m2 = resp.writeMessage(HEX.parseHex(V_MESSAGES[1][0]));
        assertArrayEquals(HEX.parseHex(V_MESSAGES[1][1]), m2, "message 2");
        assertArrayEquals(HEX.parseHex(V_MESSAGES[1][0]), init.readMessage(m2));

        assertTrue(init.isFinished());
        assertTrue(resp.isFinished());
        assertArrayEquals(V_HANDSHAKE_HASH, init.handshakeHash());
        assertArrayEquals(V_HANDSHAKE_HASH, resp.handshakeHash());

        NoiseIk.Transport ti = init.transport();
        NoiseIk.Transport tr = resp.transport();
        for (int i = 2; i < V_MESSAGES.length; i++) {
            boolean fromInit = i % 2 == 0;
            byte[] payload = HEX.parseHex(V_MESSAGES[i][0]);
            byte[] ct = (fromInit ? ti : tr).encrypt(payload);
            assertArrayEquals(HEX.parseHex(V_MESSAGES[i][1]), ct, "transport message " + i);
            assertArrayEquals(payload, (fromInit ? tr : ti).decrypt(ct));
        }
    }

    @Test
    void randomKeysRoundTrip() throws Exception {
        X25519.Keypair hub = X25519.generate();
        X25519.Keypair node = X25519.generate();
        byte[] prologue = "jailscale-control-v1".getBytes(StandardCharsets.US_ASCII);

        NoiseIk init = NoiseIk.initiator(prologue, node, hub.publicKey());
        NoiseIk resp = NoiseIk.responder(prologue, hub);
        byte[] m1 = init.writeMessage(new byte[] {1, 2, 3});
        assertEquals(NoiseIk.MESSAGE1_OVERHEAD + 3, m1.length);
        assertArrayEquals(new byte[] {1, 2, 3}, resp.readMessage(m1));
        assertArrayEquals(node.publicKey(), resp.remoteStatic());
        byte[] m2 = resp.writeMessage(new byte[0]);
        assertEquals(NoiseIk.MESSAGE2_OVERHEAD, m2.length);
        assertArrayEquals(new byte[0], init.readMessage(m2));
        assertArrayEquals(init.handshakeHash(), resp.handshakeHash());

        NoiseIk.Transport a = init.transport();
        NoiseIk.Transport b = resp.transport();
        byte[] big = new byte[65535 - 16];
        assertArrayEquals(big, b.decrypt(a.encrypt(big)));
        assertThrows(NoiseException.class, () -> a.encrypt(new byte[65535 - 15]));
        assertEquals(1, a.sendState().nonce());
        assertEquals(1, b.receiveState().nonce());
    }

    @Test
    void wrongPrologueOrWrongHubKeyFails() throws Exception {
        X25519.Keypair hub = X25519.generate();
        X25519.Keypair other = X25519.generate();
        X25519.Keypair node = X25519.generate();

        NoiseIk init = NoiseIk.initiator(new byte[] {1}, node, hub.publicKey());
        NoiseIk resp = NoiseIk.responder(new byte[] {2}, hub);
        byte[] m1 = init.writeMessage(new byte[0]);
        assertThrows(NoiseException.class, () -> resp.readMessage(m1));

        NoiseIk init2 = NoiseIk.initiator(new byte[0], node, other.publicKey());
        NoiseIk resp2 = NoiseIk.responder(new byte[0], hub);
        byte[] m1b = init2.writeMessage(new byte[0]);
        assertThrows(NoiseException.class, () -> resp2.readMessage(m1b));
    }

    @Test
    void replayedOrReorderedTransportMessagesFail() throws Exception {
        X25519.Keypair hub = X25519.generate();
        X25519.Keypair node = X25519.generate();
        NoiseIk init = NoiseIk.initiator(null, node, hub.publicKey());
        NoiseIk resp = NoiseIk.responder(null, hub);
        resp.readMessage(init.writeMessage(null));
        init.readMessage(resp.writeMessage(null));
        NoiseIk.Transport a = init.transport();
        NoiseIk.Transport b = resp.transport();

        byte[] c1 = a.encrypt(new byte[] {1});
        byte[] c2 = a.encrypt(new byte[] {2});
        assertThrows(NoiseException.class, () -> b.decrypt(c2)); // out of order
        assertArrayEquals(new byte[] {1}, b.decrypt(c1));        // failure did not advance the nonce
        assertArrayEquals(new byte[] {2}, b.decrypt(c2));
        assertThrows(NoiseException.class, () -> b.decrypt(c1)); // replay
    }

    @Test
    void truncatedAndOutOfTurnMessagesAreRejected() throws Exception {
        X25519.Keypair hub = X25519.generate();
        X25519.Keypair node = X25519.generate();
        NoiseIk init = NoiseIk.initiator(null, node, hub.publicKey());
        NoiseIk resp = NoiseIk.responder(null, hub);
        assertThrows(NoiseException.class, () -> resp.writeMessage(null));
        assertThrows(NoiseException.class, () -> init.readMessage(new byte[100]));
        assertThrows(NoiseException.class, () -> resp.readMessage(new byte[NoiseIk.MESSAGE1_OVERHEAD - 1]));
        assertThrows(IllegalStateException.class, init::transport);
        assertFalse(init.isFinished());
    }

    @Test
    void rekeyAndNonceExhaustion() throws Exception {
        X25519.Keypair hub = X25519.generate();
        X25519.Keypair node = X25519.generate();
        NoiseIk init = NoiseIk.initiator(null, node, hub.publicKey());
        NoiseIk resp = NoiseIk.responder(null, hub);
        resp.readMessage(init.writeMessage(null));
        init.readMessage(resp.writeMessage(null));
        NoiseIk.Transport a = init.transport();
        NoiseIk.Transport b = resp.transport();

        a.sendState().rekey();
        b.receiveState().rekey();
        assertArrayEquals(new byte[] {9}, b.decrypt(a.encrypt(new byte[] {9})));

        a.sendState().setNonce(CipherState.MAX_NONCE);
        assertThrows(NoiseException.class, () -> a.encrypt(new byte[1]));
    }
}
