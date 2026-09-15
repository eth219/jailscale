package io.jailscale.hub;

import io.jailscale.crypto.Blake2s;
import io.jailscale.crypto.Hkdf;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * The proof a primary gives that it is reachable, carried by a node (ARCHITECTURE.md §13.5): a
 * MAC over the standby's nonce and the primary's epoch under a key derived from {@code hub.key},
 * which both hubs hold and no node does. The node relays bytes it cannot make.
 */
final class Liveness {

    private static final byte[] LABEL = "jailscale-liveness-v1".getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RNG = new SecureRandom();

    private Liveness() {}

    static byte[] nonce() {
        byte[] n = new byte[16];
        RNG.nextBytes(n);
        return n;
    }

    private static byte[] key(byte[] hubPrivate) {
        return Blake2s.hash(LABEL, hubPrivate);
    }

    static byte[] mac(byte[] hubPrivate, byte[] nonce, long epoch) {
        byte[] e = new byte[8];
        for (int i = 0; i < 8; i++) {
            e[i] = (byte) (epoch >>> (56 - 8 * i));
        }
        return Hkdf.hmac(key(hubPrivate), nonce, e);
    }

    static boolean verify(byte[] hubPrivate, byte[] nonce, long epoch, byte[] mac) {
        return mac != null && MessageDigest.isEqual(mac(hubPrivate, nonce, epoch), mac);
    }
}
