package io.jailscale.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Noise SymmetricState (§5.2): chaining key, handshake hash and the handshake CipherState. */
final class SymmetricState {

    private final CipherState cipher = new CipherState();
    private byte[] ck;
    private byte[] h;

    SymmetricState(String protocolName) {
        byte[] name = protocolName.getBytes(StandardCharsets.US_ASCII);
        if (name.length <= Hkdf.HASH_LEN) {
            h = Arrays.copyOf(name, Hkdf.HASH_LEN);
        } else {
            h = Blake2s.hash(name);
        }
        ck = h.clone();
    }

    void mixKey(byte[] inputKeyMaterial) {
        byte[][] out = Hkdf.hkdf(ck, inputKeyMaterial, 2);
        Arrays.fill(ck, (byte) 0);
        ck = out[0];
        cipher.initializeKey(out[1]);
        Arrays.fill(out[1], (byte) 0);
    }

    void mixHash(byte[] data) {
        h = Blake2s.hash(h, data);
    }

    byte[] encryptAndHash(byte[] plaintext) throws NoiseException {
        byte[] ct = cipher.encryptWithAd(h, plaintext);
        mixHash(ct);
        return ct;
    }

    byte[] decryptAndHash(byte[] ciphertext, int off, int len) throws NoiseException {
        byte[] pt = cipher.decryptWithAd(h, ciphertext, off, len);
        mixHash(Arrays.copyOfRange(ciphertext, off, off + len));
        return pt;
    }

    boolean hasKey() {
        return cipher.hasKey();
    }

    byte[] handshakeHash() {
        return h.clone();
    }

    /** Split(): two transport CipherStates, the first for the initiator's sending direction. */
    CipherState[] split() {
        byte[][] out = Hkdf.hkdf(ck, new byte[0], 2);
        CipherState c1 = new CipherState();
        CipherState c2 = new CipherState();
        c1.initializeKey(out[0]);
        c2.initializeKey(out[1]);
        Arrays.fill(out[0], (byte) 0);
        Arrays.fill(out[1], (byte) 0);
        destroy();
        return new CipherState[] {c1, c2};
    }

    void destroy() {
        cipher.destroy();
        if (ck != null) {
            Arrays.fill(ck, (byte) 0);
        }
    }
}
