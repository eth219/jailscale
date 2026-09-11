package io.jailscale.crypto;

import java.util.Arrays;

/**
 * The {@code Noise_IK_25519_ChaChaPoly_BLAKE2s} handshake (Noise revision 34, §7.5):
 *
 * <pre>
 *   IK:
 *     &lt;- s
 *     ...
 *     -&gt; e, es, s, ss
 *     &lt;- e, ee, se
 * </pre>
 *
 * <p>The initiator must know the responder's static public key in advance (for jailscale, the
 * pinned hub key); the responder learns the initiator's static key from message 1. Each side
 * drives one instance through {@link #writeMessage}/{@link #readMessage} until
 * {@link #isFinished()}, then takes the {@link Transport}.
 *
 * <p>Not thread safe.
 */
public final class NoiseIk {

    public static final String PROTOCOL_NAME = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

    /** Overhead of message 1 beyond the payload: e(32) + enc(s)(48) + tag(16). */
    public static final int MESSAGE1_OVERHEAD = 32 + 32 + 16 + 16;
    /** Overhead of message 2 beyond the payload: e(32) + tag(16). */
    public static final int MESSAGE2_OVERHEAD = 32 + 16;

    private final boolean initiator;
    private final SymmetricState ss;
    private final byte[] s;      // local static private
    private final byte[] sPub;
    private byte[] e;            // local ephemeral private
    private byte[] ePub;
    private byte[] rs;           // remote static public
    private byte[] re;           // remote ephemeral public
    private int step;            // 0: msg1 pending, 1: msg2 pending, 2: finished
    private CipherState[] transport;

    private NoiseIk(boolean initiator, byte[] prologue, X25519.Keypair local, byte[] remoteStatic,
        X25519.Keypair ephemeral) {
        this.initiator = initiator;
        this.s = local.privateKey().clone();
        this.sPub = local.publicKey().clone();
        this.rs = remoteStatic == null ? null : remoteStatic.clone();
        if (ephemeral != null) {
            this.e = ephemeral.privateKey().clone();
            this.ePub = ephemeral.publicKey().clone();
        }
        this.ss = new SymmetricState(PROTOCOL_NAME);
        ss.mixHash(prologue == null ? new byte[0] : prologue);
        // Pre-message "<- s": both sides mix the responder's static public key.
        ss.mixHash(initiator ? rs : sPub);
    }

    /** Initiator with the responder's static public key pinned. */
    public static NoiseIk initiator(byte[] prologue, X25519.Keypair localStatic, byte[] responderStatic) {
        if (responderStatic == null || responderStatic.length != X25519.KEY_LEN) {
            throw new IllegalArgumentException("responder static key required");
        }
        return new NoiseIk(true, prologue, localStatic, responderStatic, null);
    }

    /** Responder; it learns the initiator's static key from message 1. */
    public static NoiseIk responder(byte[] prologue, X25519.Keypair localStatic) {
        return new NoiseIk(false, prologue, localStatic, null, null);
    }

    /** Test hook: fixed ephemeral keys so handshakes can be checked against published vectors. */
    static NoiseIk withEphemeral(boolean initiator, byte[] prologue, X25519.Keypair localStatic,
        byte[] responderStatic, X25519.Keypair ephemeral) {
        return new NoiseIk(initiator, prologue, localStatic, responderStatic, ephemeral);
    }

    public boolean isInitiator() {
        return initiator;
    }

    /** True once both messages have been processed and {@link #transport()} is available. */
    public boolean isFinished() {
        return step == 2;
    }

    /** The remote static public key; for the responder only known after message 1. */
    public byte[] remoteStatic() {
        return rs == null ? null : rs.clone();
    }

    /** Handshake hash {@code h}; identical on both sides and usable for channel binding. */
    public byte[] handshakeHash() {
        return ss.handshakeHash();
    }

    /**
     * Produces the next handshake message carrying {@code payload}. The initiator writes
     * message 1, the responder writes message 2.
     */
    public byte[] writeMessage(byte[] payload) throws NoiseException {
        if (payload == null) {
            payload = new byte[0];
        }
        if (step == 0 && initiator) {
            return writeMessage1(payload);
        }
        if (step == 1 && !initiator) {
            return writeMessage2(payload);
        }
        throw new NoiseException("not this side's turn to write");
    }

    /** Consumes the next handshake message and returns its payload. */
    public byte[] readMessage(byte[] message) throws NoiseException {
        return readMessage(message, 0, message.length);
    }

    public byte[] readMessage(byte[] message, int off, int len) throws NoiseException {
        if (step == 0 && !initiator) {
            return readMessage1(message, off, len);
        }
        if (step == 1 && initiator) {
            return readMessage2(message, off, len);
        }
        throw new NoiseException("not this side's turn to read");
    }

    /** The two transport directions. Only valid once {@link #isFinished()}. */
    public Transport transport() {
        if (transport == null) {
            throw new IllegalStateException("handshake not finished");
        }
        CipherState send = initiator ? transport[0] : transport[1];
        CipherState recv = initiator ? transport[1] : transport[0];
        return new Transport(send, recv, handshakeHash());
    }

    // -> e, es, s, ss
    private byte[] writeMessage1(byte[] payload) throws NoiseException {
        ensureEphemeral();
        ss.mixHash(ePub);
        ss.mixKey(X25519.dh(e, rs));                       // es
        byte[] encS = ss.encryptAndHash(sPub);             // s
        ss.mixKey(X25519.dh(s, rs));                       // ss
        byte[] encPayload = ss.encryptAndHash(payload);
        step = 1;
        return concat(ePub, encS, encPayload);
    }

    private byte[] readMessage1(byte[] msg, int off, int len) throws NoiseException {
        if (len < MESSAGE1_OVERHEAD) {
            throw new NoiseException("message 1 too short");
        }
        re = Arrays.copyOfRange(msg, off, off + 32);
        ss.mixHash(re);
        ss.mixKey(dhOrFail(s, re));                        // es (responder side)
        rs = ss.decryptAndHash(msg, off + 32, 48);         // s
        ss.mixKey(dhOrFail(s, rs));                        // ss
        byte[] payload = ss.decryptAndHash(msg, off + 80, len - 80);
        step = 1;
        return payload;
    }

    // <- e, ee, se
    private byte[] writeMessage2(byte[] payload) throws NoiseException {
        ensureEphemeral();
        ss.mixHash(ePub);
        ss.mixKey(X25519.dh(e, re));                       // ee
        ss.mixKey(X25519.dh(e, rs));                       // se (responder side)
        byte[] encPayload = ss.encryptAndHash(payload);
        finish();
        return concat(ePub, encPayload);
    }

    private byte[] readMessage2(byte[] msg, int off, int len) throws NoiseException {
        if (len < MESSAGE2_OVERHEAD) {
            throw new NoiseException("message 2 too short");
        }
        re = Arrays.copyOfRange(msg, off, off + 32);
        ss.mixHash(re);
        ss.mixKey(dhOrFail(e, re));                        // ee
        ss.mixKey(dhOrFail(s, re));                        // se
        byte[] payload = ss.decryptAndHash(msg, off + 32, len - 32);
        finish();
        return payload;
    }

    private void finish() {
        transport = ss.split();
        step = 2;
        wipe(e);
        e = null;
    }

    private void ensureEphemeral() {
        if (e == null) {
            X25519.Keypair kp = X25519.generate();
            e = kp.privateKey();
            ePub = kp.publicKey();
        }
    }

    private static byte[] dhOrFail(byte[] priv, byte[] pub) throws NoiseException {
        try {
            return X25519.dh(priv, pub);
        } catch (IllegalArgumentException ex) {
            throw new NoiseException("invalid peer key", ex);
        }
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    private static void wipe(byte[] b) {
        if (b != null) {
            Arrays.fill(b, (byte) 0);
        }
    }

    /** Zeroes the local private keys held by this handshake. */
    public void destroy() {
        wipe(s);
        wipe(e);
        ss.destroy();
    }

    /** Post-handshake transport: one CipherState per direction plus the handshake hash. */
    public static final class Transport {
        private final CipherState send;
        private final CipherState recv;
        private final byte[] handshakeHash;

        Transport(CipherState send, CipherState recv, byte[] handshakeHash) {
            this.send = send;
            this.recv = recv;
            this.handshakeHash = handshakeHash;
        }

        /** Encrypts a transport payload (max 65535 - 16 bytes per Noise §3). */
        public byte[] encrypt(byte[] plaintext) throws NoiseException {
            if (plaintext.length > 65535 - ChaChaPoly.TAG_LEN) {
                throw new NoiseException("payload exceeds Noise message limit");
            }
            return send.encryptWithAd(new byte[0], plaintext);
        }

        public byte[] decrypt(byte[] ciphertext) throws NoiseException {
            return decrypt(ciphertext, 0, ciphertext.length);
        }

        public byte[] decrypt(byte[] ciphertext, int off, int len) throws NoiseException {
            if (len > 65535) {
                throw new NoiseException("message exceeds Noise message limit");
            }
            return recv.decryptWithAd(new byte[0], ciphertext, off, len);
        }

        public CipherState sendState() {
            return send;
        }

        public CipherState receiveState() {
            return recv;
        }

        public byte[] handshakeHash() {
            return handshakeHash.clone();
        }

        public void destroy() {
            send.destroy();
            recv.destroy();
        }
    }
}
