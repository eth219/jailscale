package io.jailscale.hub;

import io.jailscale.crypto.KeyText;
import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;

/**
 * The hub's static Noise key and its rotation (ARCHITECTURE.md §5.2). {@code hub.key} holds the
 * current private key, {@code hub.key.next} the next one during a grace period.
 */
final class HubKeys {

    private static final Log LOG = Log.get("keys");
    static final String PRIVATE_PREFIX = "hkeypriv";
    static final byte[] PROLOGUE = "jailscale-control-v1".getBytes(StandardCharsets.US_ASCII);

    private final Path current;
    private final Path next;
    private X25519.Keypair cur;
    private X25519.Keypair nxt;

    HubKeys(Path stateDir) throws IOException {
        this.current = stateDir.resolve("hub.key");
        this.next = stateDir.resolve("hub.key.next");
        Files.createDirectories(stateDir);
        if (Files.exists(current)) {
            cur = load(current);
        } else {
            cur = X25519.generate();
            save(current, cur);
            LOG.info("generated hub key {}", KeyText.format(KeyText.HUB, cur.publicKey()));
        }
        if (Files.exists(next)) {
            nxt = load(next);
        }
    }

    /** Whether a hub key exists in {@code stateDir}: a standby must be given one, not make one. */
    static boolean exists(Path stateDir) {
        return Files.exists(stateDir.resolve("hub.key"));
    }

    synchronized String publicText() {
        return KeyText.format(KeyText.HUB, cur.publicKey());
    }

    /** The current key pair, for a standby to authenticate to its primary with (§13.1). */
    synchronized X25519.Keypair current() {
        return cur;
    }

    /**
     * Whether {@code remoteStatic} is this hub's own public key, current or next. An initiator
     * that completed Noise IK with it holds the private half, which is what makes it a peer hub.
     */
    synchronized boolean isOwn(byte[] remoteStatic) {
        return java.util.Arrays.equals(remoteStatic, cur.publicKey())
            || (nxt != null && java.util.Arrays.equals(remoteStatic, nxt.publicKey()));
    }

    synchronized String privateText() {
        return KeyText.format(PRIVATE_PREFIX, cur.privateKey());
    }

    synchronized String nextPrivateText() {
        return nxt == null ? null : KeyText.format(PRIVATE_PREFIX, nxt.privateKey());
    }

    synchronized String nextPublicText() {
        return nxt == null ? null : KeyText.format(KeyText.HUB, nxt.publicKey());
    }

    /** Responder handshake states for every key that is currently accepted (current first). */
    synchronized List<NoiseIk> responders() {
        List<NoiseIk> l = new ArrayList<>(2);
        l.add(NoiseIk.responder(PROLOGUE, cur));
        if (nxt != null) {
            l.add(NoiseIk.responder(PROLOGUE, nxt));
        }
        return l;
    }

    /** Creates the next key (idempotent) and returns its public text. */
    synchronized String beginRotation() throws IOException {
        if (nxt == null) {
            nxt = X25519.generate();
            save(next, nxt);
            LOG.info("rotation started, next hub key {}", nextPublicText());
        }
        return nextPublicText();
    }

    /** Promotes next to current. */
    synchronized void completeRotation() throws IOException {
        if (nxt == null) {
            return;
        }
        save(current, nxt);
        Files.deleteIfExists(next);
        cur.destroy();
        cur = nxt;
        nxt = null;
        LOG.info("rotation complete, hub key is now {}", publicText());
    }

    private static X25519.Keypair load(Path p) throws IOException {
        byte[] priv = KeyText.parse(PRIVATE_PREFIX, Files.readString(p, StandardCharsets.UTF_8));
        return new X25519.Keypair(priv, X25519.publicKey(priv));
    }

    private static void save(Path p, X25519.Keypair kp) throws IOException {
        Files.writeString(p, KeyText.format(PRIVATE_PREFIX, kp.privateKey()) + "\n", StandardCharsets.UTF_8);
        try {
            Files.setPosixFilePermissions(p, EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException _) {
            // Windows: directory ACL
        }
    }
}
