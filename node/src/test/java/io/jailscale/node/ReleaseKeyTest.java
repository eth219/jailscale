package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The signature that decides whether a downloaded release is the maintainer's (ARCHITECTURE.md
 * §9.4). Held against a key pair made here rather than the compiled-in one, so the check is
 * exercised in a tree that has no release key -- and the last test is that such a tree refuses to
 * check rather than quietly passing.
 */
class ReleaseKeyTest {

    private static final byte[] SUMS = ("6d0b1a4dce6e5e0d3e4b0ee0d0ab2a56b57e0dd8a2b1a06e0a49f24a2b5c93aa"
        + "  jailscale-linux-amd64\n").getBytes(StandardCharsets.UTF_8);

    /** A key pair, its public half as {@code PUBLIC_KEYS} carries one, and a signature: shared with {@link UpdateDownloadTest}. */
    static KeyPair keyPair() throws GeneralSecurityException {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    static String spki(KeyPair kp) {
        return Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
    }

    static byte[] sign(KeyPair kp, byte[] message) throws GeneralSecurityException {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(kp.getPrivate());
        s.update(message);
        return s.sign();
    }

    @Test
    void acceptsWhatTheReleaseKeySigned() throws Exception {
        KeyPair kp = keyPair();
        assertEquals(ReleaseKey.fingerprint(spki(kp)), ReleaseKey.verify(List.of(spki(kp)), SUMS, sign(kp, SUMS)));
    }

    @Test
    void anyKeyOnTheListMaySignAndTheAnswerSaysWhichDid() throws Exception {
        // Rotation is a two-release move: the build that ships accepting {old, new} is signed with
        // old, and the one after it is signed with new. Both have to be accepted by the build in
        // between, or the rotation strands exactly the binaries it exists to carry across.
        KeyPair oldKey = keyPair();
        KeyPair newKey = keyPair();
        List<String> both = List.of(spki(oldKey), spki(newKey));
        assertEquals(ReleaseKey.fingerprint(spki(oldKey)), ReleaseKey.verify(both, SUMS, sign(oldKey, SUMS)));
        assertEquals(ReleaseKey.fingerprint(spki(newKey)), ReleaseKey.verify(both, SUMS, sign(newKey, SUMS)));
        // And a key that was never on the list is still refused, with every key that was tried named.
        SignatureException e = assertThrows(SignatureException.class,
            () -> ReleaseKey.verify(both, SUMS, sign(keyPair(), SUMS)));
        assertTrue(e.getMessage().contains(ReleaseKey.fingerprint(spki(oldKey))), e.getMessage());
        assertTrue(e.getMessage().contains(ReleaseKey.fingerprint(spki(newKey))), e.getMessage());
        // A list nobody filled in is a refusal, not an acceptance, and it says that no key was tried.
        SignatureException none = assertThrows(SignatureException.class,
            () -> ReleaseKey.verify(List.of(), SUMS, sign(oldKey, SUMS)));
        assertTrue(none.getMessage().contains("(none)"), none.getMessage());
    }

    @Test
    void refusesEverySignatureThatIsNotThatOne() throws Exception {
        KeyPair kp = keyPair();
        byte[] good = sign(kp, SUMS);

        // The file, changed. This is the attack the signature exists for: a checksum list is only
        // worth the key over it, because whoever can replace a binary can replace the list too.
        byte[] edited = SUMS.clone();
        edited[0] = (byte) '7';
        assertThrows(SignatureException.class, () -> ReleaseKey.verify(List.of(spki(kp)), edited, good));

        // The signature, changed.
        byte[] bent = good.clone();
        bent[0] ^= 0x01;
        assertThrows(SignatureException.class, () -> ReleaseKey.verify(List.of(spki(kp)), SUMS, bent));

        // Someone else's key, signing correctly. A valid signature by the wrong signer is exactly
        // what a compromised release account would produce.
        KeyPair other = keyPair();
        assertThrows(SignatureException.class, () -> ReleaseKey.verify(List.of(spki(kp)), SUMS, sign(other, SUMS)));

        // Nothing at all, and something that is not a signature.
        assertThrows(GeneralSecurityException.class, () -> ReleaseKey.verify(List.of(spki(kp)), SUMS, new byte[0]));
        assertThrows(GeneralSecurityException.class, () -> ReleaseKey.verify(List.of(spki(kp)), SUMS, new byte[64]));
    }

    @Test
    void aKeyThatIsNotOneIsRefusedRatherThanIgnored() throws Exception {
        KeyPair kp = keyPair();
        byte[] good = sign(kp, SUMS);
        assertThrows(GeneralSecurityException.class, () -> ReleaseKey.verify(List.of("not base64!"), SUMS, good));
        assertThrows(GeneralSecurityException.class, () -> ReleaseKey.verify(List.of("AAAA"), SUMS, good));
        // A broken key next to a working one is a defect in the build, not a signature to shrug at.
        assertThrows(GeneralSecurityException.class,
            () -> ReleaseKey.verify(List.of("AAAA", spki(kp)), SUMS, good));
    }

    @Test
    void theFingerprintNamesTheKeyThatCheckedIt() throws Exception {
        String a = spki(keyPair());
        String b = spki(keyPair());
        assertEquals(16, ReleaseKey.fingerprint(a).length());
        assertTrue(ReleaseKey.fingerprint(a).matches("[0-9a-f]{16}"));
        assertNotEquals(ReleaseKey.fingerprint(a), ReleaseKey.fingerprint(b));
        assertEquals(ReleaseKey.fingerprint(a), ReleaseKey.fingerprint(a));
        assertEquals("unreadable", ReleaseKey.fingerprint("not base64!"));
    }

    @Test
    void theCompiledInKeyIsTheOneReleasesAreSignedWith() {
        // A paste that lost a character, or a key nobody replaced after a rotation, would both be
        // caught here rather than by the first operator whose download refuses. The refusal when
        // there is no key at all is UpdateDownloadTest's, which does not depend on this constant.
        assertFalse(ReleaseKey.PUBLIC_KEYS.isEmpty(), "ReleaseKey.PUBLIC_KEYS is empty; tools/release-key.sh makes one");
        assertEquals(List.of("fa85db4931653cbb"), ReleaseKey.PUBLIC_KEYS.stream().map(ReleaseKey::fingerprint).toList(),
            "the accepted release keys changed; adding one widens what this build will install, and"
                + " removing one strands every binary that was signed with it");
        // And they are keys, not just 44 bytes of base64: a signature is what gets refused here, not
        // the key, which would throw a different exception before any signature was looked at.
        assertThrows(SignatureException.class, () -> ReleaseKey.verify(ReleaseKey.PUBLIC_KEYS, SUMS, new byte[64]));
    }
}
