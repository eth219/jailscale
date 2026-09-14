package io.jailscale.node;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * The Ed25519 keys a release may be signed with, compiled in (ARCHITECTURE.md §9.4).
 *
 * <p>A checksum file published by the account that published the binaries proves that the download
 * was not corrupted on the way; it proves nothing about who produced it, because whoever could
 * replace the binary could replace the list of hashes next to it. A signature made somewhere the
 * release pipeline cannot reach is what turns "these bytes arrived intact" into "this is the
 * release the maintainer signed", and it is the thing §9.4 named as missing before a downloaded
 * binary was worth handing to anyone.
 *
 * <p><b>The keys live here and nowhere else.</b> Not in the state file, not in a flag, and above
 * all not in anything the hub says: the same reasoning that keeps {@link Updates#LATEST} compiled
 * in (§11.2) applies with more force to what decides which binaries are acceptable. A build
 * carrying no key refuses to download rather than falling back to the checksum alone, which would
 * be the whole exercise undone by a default.
 *
 * <p><b>A list, so that a key can be replaced.</b> With one key there is no way out of a key that
 * has to change: every binary in the field accepts that key and nothing else, so a new one strands
 * all of them. Rotation is therefore a two-release move, and it only works if the clients were
 * taught the next key before it was used — release N ships accepting {old, new} and is signed with
 * old; release N+1 is signed with new and the binaries already accept it. Any key on this list can
 * sign, so a list is also the blast radius: a key stays here only while it is meant to be able to.
 */
final class ReleaseKey {

    /**
     * Base64 of each 44-byte X.509 SubjectPublicKeyInfo, as {@code tools/release-key.sh} prints it,
     * the one in use first. Today: fingerprint {@code fa85db4931653cbb}, made 2026-09-14.
     *
     * <p>The private halves live in Cloud KMS and have never existed as files.
     * {@code tools/sign-release.sh} asks KMS for a signature from the maintainer's own machine, so
     * there is nothing on that machine to steal between releases, every use is in the audit log,
     * and a key believed compromised can be disabled rather than lived with. <b>Deliberately not
     * reachable from GitHub Actions</b>, by federation or otherwise — a signature the release
     * pipeline can make is worth what the checksums beside it are worth, which is the reason these
     * keys exist (§9.4).
     *
     * <p>Empty in a tree whose maintainer has not made a key yet, which {@link #configured}
     * reports and {@code update --download} refuses on.
     */
    static final List<String> PUBLIC_KEYS = List.of(
        "MCowBQYDK2VwAyEAg0LBDS1WpfjvkgUttkrqb+eoByPGmYrivlYjhE3QM3I=");

    private ReleaseKey() {}

    /** Whether this build can check a signature at all. */
    static boolean configured() {
        return !PUBLIC_KEYS.isEmpty();
    }

    /**
     * Verifies {@code signature} over {@code message} against the compiled-in keys, and returns the
     * fingerprint of the one that accepted it — which is what the operator is shown, so that "it
     * verified" names a key rather than a list.
     */
    static String verify(byte[] message, byte[] signature) throws GeneralSecurityException {
        return verify(PUBLIC_KEYS, message, signature);
    }

    /**
     * The same check against named keys, so a test can hold it against key pairs it made itself.
     * Throws rather than returning false: there is one acceptable outcome and every other one has
     * a reason worth printing.
     */
    static String verify(List<String> keys, byte[] message, byte[] signature) throws GeneralSecurityException {
        if (keys.isEmpty()) {
            throw new SignatureException("this build carries no release signing key");
        }
        List<String> tried = new ArrayList<>(keys.size());
        for (String key : keys) {
            PublicKey pub = publicKey(key); // a key on this list that is not one is a build defect, not a "no"
            tried.add(fingerprint(key));
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(pub);
            v.update(message);
            try {
                if (v.verify(signature)) {
                    return fingerprint(key);
                }
            } catch (SignatureException e) {
                // Malformed for this key is malformed for all of them; keep going so the message
                // below names every key that was tried rather than only the first.
            }
        }
        throw new SignatureException("the release signature matches none of the keys this build accepts ("
            + String.join(", ", tried) + ")");
    }

    /** Eight bytes of SHA-256 over the key, so an operator can say which key checked a download. */
    static String fingerprint(String base64Spki) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(decode(base64Spki));
            return HexFormat.of().formatHex(h, 0, 8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return "unreadable";
        }
    }

    private static PublicKey publicKey(String base64Spki) throws GeneralSecurityException {
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(decode(base64Spki)));
        } catch (IllegalArgumentException e) {
            throw new SignatureException("a compiled-in release key is not base64: " + e.getMessage());
        }
    }

    private static byte[] decode(String base64) {
        return Base64.getDecoder().decode(base64.replaceAll("\\s", ""));
    }
}
