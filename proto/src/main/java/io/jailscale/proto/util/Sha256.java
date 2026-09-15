package io.jailscale.proto.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-256 as lowercase hex, spelled once. Every Java platform is required to provide the
 * algorithm, so the checked exception is a programming error rather than a condition to handle.
 */
public final class Sha256 {

    private Sha256() {}

    public static MessageDigest digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("no SHA-256 in this runtime", e);
        }
    }

    public static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(digest().digest(bytes));
    }

    public static String hex(String utf8) {
        return hex(utf8.getBytes(StandardCharsets.UTF_8));
    }
}
