package io.jailscale.hub;

import io.jailscale.proto.util.Sha256;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

/** Invite tokens, short codes and their stored hashes (ARCHITECTURE.md §10). */
final class Tokens {

    private static final SecureRandom RNG = new SecureRandom();
    private static final String CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    private Tokens() {}

    /** 128-bit token, base64url without padding (22 chars). */
    static String inviteToken() {
        byte[] b = new byte[16];
        RNG.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /** 40-bit Crockford base32 code formatted {@code XXXX-XXXX}. */
    static String shortCode() {
        byte[] b = new byte[5];
        RNG.nextBytes(b);
        long v = 0;
        for (byte x : b) {
            v = (v << 8) | (x & 0xff);
        }
        StringBuilder sb = new StringBuilder(9);
        for (int i = 7; i >= 0; i--) {
            sb.append(CROCKFORD.charAt((int) ((v >>> (5 * i)) & 31)));
            if (i == 4) {
                sb.append('-');
            }
        }
        return sb.toString();
    }

    /** Canonical form of a typed code: upper case, Crockford aliases folded, hyphen removed. */
    static String normalizeCode(String typed) {
        StringBuilder sb = new StringBuilder(8);
        for (char c : typed.toUpperCase(Locale.ROOT).toCharArray()) {
            switch (c) {
                case '-', ' ' -> { }
                case 'O' -> sb.append('0');
                case 'I', 'L' -> sb.append('1');
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    static String hash(String secret) {
        return Sha256.hex(secret);
    }

    static String id(String prefix) {
        byte[] b = new byte[6];
        RNG.nextBytes(b);
        return prefix + HexFormat.of().formatHex(b);
    }
}
