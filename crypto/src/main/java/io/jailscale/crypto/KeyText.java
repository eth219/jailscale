package io.jailscale.crypto;

import java.util.Base64;

/**
 * Text form of 32-byte keys: {@code <prefix>:<base64url, no padding>} (DESIGN.md §5).
 * The prefix names the key's role so a key pasted into the wrong place fails to parse
 * instead of silently working.
 */
public final class KeyText {

    public static final String MACHINE = "mkey";
    public static final String HUB = "hkey";

    private static final Base64.Encoder ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DEC = Base64.getUrlDecoder();

    private KeyText() {}

    public static String format(String prefix, byte[] key) {
        if (key.length != X25519.KEY_LEN) {
            throw new IllegalArgumentException("keys are " + X25519.KEY_LEN + " bytes");
        }
        return prefix + ":" + ENC.encodeToString(key);
    }

    /** Parses {@code text}, requiring exactly {@code expectedPrefix}. */
    public static byte[] parse(String expectedPrefix, String text) {
        if (text == null) {
            throw new IllegalArgumentException("missing key");
        }
        String t = text.strip();
        int colon = t.indexOf(':');
        if (colon < 0) {
            throw new IllegalArgumentException("key has no prefix (expected " + expectedPrefix + ":)");
        }
        String prefix = t.substring(0, colon);
        if (!prefix.equals(expectedPrefix)) {
            throw new IllegalArgumentException("expected a " + expectedPrefix + ": key, got " + prefix + ":");
        }
        byte[] raw;
        try {
            raw = DEC.decode(t.substring(colon + 1));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("key is not base64url", e);
        }
        if (raw.length != X25519.KEY_LEN) {
            throw new IllegalArgumentException("key must decode to " + X25519.KEY_LEN + " bytes, got " + raw.length);
        }
        return raw;
    }
}
