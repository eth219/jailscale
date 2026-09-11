package io.jailscale.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class KeyTextTest {

    @Test
    void roundTrip() {
        byte[] key = X25519.generate().publicKey();
        String text = KeyText.format(KeyText.HUB, key);
        assertTrue(text.startsWith("hkey:"));
        assertTrue(text.length() == 5 + 43, text);
        assertArrayEquals(key, KeyText.parse(KeyText.HUB, text));
        assertArrayEquals(key, KeyText.parse(KeyText.HUB, "  " + text + "\n"));
    }

    @Test
    void wrongPrefixOrShapeIsRejected() {
        String hub = KeyText.format(KeyText.HUB, new byte[32]);
        assertThrows(IllegalArgumentException.class, () -> KeyText.parse(KeyText.MACHINE, hub));
        assertThrows(IllegalArgumentException.class, () -> KeyText.parse(KeyText.HUB, hub.substring(5)));
        assertThrows(IllegalArgumentException.class, () -> KeyText.parse(KeyText.HUB, "hkey:AAAA"));
        assertThrows(IllegalArgumentException.class, () -> KeyText.parse(KeyText.HUB, "hkey:***"));
        assertThrows(IllegalArgumentException.class, () -> KeyText.parse(KeyText.HUB, null));
        assertThrows(IllegalArgumentException.class, () -> KeyText.format(KeyText.HUB, new byte[31]));
    }
}
