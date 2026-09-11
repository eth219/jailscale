package io.jailscale.proto.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The pieces of RFC 8446 the transcript check rests on, against hand-built bytes. */
class Tls13Test {

    private static byte[] hello(int type, byte[] random, byte[] tail) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(3);
        b.write(3);
        b.write(random, 0, 32);
        b.write(tail, 0, tail.length);
        return Tls13.message(type, b.toByteArray());
    }

    private static byte[] record(int type, byte[] payload, int from, int to) {
        byte[] r = new byte[5 + to - from];
        r[0] = (byte) type;
        r[1] = 3;
        r[2] = 3;
        r[3] = (byte) ((to - from) >> 8);
        r[4] = (byte) (to - from);
        System.arraycopy(payload, from, r, 5, to - from);
        return r;
    }

    @Test
    void tapCollectsPlaintextHandshakeMessagesAcrossRecordsAndStopsAtApplicationData() {
        byte[] ch1 = hello(Tls13.CLIENT_HELLO, new byte[32], new byte[] {0, 0, 2, 0x13, 1, 1, 0, 0, 0});
        byte[] ch2 = hello(Tls13.CLIENT_HELLO, new byte[32], new byte[] {0, 0, 2, 0x13, 1, 1, 0, 0, 0});
        ch2[10] = 7;
        Tls13.Tap tap = new Tls13.Tap();
        // one message split over two records, a change-cipher-spec in between, the second whole, then application data
        tap.accept(record(22, ch1, 0, 20));
        assertEquals(0, tap.messages().size(), "half a message is not a message");
        byte[] rest = record(22, ch1, 20, ch1.length);
        tap.accept(rest, 0, 3); // and a record header split across writes
        tap.accept(rest, 3, rest.length - 3);
        assertEquals(1, tap.messages().size());
        tap.accept(record(20, new byte[] {1}, 0, 1));
        tap.accept(record(22, ch2, 0, ch2.length));
        assertFalse(tap.done());
        tap.accept(record(23, new byte[] {9, 9, 9}, 0, 3));
        assertTrue(tap.done());
        tap.accept(record(22, ch1, 0, ch1.length)); // after application data nothing is plaintext, so nothing is taken
        List<byte[]> m = tap.messages();
        assertEquals(2, m.size());
        assertArrayEquals(ch1, m.get(0));
        assertArrayEquals(ch2, m.get(1));
    }

    @Test
    void helloRetryRequestIsAServerHelloWithTheFixedRandom() {
        byte[] hrrRandom = HexFormat.of().parseHex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c");
        byte[] hrr = hello(Tls13.SERVER_HELLO, hrrRandom, new byte[] {0, 0x13, 1, 0, 0, 0});
        byte[] sh = hello(Tls13.SERVER_HELLO, new byte[32], new byte[] {0, 0x13, 1, 0, 0, 0});
        assertTrue(Tls13.isHelloRetryRequest(hrr));
        assertFalse(Tls13.isHelloRetryRequest(sh));
        assertFalse(Tls13.isHelloRetryRequest(hello(Tls13.CLIENT_HELLO, hrrRandom, new byte[] {0})));
    }

    @Test
    void transcriptFollowsSection441WithAndWithoutARetry() throws Exception {
        byte[] ch1 = hello(Tls13.CLIENT_HELLO, new byte[32], new byte[] {0, 0, 2, 0x13, 1, 1, 0, 0, 0});
        byte[] ch2 = hello(Tls13.CLIENT_HELLO, new byte[32], new byte[] {0, 0, 2, 0x13, 1, 1, 0, 0, 0});
        ch2[9] = 1;
        byte[] hrrRandom = HexFormat.of().parseHex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c");
        byte[] hrr = hello(Tls13.SERVER_HELLO, hrrRandom, new byte[] {0, 0x13, 1, 0, 0, 0});
        byte[] sh = hello(Tls13.SERVER_HELLO, new byte[32], new byte[] {0, 0x13, 1, 0, 0, 0});
        byte[] ee = Tls13.encryptedExtensions(true, new int[] {Tls13.GROUP_X25519}, "http/1.1", true);
        byte[] cert = Tls13.message(Tls13.CERTIFICATE, new byte[] {0, 0, 0, 0});

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(ch1);
        md.update(sh);
        md.update(ee);
        md.update(cert);
        assertArrayEquals(md.digest(), Tls13.transcriptHash("SHA-256", List.of(ch1), null, sh, ee, cert));

        md = MessageDigest.getInstance("SHA-256");
        md.update(Tls13.message(Tls13.MESSAGE_HASH, MessageDigest.getInstance("SHA-256").digest(ch1)));
        md.update(hrr);
        md.update(ch2);
        md.update(sh);
        md.update(ee);
        md.update(cert);
        assertArrayEquals(md.digest(), Tls13.transcriptHash("SHA-256", List.of(ch1, ch2), hrr, sh, ee, cert));

        // the pieces have to fit: a retry needs two hellos, no retry needs one, and types are checked
        assertThrows(IllegalArgumentException.class, () -> Tls13.transcriptHash("SHA-256", List.of(ch1, ch2), null, sh, ee, cert));
        assertThrows(IllegalArgumentException.class, () -> Tls13.transcriptHash("SHA-256", List.of(ch1), hrr, sh, ee, cert));
        assertThrows(IllegalArgumentException.class, () -> Tls13.transcriptHash("SHA-256", List.of(ch1), null, hrr, ee, cert));
        assertThrows(IllegalArgumentException.class, () -> Tls13.transcriptHash("SHA-256", List.of(ch1), null, sh, cert, ee));
        assertThrows(IllegalArgumentException.class, () -> Tls13.transcriptHash("SHA-256", List.of(ch1), null, sh, ee, Arrays.copyOf(cert, 3)));
    }

    @Test
    void certificateVerifyContentIsRecognisedByItsContextAndHashLength() {
        byte[] c32 = Arrays.copyOf(Tls13.CERT_VERIFY_CONTEXT, Tls13.CERT_VERIFY_CONTEXT.length + 32);
        byte[] c48 = Arrays.copyOf(Tls13.CERT_VERIFY_CONTEXT, Tls13.CERT_VERIFY_CONTEXT.length + 48);
        assertEquals("SHA-256", Tls13.hashAlgorithmOf(c32));
        assertEquals("SHA-384", Tls13.hashAlgorithmOf(c48));
        assertNull(Tls13.hashAlgorithmOf(Arrays.copyOf(Tls13.CERT_VERIFY_CONTEXT, Tls13.CERT_VERIFY_CONTEXT.length + 40)));
        byte[] wrongLabel = c32.clone();
        wrongLabel[70] ^= 1;
        assertNull(Tls13.hashAlgorithmOf(wrongLabel));
        assertNull(Tls13.hashAlgorithmOf(new byte[32]));
        assertEquals(32, Tls13.transcriptHashIn(c32).length);
    }

    @Test
    void encodingsMatchTheWireFormat() throws Exception {
        // EncryptedExtensions with one group and http/1.1, as captured from JSSE 25
        assertEquals("080000190017000a00040002001d0010000b000908687474702f312e31",
            HexFormat.of().formatHex(Tls13.encryptedExtensions(true, new int[] {Tls13.GROUP_X25519}, "http/1.1", true)));
        assertEquals("0800000a0008000a00040002001d",
            HexFormat.of().formatHex(Tls13.encryptedExtensions(true, new int[] {Tls13.GROUP_X25519}, "http/1.1", false)));
        assertEquals("0800000200 00".replace(" ", ""),
            HexFormat.of().formatHex(Tls13.encryptedExtensions(false, new int[] {Tls13.GROUP_X25519}, "http/1.1", false)));
        // ServerHello: version, random, echoed id, suite, no compression, supported_versions then key_share
        byte[] sh = Tls13.serverHello(new byte[32], new byte[] {1, 2}, 0x1301, new byte[32]);
        String hex = HexFormat.of().formatHex(sh);
        assertTrue(hex.startsWith("020000580303" + "00".repeat(32) + "020102" + "1301" + "00" + "002e" + "002b00020304" + "00330024001d0020"), hex);
        assertEquals(4 + 0x58, sh.length);
        // ALPN lists and session ids come out of a ClientHello
        byte[] alpn = HexFormat.of().parseHex("000c02683208687474702f312e31");
        assertTrue(Tls13.alpnOffers(alpn, "http/1.1"));
        assertTrue(Tls13.alpnOffers(alpn, "h2"));
        assertFalse(Tls13.alpnOffers(alpn, "http/1.0"));
        assertFalse(Tls13.alpnOffers(null, "http/1.1"));
        // X25519 of the base point: RFC 7748 §6.1 Alice's public key from her private key
        byte[] scalar = HexFormat.of().parseHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", HexFormat.of().formatHex(Tls13.x25519PublicKey(scalar)));
    }
}
