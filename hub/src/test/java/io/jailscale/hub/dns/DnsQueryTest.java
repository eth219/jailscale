package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Answer parsing for the address check (ARCHITECTURE.md §7.2). The responses a public resolver
 * really sends are not one clean answer: a CNAME is followed by the address it leads to, and
 * anything that returns the wrong record type as if it were an address feeds a nonsense value into
 * a check whose whole job is to compare addresses.
 */
class DnsQueryTest {

    private static final int A = 1;
    private static final int CNAME = 5;
    private static final int TXT = 16;

    /** A response carrying the given answers, each {@code {type, rdata...}}. */
    private static byte[] response(int id, byte[]... answers) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(id >>> 8);
        b.write(id);
        b.write(0x81);      // QR + RD
        b.write(0x80);      // RA, rcode 0
        b.write(0);
        b.write(1);         // one question
        b.write(answers.length >>> 8);
        b.write(answers.length);
        for (int i = 0; i < 4; i++) {
            b.write(0);
        }
        b.writeBytes(DnsResponder.encodeName("hub.example.com"));
        b.write(0);
        b.write(A);
        b.write(0);
        b.write(1);
        for (byte[] a : answers) {
            b.write(0xc0);  // a pointer back to the question's name
            b.write(0x0c);
            b.write(0);
            b.write(a[0]);  // type
            b.write(0);
            b.write(1);     // IN
            for (int i = 0; i < 4; i++) {
                b.write(0); // ttl
            }
            b.write((a.length - 1) >>> 8);
            b.write(a.length - 1);
            b.write(a, 1, a.length - 1);
        }
        return b.toByteArray();
    }

    private static byte[] answer(int type, int... rdata) {
        byte[] out = new byte[rdata.length + 1];
        out[0] = (byte) type;
        for (int i = 0; i < rdata.length; i++) {
            out[i + 1] = (byte) rdata[i];
        }
        return out;
    }

    @Test
    void readsTheAddressesAndNothingElse() throws Exception {
        byte[] m = response(7, answer(A, 203, 0, 113, 10), answer(A, 203, 0, 113, 11));
        List<byte[]> rd = DnsQuery.parse(m, 7, A);
        assertEquals(2, rd.size());
        assertEquals("203.0.113.10", dotted(rd.get(0)));
        assertEquals("203.0.113.11", dotted(rd.get(1)));
    }

    @Test
    void aCnameInFrontOfTheAddressIsSkipped() throws Exception {
        // What a name pointed at a CDN or a load balancer actually answers. Returning the CNAME's
        // rdata as though it were an address would compare a hostname against an address forever.
        byte[] m = response(9, answer(CNAME, 3, 'w', 'w', 'w', 0), answer(A, 198, 51, 100, 7));
        List<byte[]> rd = DnsQuery.parse(m, 9, A);
        assertEquals(1, rd.size());
        assertEquals("198.51.100.7", dotted(rd.get(0)));
    }

    @Test
    void anAnswerOfAnotherTypeIsNotAnAddress() {
        byte[] m = response(11, answer(TXT, 2, 'h', 'i'));
        assertEquals(List.of(), assertDoesNotThrowIo(() -> DnsQuery.parse(m, 11, A)));
    }

    @Test
    void aReplyToSomeoneElsesQuestionIsRefused() {
        // The id is the only thing tying a UDP answer to our query.
        byte[] m = response(11, answer(A, 203, 0, 113, 10));
        assertThrows(IOException.class, () -> DnsQuery.parse(m, 12, A));
    }

    @Test
    void aTruncatedAnswerIsRefusedRatherThanRead() {
        byte[] m = response(13, answer(A, 203, 0, 113, 10));
        byte[] cut = java.util.Arrays.copyOf(m, m.length - 2);
        assertThrows(IOException.class, () -> DnsQuery.parse(cut, 13, A));
    }

    private static String dotted(byte[] rd) {
        return (rd[0] & 0xff) + "." + (rd[1] & 0xff) + "." + (rd[2] & 0xff) + "." + (rd[3] & 0xff);
    }

    private interface Call {
        List<byte[]> get() throws IOException;
    }

    private static List<byte[]> assertDoesNotThrowIo(Call c) {
        try {
            return c.get();
        } catch (IOException e) {
            throw new AssertionError("should not have thrown", e);
        }
    }
}
