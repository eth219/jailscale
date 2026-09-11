package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;

class DnsResponderTest {

    @Test
    void answersTxtForTheChallengeNameOnly() throws Exception {
        try (DnsResponder d = new DnsResponder("Hub.Example.com")) {
            d.start("127.0.0.1", 0);
            assertEquals(List.of(), DnsQuery.txt("127.0.0.1", d.port(), "_acme-challenge.hub.example.com", 2000));
            d.setTxt(List.of("abc", "x".repeat(300)));
            List<String> got = DnsQuery.txt("127.0.0.1", d.port(), "_ACME-CHALLENGE.hub.example.com", 2000);
            assertEquals(2, got.size());
            assertTrue(got.contains("abc"));
            assertTrue(got.contains("x".repeat(300)));
            IOException e = assertThrows(IOException.class, () -> DnsQuery.txt("127.0.0.1", d.port(), "other.example.com", 2000));
            assertTrue(e.getMessage().contains("rcode 5"), e.getMessage());
        }
    }

    @Test
    void ignoresGarbageAndResponses() {
        DnsResponder d = new DnsResponder("hub.test");
        assertEquals(null, d.respond(new byte[5]));
        byte[] resp = new byte[12];
        resp[2] = (byte) 0x80;
        assertEquals(null, d.respond(resp));
    }
}
