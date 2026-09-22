package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.jailscale.hub.dns.DnsResponder;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A hub tells its own glue address from a peer's by asking each for {@code _jailhub-self} and
 * comparing the answer with its own token (ARCHITECTURE.md §13).
 */
@Timeout(30)
class AdvertiseTest {

    @Test
    void theGlueComesFromTheParentsReferralNotFromAResolver() throws Exception {
        try (java.net.DatagramSocket parent = io.jailscale.hub.dns.ReferralTest.fakeParent()) {
            Map<String, String> glue = Advertise.glue("hub.example.com", java.util.List.of("127.0.0.1"), parent.getLocalPort());
            assertEquals("203.0.113.1", glue.get("ns1"));
            assertEquals("203.0.113.2", glue.get("ns2"));
        }
        assertEquals(Map.of(), Advertise.glue("hub.example.com", java.util.List.of(), 53), "no parent server, no glue");
    }

    @Test
    void theAddressThatAnswersWithOurTokenIsOurs() throws Exception {
        try (DnsResponder me = new DnsResponder("hub.test", "mine")) {
            me.start("127.0.0.1", 0);
            Map<String, String> glue = new LinkedHashMap<>();
            glue.put("ns1", "127.0.0.1");
            assertEquals("127.0.0.1", Advertise.whoAmI(glue, "hub.test", me.port(), "mine"));
            assertNull(Advertise.whoAmI(glue, "hub.test", me.port(), "someone-elses"),
                "a server answering with another token is another hub");
            assertNull(Advertise.whoAmI(Map.of(), "hub.test", me.port(), "mine"), "no glue, no delegation, no address");
        }
    }
}
