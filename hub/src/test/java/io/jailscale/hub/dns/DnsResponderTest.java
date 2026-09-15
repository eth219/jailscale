package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DnsResponderTest {

    /** A zone with two hosts serving and both delegated. */
    private static DnsResponder.Zone twoHosts(List<String> serving) {
        return new DnsResponder.Zone() {
            @Override public List<String> serving() { return serving; }
            @Override public Map<String, String> nameServers() { return Map.of("ns1", "203.0.113.1", "ns2", "203.0.113.2"); }
        };
    }

    @Test
    void answersTxtForTheChallengeNameAsItAlwaysHas() throws Exception {
        try (DnsResponder d = new DnsResponder("Hub.Example.com")) {
            d.start("127.0.0.1", 0);
            assertEquals(List.of(), DnsQuery.txt("127.0.0.1", d.port(), "_acme-challenge.hub.example.com", 2000));
            d.setTxt(List.of("abc", "x".repeat(300)));
            List<String> got = DnsQuery.txt("127.0.0.1", d.port(), "_ACME-CHALLENGE.hub.example.com", 2000);
            assertEquals(2, got.size());
            assertTrue(got.contains("abc"));
            assertTrue(got.contains("x".repeat(300)));
            assertEquals(List.of("hub.example.com"), DnsQuery.ns("127.0.0.1", d.port(), "_acme-challenge.hub.example.com", 2000),
                "the single-host delegation names the hub itself");
            IOException e = assertThrows(IOException.class, () -> DnsQuery.txt("127.0.0.1", d.port(), "other.example.com", 2000));
            assertTrue(e.getMessage().contains("rcode 5"), e.getMessage());
        }
    }

    @Test
    void theApexAndEveryNameUnderItResolveToTheHostsServing() throws Exception {
        try (DnsResponder d = new DnsResponder("hub.example.com")) {
            d.start("127.0.0.1", 0);
            // Before anything is known, the zone has no addresses: NODATA, not an error and not a lie.
            assertEquals(List.of(), DnsQuery.a("127.0.0.1", d.port(), "hub.example.com", 2000));
            d.setZone(twoHosts(List.of("203.0.113.1", "203.0.113.2")));
            assertEquals(List.of("203.0.113.1", "203.0.113.2"), DnsQuery.a("127.0.0.1", d.port(), "hub.example.com", 2000));
            assertEquals(List.of("203.0.113.1", "203.0.113.2"), DnsQuery.a("127.0.0.1", d.port(), "MyApp.hub.example.com", 2000));
            assertEquals(List.of("203.0.113.1", "203.0.113.2"), DnsQuery.a("127.0.0.1", d.port(), "deep.er.hub.example.com", 2000),
                "the wildcard covers any depth");
            // The serving set is read on every query, so a host that goes is gone from the next answer.
            d.setZone(twoHosts(List.of("203.0.113.2")));
            assertEquals(List.of("203.0.113.2"), DnsQuery.a("127.0.0.1", d.port(), "myapp.hub.example.com", 2000));
            // No IPv6 is advertised: NODATA, so a resolver asking AAAA first moves on to A.
            assertEquals(List.of(), DnsQuery.aaaa("127.0.0.1", d.port(), "myapp.hub.example.com", 2000));
            assertEquals(List.of(), DnsQuery.aaaa("127.0.0.1", d.port(), "hub.example.com", 2000));
        }
    }

    @Test
    void theNameServersAndTheirGlueAreWhatTheParentDelegatedTo() throws Exception {
        try (DnsResponder d = new DnsResponder("hub.example.com")) {
            d.start("127.0.0.1", 0);
            d.setZone(twoHosts(List.of("203.0.113.1")));
            assertEquals(List.of("ns1.hub.example.com", "ns2.hub.example.com"), DnsQuery.ns("127.0.0.1", d.port(), "hub.example.com", 2000));
            assertEquals(List.of("203.0.113.1"), DnsQuery.a("127.0.0.1", d.port(), "ns1.hub.example.com", 2000));
            assertEquals(List.of("203.0.113.2"), DnsQuery.a("127.0.0.1", d.port(), "NS2.hub.example.com", 2000));
            // A glue name is not a published name: it does not fall through to the wildcard for other types.
            assertEquals(List.of(), DnsQuery.txt("127.0.0.1", d.port(), "ns2.hub.example.com", 2000));
        }
        try (DnsResponder d = new DnsResponder("hub.example.com")) {
            d.start("127.0.0.1", 0);
            d.setZone(new DnsResponder.Zone() {
                @Override public List<String> serving() { return List.of("203.0.113.1"); }
                @Override public Map<String, String> nameServers() { return Map.of(); }
            });
            // Before the glue is known, a glue name answers nothing rather than the wildcard: the
            // live primary answered ns2 with itself once, a resolver cached that, and the lookup
            // that was meant to find the glue read it back.
            assertEquals(List.of(), DnsQuery.a("127.0.0.1", d.port(), "ns2.hub.example.com", 2000));
            assertEquals(List.of("203.0.113.1"), DnsQuery.a("127.0.0.1", d.port(), "ns3.hub.example.com", 2000), "only the delegable labels are held back");
        }
        try (DnsResponder d = new DnsResponder("hub.example.com")) {
            d.start("127.0.0.1", 0);
            // Not delegated (three records at the parent): the zone still names itself, as it did.
            assertEquals(List.of("hub.example.com"), DnsQuery.ns("127.0.0.1", d.port(), "hub.example.com", 2000));
        }
    }

    @Test
    void onlyThisProcessKnowsItsOwnToken() throws Exception {
        try (DnsResponder a = new DnsResponder("hub.example.com", "token-a"); DnsResponder b = new DnsResponder("hub.example.com", "token-b")) {
            a.start("127.0.0.1", 0);
            b.start("127.0.0.1", 0);
            assertEquals(List.of("token-a"), DnsQuery.txt("127.0.0.1", a.port(), "_jailhub-self.hub.example.com", 2000));
            assertEquals(List.of("token-b"), DnsQuery.txt("127.0.0.1", b.port(), "_jailhub-self.hub.example.com", 2000));
            assertEquals(List.of(), DnsQuery.a("127.0.0.1", a.port(), "_jailhub-self.hub.example.com", 2000),
                "the token name has no address, not even the wildcard's");
        }
    }

    @Test
    void theStandbyIsToldWhenTheChallengeValuesChange() {
        DnsResponder d = new DnsResponder("hub.example.com");
        List<List<String>> seen = new java.util.ArrayList<>();
        d.onTxtChanged(seen::add);
        d.setTxt(List.of("one", "two"));
        d.clearTxt();
        assertEquals(List.of(List.of("one", "two"), List.of()), seen);
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
