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
    void everyShapeCopiesTheRecursionBit() {
        // RFC 1035 §4.1.1: RD is copied into the response. The answer and the truncated forms
        // always did; the error one did not, which stayed invisible while each wrote its own header.
        DnsResponder d = new DnsResponder("hub.test");
        for (String name : List.of("some.other.example.com", "myapp.hub.test")) {
            byte[] asked = DnsFuzzTest.query(name, 1);                 // query() sets RD
            assertEquals(1, d.respond(asked)[2] & 0x01, name + " should carry the RD it was asked with");
            assertEquals(1, d.respond(asked, DnsResponder.Budget.NO_RECORDS)[2] & 0x01, name + " truncated");
            byte[] plain = asked.clone();
            plain[2] &= ~0x01;
            assertEquals(0, d.respond(plain)[2] & 0x01, name + " should not carry one it was not asked with");
        }
    }

    @Test
    void aNameOutsideTheZoneIsRefusedRatherThanTruncated() {
        // The slip skips building records, and it has to do that after the zone check and not
        // before: REFUSED is twelve bytes and echoes no question, which reflects less than the TC
        // form, and it is a refusal rather than an instruction to come back over TCP.
        DnsResponder d = new DnsResponder("hub.test");
        byte[] r = d.respond(DnsFuzzTest.query("some.other.example.com", 1), DnsResponder.Budget.NO_RECORDS);
        assertEquals(12, r.length, "a refusal is a bare header whatever the budget");
        assertEquals(0, r[2] & 0x02, "and is not a truncation");
        assertEquals(5, r[3] & 0x0f, "REFUSED");
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
