package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
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

    /**
     * A question whose labels are given as bytes, so that a label may hold a dot or a byte over
     * 0x7F -- neither of which {@code DnsFuzzTest.query} can write, splitting a String on '.'.
     */
    private static byte[] rawQuery(int id, int type, String... labels) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(id >>> 8);
        o.write(id);
        o.write(0x01);
        o.write(0x00);
        o.write(0);
        o.write(1);
        for (int i = 0; i < 6; i++) {
            o.write(0);
        }
        for (String label : labels) {
            byte[] b = label.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            o.write(b.length);
            o.writeBytes(b);
        }
        o.write(0);
        o.write(type >>> 8);
        o.write(type);
        o.write(0);
        o.write(1); // IN
        return o.toByteArray();
    }

    private static int rcode(byte[] response) {
        return response[3] & 0x0f;
    }

    @Test
    void twoWireNamesThatPrintAsOneStringAreNotOneName() throws Exception {
        DnsResponder d = new DnsResponder("hub.example.com");
        d.setTxt(List.of("challenge-value"));
        d.setZone(new DnsResponder.Zone() {
            @Override public List<String> serving() { return List.of("203.0.113.9"); }
            @Override public Map<String, String> nameServers() { return Map.of("ns1", "203.0.113.1"); }
        });
        // The names as the zone holds them, so that refusing everything cannot pass this.
        byte[] glue = d.respond(rawQuery(1, 1, "ns1", "hub", "example", "com"));
        assertEquals(0, rcode(glue));
        assertEquals(List.of("203.0.113.1"), addresses(DnsQuery.parse(glue, 1, 1)));
        assertEquals(List.of("challenge-value"),
            txt(DnsQuery.parse(d.respond(rawQuery(2, 16, "_acme-challenge", "hub", "example", "com")), 2, 16)));

        // One label whose 19 bytes are `ns1.hub.example.com`: legal on the wire, under the 63-byte
        // cap the parser enforces, and a different name from the four-label form. Joining the
        // labels with a dot made the two one string, and this was answered with ns1's glue.
        assertEquals(5, rcode(d.respond(rawQuery(3, 1, "ns1.hub.example.com"))),
            "a single label that prints as ns1.<hub> is not a name in this zone");
        // The same collapse the other way round: a dot inside the last label.
        assertEquals(5, rcode(d.respond(rawQuery(4, 16, "_acme-challenge.hub", "example.com"))),
            "a two-label name that prints as the challenge name is not the challenge name");
    }

    @Test
    void aLabelOutsideAsciiIsStillItsOwnName() {
        List<String> asked = new java.util.ArrayList<>();
        DnsResponder d = new DnsResponder("hub.example.com");
        d.setZone(new DnsResponder.Zone() {
            @Override public List<String> serving() { return List.of("203.0.113.9"); }
            @Override public Map<String, String> nameServers() { return Map.of(); }
            @Override public List<String> forName(String label) {
                asked.add(label);
                return serving();
            }
        });
        // US-ASCII decoding turns every byte over 0x7F into the one replacement character, which
        // made all 128 of them the same published name.
        assertEquals(0, rcode(d.respond(rawQuery(5, 1, "\u0080", "hub", "example", "com"))));
        assertEquals(0, rcode(d.respond(rawQuery(6, 1, "\u0081", "hub", "example", "com"))));
        assertEquals(0, rcode(d.respond(rawQuery(7, 1, "MyApp", "hub", "example", "com"))));
        assertEquals(List.of("\u0080", "\u0081", "myapp"), asked, "one label of bytes, one name, folded as ASCII");
    }

    private static List<String> addresses(List<byte[]> rdata) throws IOException {
        List<String> out = new java.util.ArrayList<>();
        for (byte[] rd : rdata) {
            out.add(java.net.InetAddress.getByAddress(rd).getHostAddress());
        }
        return out;
    }

    private static List<String> txt(List<byte[]> rdata) {
        List<String> out = new java.util.ArrayList<>();
        for (byte[] rd : rdata) {
            out.add(new String(rd, 1, rd[0] & 0xff, java.nio.charset.StandardCharsets.US_ASCII));
        }
        return out;
    }

    @Test
    void ignoresGarbageAndResponses() {
        DnsResponder d = new DnsResponder("hub.test");
        assertEquals(null, d.respond(new byte[5]));
        byte[] resp = new byte[12];
        resp[2] = (byte) 0x80;
        assertEquals(null, d.respond(resp));
    }

    @Test
    void theTcpListenerIsOnTheNumberThePairWasBoundTo() throws Exception {
        // start() binds two sockets to one number, and until now only one of them was ever asked
        // a question: DnsQuery is UDP-only and nothing else connected. So the half of the pair
        // that a resolver reaches after TC -- which is the whole reason TC is worth sending --
        // could have been bound to any number at all, and every test would still have been green.
        try (DnsResponder d = new DnsResponder("hub.example.com")) {
            d.start("127.0.0.1", 0);
            d.setTxt(List.of("a".repeat(300), "b".repeat(300)));
            byte[] q = DnsFuzzTest.query("_acme-challenge.hub.example.com", 16);
            assertTrue(d.respond(q).length > DnsResponder.MAX_UDP, "the fixture has to overflow a datagram");

            IOException tc = assertThrows(IOException.class,
                () -> DnsQuery.txt("127.0.0.1", d.port(), "_acme-challenge.hub.example.com", 2000));
            assertTrue(tc.getMessage().contains("TC"), "the datagram should say come back over TCP, said " + tc.getMessage());

            // And on that same number, over TCP, the whole answer is there.
            assertArrayEquals(d.respond(q), overTcp("127.0.0.1", d.port(), q));
        }
    }

    @Test
    void aNumberUdpCannotHaveLeavesNoListenerBehind() throws Exception {
        try (DatagramSocket blocker = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0))) {
            int p = blocker.getLocalPort();
            // The premise, asserted rather than assumed: a DatagramSocket that did not ask for
            // reuse is exclusive on all three platforms -- SO_EXCLUSIVEADDRUSE is what the JDK
            // sets on Windows for exactly this. If that stops being true, this line says so
            // instead of the one below failing as though start() were at fault.
            DatagramSocket other = new DatagramSocket(null);
            other.setReuseAddress(true);
            assertThrows(IOException.class, () -> other.bind(new InetSocketAddress("127.0.0.1", p)),
                "the blocker is not a blocker on this platform, so nothing below is measured");
            other.close();

            try (DnsResponder d = new DnsResponder("hub.example.com")) {
                assertThrows(IOException.class, () -> d.start("127.0.0.1", p), "the pair cannot be had on " + p);
            }
            // TCP draws the number now, so the bind that fails is the second one and the listener
            // the first one opened has to be given back. A hub that failed to start and is still
            // listening on the number is worse than one that simply did not start.
            try (ServerSocket s = new ServerSocket()) {
                s.bind(new InetSocketAddress("127.0.0.1", p), 16);
            }
        }
    }

    /** The same question over TCP, where a resolver goes when a datagram says TC: length-prefixed. */
    private static byte[] overTcp(String host, int port, byte[] query) throws IOException {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), 2000);
            s.setSoTimeout(2000);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            out.writeShort(query.length);
            out.write(query);
            out.flush();
            DataInputStream in = new DataInputStream(s.getInputStream());
            byte[] answer = new byte[in.readUnsignedShort()];
            in.readFully(answer);
            return answer;
        }
    }
}
