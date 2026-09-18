package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
    void aNameOverTheLengthRfc1035AllowsIsRefusedAndOneAtItIsNot() throws Exception {
        // 255 octets is a name's whole wire form -- every label's length byte, its bytes, and the
        // root's zero -- and the parser used to bound a name by the datagram it arrived in and by
        // nothing else. Both sides of the boundary, because a bound asserted only from above passes
        // just as well when it refuses every name there is.
        DnsResponder d = new DnsResponder("hub.example.com");
        d.setZone(twoHosts(List.of("203.0.113.9")));

        // `hub.example.com` is 16 octets and the root's zero is one, so 238 of them may be a prefix.
        byte[] longest = rawQuery(8, 1, labelsFilling(238, "hub", "example", "com"));
        assertEquals(DnsResponder.MAX_NAME, wireNameLength(longest), "the longest name RFC 1035 allows");
        byte[] answer = d.respond(longest);
        assertEquals(0, rcode(answer), "which is a question this zone answers like any other");
        assertEquals(List.of("203.0.113.9"), addresses(DnsQuery.parse(answer, 8, 1)));
        // And in a datagram, which is the property the bound exists for: the longest question there
        // is fits the 512 a resolver with no EDNS may be sent, so the TC form never has to drop it
        // -- a truncation with no question in it is one a resolver discards as unsolicited.
        byte[] datagram = d.respond(longest, DnsResponder.Budget.DATAGRAM);
        assertTrue(datagram.length <= DnsResponder.MAX_UDP, "the longest name and its answer in one datagram, was " + datagram.length);
        assertEquals(0, datagram[2] & 0x02, "with room to spare, so not even truncated");
        assertEquals(1, datagram[5], "and the question echoed");

        byte[] tooLong = rawQuery(9, 1, labelsFilling(239, "hub", "example", "com"));
        assertEquals(DnsResponder.MAX_NAME + 1, wireNameLength(tooLong), "one octet past it");
        byte[] refused = d.respond(tooLong);
        assertEquals(1, rcode(refused), "FORMERR");
        assertEquals(12, refused.length, "in twelve bytes");
        assertEquals(0, refused[5], "which echo no question");
        assertEquals(0, refused[2] & 0x02, "and are a refusal, not a truncation to come back for");
    }

    /**
     * Labels that fill exactly {@code octets} of wire, each label's own length byte included,
     * followed by {@code apex}. Longest first, so the fill is the fewest labels that can make it.
     *
     * <p>Not every amount can be filled: a label costs its length byte, so one octet left over is
     * one no label can spend, and an empty label is a zero byte -- which {@code rawQuery} writes as
     * the end of the name, quietly building a shorter question than the caller asked for. It throws
     * rather than do that.
     */
    private static String[] labelsFilling(int octets, String... apex) {
        List<String> labels = new java.util.ArrayList<>();
        for (int left = octets; left > 0; ) {
            int label = Math.min(63, left - 1);     // the label's own length byte is the other one
            if (label < 1) {
                throw new IllegalArgumentException(octets + " octets is not a whole number of labels");
            }
            labels.add("a".repeat(label));
            left -= label + 1;
        }
        labels.addAll(List.of(apex));
        return labels.toArray(new String[0]);
    }

    /**
     * What the question's name measures on the wire: the query, less its header and its type and
     * class. A query {@code rawQuery} wrote, therefore -- one question, and nothing behind it.
     */
    private static int wireNameLength(byte[] query) {
        return query.length - 12 - 4;
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

            // DnsQuery follows the TC to TCP, so asking it is the assertion: an answer too large
            // for a datagram comes back whole, which it can only do from the other socket of the
            // pair, on the number UDP was bound to.
            List<String> got = DnsQuery.txt("127.0.0.1", d.port(), "_acme-challenge.hub.example.com", 2000);
            assertEquals(2, got.size(), "both records, which needed the TCP half: " + got);
            assertTrue(got.contains("a".repeat(300)) && got.contains("b".repeat(300)), got.toString());

            // And byte for byte what the responder would build.
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

    /**
     * How wide a band of held UDP ports the test below builds, in ports: the attempt budget, plus
     * room for the allocator to have moved between the two draws.
     *
     * <p>Derived from {@link DnsResponder#PAIR_TRIES} rather than written as a number, because a
     * band only as wide as the budget is one a stepping loop walks straight out of the top of --
     * and the premises below could then not be met at all. That is #230: the band was 32 against a
     * budget of 16 and the draw was allowed anywhere in it, so from the upper half a stepping loop
     * reached past the top and the test passed against the defect it is here to catch.
     *
     * <p>What makes the test sound is the premise loop and not this width: every number the loop
     * would try has to be one this test holds. What the margin buys is how often that premise can
     * be met -- it tolerates the second draw landing up to fifteen numbers above the first, and an
     * allocator that leaves more than that between two draws skips this test rather than failing
     * it. {@code DnsQueryFallbackTest} is the worked example, from #220.
     */
    private static final int BAND = DnsResponder.PAIR_TRIES + 16;

    @Test
    void aBandOfHeldUdpPortsIsEscapedRatherThanSteppedThrough() throws Exception {
        // #181. The retry used to step: TCP drew, UDP asked for the twin, and a failure simply
        // redrew the next number up. Against a *band* of held UDP ports that is not eight chances,
        // it is one chance taken eight times a port apart, and on windows-2025 it ran out -- eight
        // adjacent TCP numbers, every one of their UDP twins taken. So this is built as a band and
        // not as a coin flip, which is what the issue asks any fix to be measured against.
        List<DatagramSocket> band = new ArrayList<>();
        Set<Integer> bandPorts = new HashSet<>();
        try {
            // Where the TCP allocator is about to go. Drawn and given straight back, so that the
            // next draw lands on it or just past it wherever the allocator is sequential.
            int from = drawTcpPort();
            // The window has to be made of port numbers. An allocator this near the top of the
            // range is about to wrap, and `from + BAND` is then not a port at all -- which
            // InetSocketAddress reports as IllegalArgumentException, not as the IOException the
            // loop below catches, so this would be an error rather than a skip.
            // 65_536 and not 65_535: the band's topmost port is from + BAND - 1, which is the
            // bound the loop below uses. The tighter number threw away a run that would have been
            // fine.
            assumeTrue(from + BAND <= 65_536,
                "the allocator drew " + from + ", within " + BAND + " of the top of the range");
            for (int p = from; p < from + BAND; p++) {
                DatagramSocket s = new DatagramSocket(null);
                try {
                    s.bind(new InetSocketAddress("127.0.0.1", p));
                    band.add(s);
                    bandPorts.add(p);
                } catch (IOException taken) {
                    // Somebody else holds this one. It is unavailable now, but it is not this
                    // test's to keep unavailable, and a number that comes free part-way through is
                    // one the old stepping loop could have landed on. That only matters inside the
                    // window the premises below check, so a hole above it is harmless rather than
                    // a skip.
                    s.close();
                }
            }
            // Where the allocator is now, and therefore where a stepping loop would start. This is
            // deliberately the last draw before start(): what follows binds nothing, so start()'s
            // own first attempt is one step from here.
            int next = drawTcpPort();

            // Three premises, checked and not assumed. Without them there is nothing to escape and
            // this test would pass against the old stepping loop -- which it did, when the band was
            // only as wide as the budget and `next` could be anywhere in it: a draw at from + 20
            // let a loop stepping sixteen numbers up reach from + 36, and from + 32 upwards was
            // never held. That is #230, and it was half the allowed window.
            //
            // The first two are implied by the loop after them -- bandPorts holds nothing outside
            // the band -- and they are kept because the skip message is the whole value of a skip:
            // "the allocator does not step" and "not enough band above it" are two different
            // machines, and neither is "the band has a hole".
            assumeTrue(next >= from,
                "the allocator drew " + next + " after " + from + ", so it does not step and there is no band");
            assumeTrue(next + DnsResponder.PAIR_TRIES < from + BAND,
                "the allocator drew " + next + " after " + from + ", leaving fewer than "
                    + DnsResponder.PAIR_TRIES + " of the band above it, so a stepping loop could walk out of the top");
            for (int p = next; p <= next + DnsResponder.PAIR_TRIES; p++) {
                final int held = p;
                assumeTrue(bandPorts.contains(p),
                    () -> "the band has a hole at " + held + ", inside the " + DnsResponder.PAIR_TRIES
                        + " numbers a stepping loop would try, so it could succeed on the hole");
            }

            try (DnsResponder d = new DnsResponder("hub.example.com")) {
                // Stepping from `next`, every number the old loop would try is one this test holds
                // and it threw here. Alternating gives UDP the draw on attempt 1, and a UDP
                // allocator will not hand out a number it has already given to the band.
                d.start("127.0.0.1", 0);
                // One assertion and not two: the premise loop above put every number in
                // [next, next + PAIR_TRIES] into bandPorts, so "not a number this test holds"
                // already says "not one a stepping loop would have reached".
                assertFalse(bandPorts.contains(d.port()),
                    "started on " + d.port() + ", which this test is holding, so it did not escape the band");
                // And it is a working responder on that number, not merely a pair of bound sockets.
                assertEquals(List.of(), DnsQuery.txt("127.0.0.1", d.port(), "_acme-challenge.hub.example.com", 2000));
            }
        } finally {
            for (DatagramSocket s : band) {
                s.close();
            }
        }
    }

    /** A TCP port from the ephemeral range, given back before it is returned. */
    private static int drawTcpPort() throws IOException {
        try (ServerSocket probe = new ServerSocket()) {
            probe.setReuseAddress(true);
            probe.bind(new InetSocketAddress("127.0.0.1", 0), 16);
            return probe.getLocalPort();
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
