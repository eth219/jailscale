package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * How much bigger than a query an answer can be (ARCHITECTURE.md §11.5, §13.3).
 *
 * <p>The design said the answers here were too small to amplify with. That was true and it was an
 * assertion: nothing measured it, and nothing would have noticed a record type or a longer value
 * making it false. A reflector's whole worth is this ratio, so it is a number, and this is where it
 * is kept.
 *
 * <p>The zone is set to the largest this design allows — two hosts serving, both name servers
 * delegated, and an issuance in flight so both challenge values are present, which is the only time
 * the TXT set is non-empty ({@code AcmeManager.issue} orders exactly {@code hub} and {@code *.hub}).
 *
 * <p><b>And the hub name is swept, because the ratio moves with it and the short name is the bad
 * one.</b> A longer name lengthens the query in full and the answer hardly at all, since every
 * mention of it inside the answer is a compression pointer to the question — so the ratio falls as
 * the name grows: 5.31 at {@code jailscale.sinabro.io}, 5.69 at {@code hub.test}, 5.87 at
 * {@code x.io}, 5.92 at {@code a.b}. This used to measure the live name alone and call it the worst
 * case, with the reasoning written down backwards; measuring only there is measuring the most
 * flattering hub anyone could deploy, and a later change could lift that below the bound while a
 * hub on a short domain sat above it. The absolute size goes the other way -- the longest name
 * holds the largest answer -- so both ends are kept.
 */
class DnsAmplificationTest {

    /**
     * Measured 5.31 at {@code _acme-challenge} ANY with both challenge values present. The gate is
     * above that and far below where a reflector becomes worth using — the attacks this class of
     * server has been used for ran at 50 to 70, on EDNS answers this one cannot produce. A change
     * that pushes past 8 has added something that does not belong in a datagram; the answer is
     * probably to stop answering it on UDP, not to raise this.
     */
    private static final double MAX_RATIO = 8;

    /** The live hub, and the shortest name anybody could register: the ratio's two ends. */
    private static final List<String> HUBS = List.of("jailscale.sinabro.io", "a.b");
    private static final String HUB = "jailscale.sinabro.io";

    @Test
    void noAnswerIsWorthReflecting() {
        double worst = 0;
        String worstAt = "";
        int biggest = 0;
        String biggestAt = "";
        int biggestDatagram = 0;
        String biggestDatagramAt = "";
        for (String hub : HUBS) {
            DnsResponder d = fullest(hub);
            for (String name : names(hub)) {
                for (int type : new int[] {1, 2, 6, 16, 28, 255, 99}) {
                    byte[] q = DnsFuzzTest.query(name, type);
                    byte[] r = d.respond(q);
                    if (r == null) {
                        continue;
                    }
                    double ratio = (double) r.length / q.length;
                    if (ratio > worst) {
                        worst = ratio;
                        worstAt = name + " type " + type;
                    }
                    // The whole answer, which is TCP's, and what a datagram would carry of it. The
                    // ratio is taken on the larger of the two, so the bound stays the conservative
                    // one; the sizes are kept apart because only one of them is bounded by 512.
                    if (r.length > biggest) {
                        biggest = r.length;
                        biggestAt = name + " type " + type;
                    }
                    byte[] datagram = d.respond(q, DnsResponder.Budget.DATAGRAM);
                    if (datagram.length > biggestDatagram) {
                        biggestDatagram = datagram.length;
                        biggestDatagramAt = name + " type " + type;
                    }
                }
            }
        }
        assertTrue(worst <= MAX_RATIO, "worst answer-to-query ratio " + worst + " at " + worstAt);
        // What leaves on :53 is bounded by the encoder, so this half cannot fail without a defect:
        // it is here because that bound is the thing this file exists to keep honest.
        assertTrue(biggestDatagram <= DnsResponder.MAX_UDP,
            "largest datagram " + biggestDatagram + " bytes at " + biggestDatagramAt);
        // The whole answer is a statement about the zone and not about the transport -- TCP would
        // carry more. An answer this zone can build that does not fit a datagram is not broken, it
        // is two round trips for every resolver that asks, which is a design change and not an
        // accident; §15 says the zone is what grows, so this is where that shows up.
        assertTrue(biggest <= DnsResponder.MAX_UDP, "largest answer " + biggest + " bytes at " + biggestAt);
    }

    @Test
    void aNameOutsideTheZoneCostsTheAskerMoreThanTheHub() {
        // REFUSED is a bare header, so the one query anybody can send for any name at all is the
        // one that reflects nothing. Worth pinning: it is the cheapest thing to get wrong by
        // starting to echo the question back.
        DnsResponder d = fullest();
        byte[] q = DnsFuzzTest.query("some.other.example.com", 255);
        byte[] r = d.respond(q);
        assertEquals(12, r.length, "REFUSED should be a header and nothing else");
        assertTrue(r.length < q.length, "a refusal should be smaller than the question");
    }

    @Test
    void anAnswerTooLargeForADatagramIsTruncatedOnUdpAndWholeOnTcp() throws Exception {
        // Nothing this zone holds reaches 512 today -- two hosts is the most §13 allows -- so the
        // bound is driven with a zone of forty addresses. That is the case it exists for: the zone
        // is what grows, and an oversized datagram is not an error a resolver reports, it is one it
        // discards, which under `_acme-challenge` is a certificate that stops renewing and says so
        // nowhere. A test that only asserted today's sizes would let the bound be deleted.
        List<String> many = new java.util.ArrayList<>();
        for (int i = 1; i <= 40; i++) {
            many.add("203.0.113." + i);
        }
        DnsResponder d = new DnsResponder(HUB);
        d.setZone(new DnsResponder.Zone() {
            @Override public List<String> serving() {
                return many;
            }

            @Override public Map<String, String> nameServers() {
                return Map.of();
            }
        });
        byte[] q = DnsFuzzTest.query("myapp." + HUB, 1);

        byte[] whole = d.respond(q);
        assertTrue(whole.length > DnsResponder.MAX_UDP,
            "the zone should be large enough to overflow a datagram, was " + whole.length);

        byte[] datagram = d.answerForUdp(q, java.net.InetAddress.getByName("198.51.100.7"), 1_000_000);
        assertTrue(datagram.length <= DnsResponder.MAX_UDP, "UDP answer was " + datagram.length + " bytes");
        assertTrue((datagram[2] & 0x02) != 0, "TC should be set so the resolver asks again over TCP");
        // And the shape of it, which is what a resolver has to be able to match to its query: the
        // header and the question, counting no records at all.
        assertEquals(q.length, datagram.length, "the header and the question, and nothing after it");
        assertEquals(1, datagram[5], "the question is still echoed");
        for (int i = 6; i < 12; i++) {
            assertEquals(0, datagram[i], "no records should be counted at byte " + i);
        }
        // TCP is unchanged: it has a length prefix, so the whole answer goes.
        assertTrue(d.respond(q).length > DnsResponder.MAX_UDP, "TCP should still carry the whole answer");
    }

    @Test
    void aQuestionLongerThanANameMayBeIsRefusedBeforeAnyAnswer() throws Exception {
        // The TC answer echoes the question, and nothing used to check that the echo fit either. A
        // name was bounded by the packet and not by the 255 octets RFC 1035 allows one, so this
        // query -- 60 labels under the hub name, 998 bytes, which arrives in one datagram -- was
        // answered by cutting to the question's end, which is a 998-byte datagram: over the 512
        // that §11.5 states, broken by the one path that existed to keep it. Not amplification, an
        // answer no larger than the query that asked for it, but an oversized datagram is discarded
        // by a resolver rather than reported, which is the failure the bound is there to prevent.
        //
        // The fix for that left the header alone, TC set and the question dropped, which a resolver
        // matching a reply by its question section discards as unsolicited. So the name is bounded
        // where it is read now: twelve bytes of FORMERR, and no encoder sees the question at all.
        DnsResponder d = fullest();
        byte[] q = DnsFuzzTest.query(DnsFuzzTest.LONG_LABELS + HUB, 1);
        assertTrue(q.length > DnsResponder.MAX_UDP, "the question itself has to be what does not fit, was " + q.length);

        byte[] r = d.answerForUdp(q, java.net.InetAddress.getByName("198.51.100.7"), 1_000_000);
        assertEquals(12, r.length, "a name over the bound is refused in twelve bytes, was " + r.length);
        assertEquals(1, r[3] & 0x0f, "FORMERR");
        assertEquals(0, r[2] & 0x02, "a refusal, not a truncation for a resolver to come back for");
        for (int i = 4; i < 12; i++) {
            assertEquals(0, r[i], "nothing should be counted at byte " + i);
        }
    }

    @Test
    void aBudgetSmallerThanADatagramBoundsTheEchoToo() {
        // No caller passes one today -- both budgets that reach the encoder are a datagram's -- so
        // this is the parameter's own promise rather than a live path. It is worth pinning because
        // the next budget is where an echo measured against the constant instead of against what
        // was asked for would put an oversized answer back on the wire, which is the failure the
        // commit above closed.
        DnsResponder d = fullest();
        byte[] q = DnsFuzzTest.query("myapp." + HUB, 1);
        int whole = d.respond(q).length;
        assertTrue(whole > q.length, "the whole answer has to be the thing that does not fit");

        // `size > budget`, at the byte where it turns over. Without this the comparison could be
        // `>=` -- an answer of exactly the budget needlessly truncated -- and every other case
        // here is far enough from the boundary not to notice.
        assertEquals(whole, d.respond(q, budget(whole)).length, "room for the answer exactly, and it is kept");
        assertEquals(q.length, d.respond(q, budget(whole - 1)).length, "one byte less and it is the question alone");

        // And the echo's own boundary, below which not even the question fits.
        assertEquals(q.length, d.respond(q, budget(q.length)).length, "room for the echo exactly, and it is kept");
        assertEquals(12, d.respond(q, budget(q.length - 1)).length, "one byte less and the header goes alone");
    }

    private static DnsResponder.Budget budget(int bytes) {
        return new DnsResponder.Budget(bytes, true);
    }

    /** The zone at its largest: two hosts, both name servers, an issuance in flight. */
    private static DnsResponder fullest() {
        return fullest(HUB);
    }

    private static DnsResponder fullest(String hub) {
        DnsResponder d = new DnsResponder(hub);
        d.setTxt(List.of("HRpBmSGlhQU7ZP6QzkPXVaTHi0Nw4N4iCNMLrGgGTMY", "oCyDnBOLHQiVBnHJc1xPzLHQjQvKLKBOr3ZSW3E6xBo"));
        d.setZone(new DnsResponder.Zone() {
            @Override public List<String> serving() {
                return List.of("203.0.113.1", "203.0.113.2");
            }

            @Override public Map<String, String> nameServers() {
                return Map.of("ns1", "203.0.113.1", "ns2", "203.0.113.2");
            }
        });
        return d;
    }

    private static List<String> names(String hub) {
        return List.of(
            "_acme-challenge." + hub, hub, "myapp." + hub, "a.b.c." + hub,
            "ns1." + hub, "ns2." + hub, DnsResponder.SELF_LABEL + "." + hub, "other.example.com");
    }

}
