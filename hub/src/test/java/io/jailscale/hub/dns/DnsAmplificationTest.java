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
                    if (r.length > biggest) {
                        biggest = r.length;
                        biggestAt = name + " type " + type;
                    }
                }
            }
        }
        assertTrue(worst <= MAX_RATIO, "worst answer-to-query ratio " + worst + " at " + worstAt);
        // The absolute size matters on its own: it is what a datagram may carry without EDNS, and
        // an answer past it is one a resolver discards rather than reads (see DnsResponder.MAX_UDP).
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
