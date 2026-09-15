package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
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
 * The hub name is the live one rather than {@code hub.test}, because a short name makes a short
 * query and a short query flatters the ratio.
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

    private static final String HUB = "jailscale.sinabro.io";

    @Test
    void noAnswerIsWorthReflecting() {
        DnsResponder d = fullest();
        double worst = 0;
        String worstAt = "";
        int biggest = 0;
        String biggestAt = "";
        for (String name : names()) {
            for (int type : new int[] {1, 2, 6, 16, 28, 255, 99}) {
                byte[] q = query(name, type);
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
        byte[] q = query("some.other.example.com", 255);
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
        byte[] q = query("myapp." + HUB, 1);

        byte[] whole = d.respond(q);
        assertTrue(whole.length > DnsResponder.MAX_UDP,
            "the zone should be large enough to overflow a datagram, was " + whole.length);

        byte[] datagram = d.answerForUdp(q, java.net.InetAddress.getByName("198.51.100.7"), 1_000_000);
        assertTrue(datagram.length <= DnsResponder.MAX_UDP, "UDP answer was " + datagram.length + " bytes");
        assertTrue((datagram[2] & 0x02) != 0, "TC should be set so the resolver asks again over TCP");
        // TCP is unchanged: it has a length prefix, so the whole answer goes.
        assertTrue(d.respond(q).length > DnsResponder.MAX_UDP, "TCP should still carry the whole answer");
    }

    @Test
    void anAnswerTooLargeForADatagramComesBackTruncated() {
        // Nothing this zone holds reaches 512 today, so the path is driven with a response built by
        // hand: the point is that the bound exists and produces a well-formed TC answer, not that
        // some name currently trips it.
        byte[] question = query("myapp." + HUB, 1);
        byte[] oversized = new byte[600];
        System.arraycopy(question, 0, oversized, 0, question.length);
        oversized[2] = (byte) 0x84;                       // QR, AA
        oversized[6] = 0;
        oversized[7] = 9;                                 // nine answers, none of which survive

        byte[] t = DnsResponder.truncate(oversized);
        assertEquals(question.length, t.length, "the header and the question, and nothing after it");
        assertTrue((t[2] & 0x02) != 0, "TC should be set");
        assertEquals(1, t[5], "the question is still echoed");
        for (int i = 6; i < 12; i++) {
            assertEquals(0, t[i], "no records should be counted at byte " + i);
        }
        assertTrue(t.length <= question.length, "a truncated answer must not be larger than the query");
    }

    /** The zone at its largest: two hosts, both name servers, an issuance in flight. */
    private static DnsResponder fullest() {
        DnsResponder d = new DnsResponder(HUB);
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

    private static List<String> names() {
        return List.of(
            "_acme-challenge." + HUB, HUB, "myapp." + HUB, "a.b.c." + HUB,
            "ns1." + HUB, "ns2." + HUB, DnsResponder.SELF_LABEL + "." + HUB, "other.example.com");
    }

    static byte[] queryFor(String name, int type) {
        return query(name, type);
    }

    private static byte[] query(String name, int type) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(0x12);
        o.write(0x34);
        o.write(0x01);
        o.write(0x00);
        o.write(0);
        o.write(1);
        for (int i = 0; i < 6; i++) {
            o.write(0);
        }
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII);
            o.write(b.length);
            o.writeBytes(b);
        }
        o.write(0);
        o.write(type >> 8);
        o.write(type & 0xff);
        o.write(0);
        o.write(1);
        return o.toByteArray();
    }
}
