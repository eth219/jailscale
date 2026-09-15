package io.jailscale.hub.dns;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

/** The per-network answer rate on UDP 53 (ARCHITECTURE.md §11.5). */
class ResponseRateTest {

    private static ResponseRate.Verdict check(ResponseRate r, String ip, long now) throws Exception {
        return r.check(InetAddress.getByName(ip), now);
    }

    @Test
    void anOrdinaryResolverIsNeverTouched() throws Exception {
        // What this zone actually sees: a handful of queries when a TTL lapses. The limit has to be
        // somewhere no honest traffic can reach, or it is a way to take the zone down.
        ResponseRate r = new ResponseRate();
        long now = 1_000_000;
        for (int i = 0; i < 200; i++) {
            assertSame(ResponseRate.Verdict.ANSWER, check(r, "198.51.100.7", now + i * 100L),
                "query " + i + " at 10 a second");
        }
        assertEquals(0, r.dropped());
        assertEquals(0, r.truncated());
    }

    @Test
    void afloodIsCutAndOneInSlipIsToldToUseTcp() throws Exception {
        ResponseRate r = new ResponseRate();
        long now = 1_000_000;
        int answered = 0;
        int truncated = 0;
        int dropped = 0;
        for (int i = 0; i < 500; i++) {
            switch (check(r, "198.51.100.7", now)) {   // all in the same millisecond: no refill
                case ANSWER -> answered++;
                case TRUNCATE -> truncated++;
                case DROP -> dropped++;
            }
        }
        assertEquals(ResponseRate.BURST, answered, "the burst, and then nothing more");
        // Every SLIP-th of what is left, so a resolver behind a forged address still learns to ask
        // over TCP rather than being left with silence.
        assertEquals((500 - ResponseRate.BURST) / ResponseRate.SLIP, truncated);
        assertEquals(500 - ResponseRate.BURST - truncated, dropped);
        assertEquals(dropped, r.dropped());
        assertEquals(truncated, r.truncated());
    }

    @Test
    void theBudgetComesBack() throws Exception {
        ResponseRate r = new ResponseRate();
        long now = 1_000_000;
        for (int i = 0; i < ResponseRate.BURST; i++) {
            check(r, "198.51.100.7", now);
        }
        assertNotEquals(ResponseRate.Verdict.ANSWER, check(r, "198.51.100.7", now));
        // A second later, a second's worth.
        assertSame(ResponseRate.Verdict.ANSWER, check(r, "198.51.100.7", now + 1000));
    }

    @Test
    void v4IsKeyedOnTheNetworkAndNotTheAddress() throws Exception {
        // A reflection attack aims at a network, so an attacker who could get the full rate for each
        // address in a /24 would have 256 times the budget against one victim.
        ResponseRate r = new ResponseRate();
        long now = 1_000_000;
        for (int i = 0; i < ResponseRate.BURST; i++) {
            check(r, "198.51.100." + (i % 256), now);
        }
        assertNotEquals(ResponseRate.Verdict.ANSWER, check(r, "198.51.100.200", now),
            "another address in a spent /24");
        assertSame(ResponseRate.Verdict.ANSWER, check(r, "203.0.113.1", now), "a different /24");
    }

    @Test
    void v6IsKeyedOnTheSixtyFourAndNotTheAddress() throws Exception {
        // The case a per-address bound cannot survive at all: a routed /64 is what every ordinary
        // VPS is given, so 2^64 source addresses cost an attacker nothing.
        ResponseRate r = new ResponseRate();
        long now = 1_000_000;
        for (int i = 0; i < ResponseRate.BURST; i++) {
            check(r, "2001:db8:1:2::" + Integer.toHexString(i + 1), now);
        }
        assertNotEquals(ResponseRate.Verdict.ANSWER, check(r, "2001:db8:1:2:ffff::9", now),
            "another address in a spent /64");
        assertSame(ResponseRate.Verdict.ANSWER, check(r, "2001:db8:1:3::1", now), "a different /64");
    }

    @Test
    void theSlipFiresAtRatesBetweenTheLimitAndTwiceIt() throws Exception {
        // The slip used to need two *consecutive* over-limit queries, and between the limit and
        // twice it they are never consecutive: one token refills between arrivals, so DROP and
        // ANSWER alternate, the counter resets on every ANSWER and TRUNCATE never fires. A network
        // paced there got silence for ever, which is the one thing the slip exists to prevent.
        ResponseRate r = new ResponseRate(50, 20);
        long now = 1_000_000;
        int truncated = 0;
        for (int i = 0; i < 600; i++, now += 33) {          // ~30 a second against a limit of 20
            if (check(r, "198.51.100.7", now) == ResponseRate.Verdict.TRUNCATE) {
                truncated++;
            }
        }
        assertTrue(truncated > 50, "a resolver paced at 1.5x the limit should still be told to use TCP, got " + truncated);
    }

    @Test
    void walkingAPrefixDoesNotCollectTheWholeTable() throws Exception {
        // Buckets are per key and a victim owns a prefix, so an attacker forging sources across a
        // /48 touches more distinct /64s than the table has buckets and used to collect every
        // bucket's budget at once -- 2,048 x 20 a second at one victim, not the per-network 20.
        ResponseRate r = new ResponseRate();
        long now = 1_000_000;
        int answered = 0;
        for (int i = 0; i < 60_000; i++) {
            String ip = "2001:db8:" + Integer.toHexString(i >> 16) + ":" + Integer.toHexString(i & 0xffff) + "::1";
            if (check(r, ip, now) == ResponseRate.Verdict.ANSWER) {
                answered++;
            }
        }
        assertTrue(answered <= ResponseRate.GLOBAL_BURST,
            "one instant at one victim should be bounded by the table-wide burst, got " + answered);
    }

    @Test
    void loopbackIsExempt() throws Exception {
        // §8.1 exempts loopback from the visitor caps because a local proxy would fold everyone into
        // one address; a forwarder in front of :53 would do the same to every resolver in the world,
        // and this hub's own dns-01 self-check asks from here.
        ResponseRate r = new ResponseRate();
        long now = 1_000_000;
        for (int i = 0; i < 500; i++) {
            assertSame(ResponseRate.Verdict.ANSWER, check(r, "127.0.0.1", now), "loopback query " + i);
        }
        assertSame(ResponseRate.Verdict.ANSWER, check(r, "::1", now), "v6 loopback");
        assertEquals(0, r.dropped());
    }

    @Test
    void theUdpPathAppliesTheLimitAndTheDatagramBound() throws Exception {
        // The wiring, not the arithmetic: that what DnsResponder would put in a datagram is what
        // this class decided. Driven through answerForUdp rather than a socket, so the source
        // address can be one that is not exempt.
        DnsResponder d = new DnsResponder("hub.test");
        d.setZone(new DnsResponder.Zone() {
            @Override public java.util.List<String> serving() {
                return java.util.List.of("203.0.113.1");
            }

            @Override public java.util.Map<String, String> nameServers() {
                return java.util.Map.of();
            }
        });
        InetAddress far = InetAddress.getByName("198.51.100.7");
        byte[] q = DnsFuzzTest.query("myapp.hub.test", 1);
        long now = 1_000_000;

        byte[] first = d.answerForUdp(q, far, now);
        assertTrue(first != null && first.length > 12, "an ordinary query should be answered");

        int dropped = 0;
        int truncated = 0;
        for (int i = 0; i < 200; i++) {
            byte[] r = d.answerForUdp(q, far, now);
            if (r == null) {
                dropped++;
            } else if ((r[2] & 0x02) != 0) {
                truncated++;
                assertTrue(r.length <= q.length, "a truncated answer must not be larger than the query");
            }
        }
        assertTrue(dropped > 0, "a flood should be dropped");
        assertTrue(truncated > 0, "and some of it told to use TCP");
    }

    @Test
    void manyNetworksCostNothingToTrack() throws Exception {
        // The point of the fixed table: an attacker rotating source networks is the case that would
        // grow a map, and the scan that trimmed it would run on the thread reading the socket. Here
        // a hundred thousand of them touch the same 2,048 buckets and allocate nothing.
        ResponseRate r = new ResponseRate();
        long now = 1_000_000;
        long started = System.nanoTime();
        for (int i = 0; i < 100_000; i++) {
            check(r, "10." + (i >> 16 & 0xff) + "." + (i >> 8 & 0xff) + "." + (i & 0xff), now);
        }
        long ms = (System.nanoTime() - started) / 1_000_000;
        // Not a timing assertion -- an O(1) table cannot be slow enough to fail one, and a bound
        // nothing can breach is not a test. What is asserted is the property: after a hundred
        // thousand networks the table still answers an ordinary caller, which a map that had grown
        // (and a scan that trimmed it) is exactly what this shape exists to avoid.
        assertSame(ResponseRate.Verdict.ANSWER, check(r, "198.51.100.7", now + 10_000),
            "after " + ms + " ms and 100,000 networks a fresh caller is still answered");
    }
}
