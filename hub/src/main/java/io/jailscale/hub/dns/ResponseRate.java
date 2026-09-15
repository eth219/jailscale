package io.jailscale.hub.dns;

import java.net.InetAddress;

/**
 * How often one network may be answered on UDP 53 (ARCHITECTURE.md §11.5).
 *
 * <p>Every other unauthenticated thing the hub does for a stranger is metered by a token bucket;
 * this is that, for the one surface that was not. What it defends is not the hub's own capacity but
 * somebody else's: a query's source address is a claim, not a fact, so an attacker puts a victim's
 * address on a query here and the hub sends the answer there. The answers are small — measured at
 * worst {@code 5.3x} the query, with the largest 287 bytes ({@code DnsAmplificationTest}) — which
 * makes this a poor amplifier rather than a harmless one, and a poor amplifier that answers without
 * limit is still a free one.
 *
 * <p><b>Keyed by network and not by address.</b> A reflection attack names a victim, and a victim is
 * a network: limiting per address would let an attacker walk the /24 it is aiming at and get the
 * full rate for each. So v4 is keyed on its /24 and v6 on its /64, which is the smallest thing an
 * attacker is given rather than chooses — the same reasoning that makes a per-address bound
 * meaningless against anyone holding a routed /64.
 *
 * <p><b>A fixed table, so nothing grows and nothing is pruned.</b> {@code RateLimiter} keeps a map
 * keyed by source and drops full buckets once it holds too many, which is right where the caller has
 * already been made to do work to get there. Here the caller has done nothing but send one
 * unverified packet, so the map would be an attacker's to grow and the scan that trims it would land
 * on this thread, once per packet, under exactly the flood it exists for. {@link #BUCKETS} buckets
 * indexed by a hash of the network cost 36 KB once and one array read per query.
 *
 * <p>Two networks that hash together share a budget. That is the whole cost of the collision and it
 * is the safe direction — sharing limits more, never less — and the key is deliberately <b>not</b>
 * stored to tell them apart, because a table that replaced the loser of a collision would let an
 * attacker clear a victim's bucket by choosing addresses that land on it.
 */
final class ResponseRate {

    /** 2,048 buckets: 36 KB, and more networks than this zone will see in a day from honest resolvers. */
    static final int BUCKETS = 2048;
    /**
     * Answers a second per network, and what may arrive at once. Far above any honest resolver's
     * traffic for a zone that holds one person's names -- the addresses carry a 30 second TTL and
     * the challenge values five -- and far below what makes a 287-byte answer worth reflecting: at
     * this rate a victim receives about 5 KB/s from a hub, against the 60 KB/s of queries it costs
     * the attacker to ask for it.
     */
    static final int BURST = 50;
    static final double PER_SECOND = 20;
    /**
     * One over-limit query in this many is answered {@code TC=1} instead of being dropped, which
     * tells a resolver to ask again over TCP -- which this server also answers, and where a source
     * address is a fact rather than a claim.
     *
     * <p>Without it a limit is a way to take the zone down: an honest resolver sharing a bucket with
     * an attacker, or behind the address an attacker is forging, would get silence and the names
     * would go dark for everyone behind it. A truncated answer is the question echoed and no
     * records, so it is never larger than the query that asked for it and reflects nothing.
     */
    static final int SLIP = 2;

    private final double[] tokens = new double[BUCKETS];
    private final long[] at = new long[BUCKETS];
    private final int[] overLimit = new int[BUCKETS];
    private final int burst;
    private final double perSecond;
    private long dropped;
    private long truncated;

    ResponseRate() {
        this(BURST, PER_SECOND);
    }

    ResponseRate(int burst, double perSecond) {
        this.burst = burst;
        this.perSecond = perSecond;
        java.util.Arrays.fill(tokens, burst);
    }

    /** What to do with one query. */
    enum Verdict {
        /** Under the limit: answer it. */
        ANSWER,
        /** Over, and this is the one in {@link #SLIP} that is told to come back over TCP. */
        TRUNCATE,
        /** Over: send nothing at all. */
        DROP
    }

    /**
     * Takes one answer's worth of budget for {@code source}. Synchronized because it is cheaper than
     * the invariant: one thread reads the UDP socket today and a second one here would be a data
     * race nobody would see until it mattered.
     */
    synchronized Verdict check(InetAddress source, long now) {
        // Loopback is exempt, as it is for the visitor caps of §8.1 and for the same reason: a
        // forwarder on this host would otherwise fold every resolver in the world into one bucket
        // and take the zone down at twenty queries a second. It is also where this hub's own
        // dns-01 self-check asks from, and a certificate that fails to issue because the server was
        // busy being flooded is the outcome this whole limit exists to avoid. Nothing is given away:
        // a datagram claiming a loopback source cannot arrive from off the machine.
        if (source.isLoopbackAddress()) {
            return Verdict.ANSWER;
        }
        int i = bucket(source);
        double have = Math.min(burst, tokens[i] + Math.max(0, now - at[i]) * perSecond / 1000.0);
        at[i] = now;
        if (have >= 1) {
            tokens[i] = have - 1;
            overLimit[i] = 0;
            return Verdict.ANSWER;
        }
        tokens[i] = have;
        if (++overLimit[i] >= SLIP) {
            overLimit[i] = 0;
            truncated++;
            return Verdict.TRUNCATE;
        }
        dropped++;
        return Verdict.DROP;
    }

    /** Queries dropped and answered truncated since this hub started, for the log line. */
    long dropped() {
        return dropped;
    }

    long truncated() {
        return truncated;
    }

    /**
     * The bucket for a source's network: the first three bytes of a v4 address, the first eight of a
     * v6 one. Mixed rather than taken modulo, so that networks one apart do not land one apart --
     * an attacker sweeping a /16 would otherwise fill the table in order and share nothing.
     */
    private static int bucket(InetAddress source) {
        byte[] b = source.getAddress();
        int prefix = b.length == 4 ? 3 : 8;
        int h = 0;
        for (int i = 0; i < prefix && i < b.length; i++) {
            h = h * 31 + (b[i] & 0xff);
        }
        h *= 0x9E3779B1;                 // a round of mixing, so adjacent networks scatter
        h ^= h >>> 15;
        return Math.floorMod(h, BUCKETS);
    }
}
