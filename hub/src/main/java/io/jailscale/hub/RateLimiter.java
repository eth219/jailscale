package io.jailscale.hub;

import io.jailscale.proto.net.NetKey;
import io.jailscale.proto.util.Clock;
import java.util.function.LongSupplier;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A per-key token bucket for the work an unauthenticated caller can make the hub do
 * (ARCHITECTURE.md §11.5): opening a Noise handshake, and presenting a credential to register.
 *
 * <p>Buckets are keyed by source address, so the map would grow without bound under an attacker
 * who rotates addresses. Once it passes {@link #MAX_KEYS} the refilled buckets are dropped; a
 * bucket back at full strength is indistinguishable from one that never existed, so nothing is
 * lost by forgetting it.
 *
 * <p><b>A map here, where {@code dns.ResponseRate} has a fixed table, and the difference is what it
 * costs to be tracked.</b> Every caller here has completed a TLS handshake to reach this, which is
 * the expensive thing in the path; a bucket is 48 bytes beside it, and giving each address its own
 * means a flood from ten thousand of them does not touch the bucket of a node trying to reconnect.
 * On :53 the caller has sent one unverified datagram, so a map would be an attacker's to grow and
 * the isolation is not worth having on those terms.
 */
final class RateLimiter {

    /** Above this many tracked keys, refilled buckets are dropped (~48 bytes each). */
    static final int MAX_KEYS = 10_000;

    /**
     * How often the scan that does that may run. It used to run on every call once the map was
     * over {@link #MAX_KEYS}, which is where it costs the most and buys the least: the scan is over
     * every tracked key, and between two consecutive calls there is nothing new for it to find.
     * Measured on the shipped numbers (burst 30, 1/s, 10,500 keys, none of them prunable because a
     * bucket is not full again until 30 s after its last use), one {@code allow} cost <b>36.4 µs
     * against 0.044 µs</b> with a map of one -- 825 times, all of it the scan.
     *
     * <p><b>That is waste and it was not the denial of service it looked like.</b> A caller must
     * complete a TLS handshake to reach this, and the hub spends about 875 µs of its own CPU on a
     * Noise handshake (§14), so the scan was four percent on top of a request that was already the
     * expensive thing. What makes it worth removing is that it is pure loss, that it is paid by
     * refused requests which should cost nothing, and that it grows with {@code MAX_KEYS} if anyone
     * ever raises that.
     *
     * <p>A second a scan is plenty: what the scan bounds is memory, and the map can only grow by
     * one second's worth of <em>new addresses that have each completed a TLS handshake</em>, which
     * is a few thousand entries at the very most and 48 bytes each.
     */
    static final long DEFAULT_PRUNE_MS = 1_000;

    private record Bucket(double tokens, long at) {}

    private final int burst;
    private final double perSecond;
    /** {@link HubConfig.Tuning#rateLimitPruneMs}; a constructor parameter and not a static (#61). */
    private final long pruneIntervalMs;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    private final AtomicLong prunes = new AtomicLong();
    /** Seeded, not left at zero: {@link Clock} has no defined origin and may start below it. */
    private final LongSupplier now;
    private volatile long lastPrune;

    /**
     * The clock is a parameter for the same reason the interval is (#61): a bucket refills by
     * elapsed time, and a test that has to spend that time in {@code Thread.sleep} is measuring the
     * machine as much as the code. {@code refillsOverTime} did exactly that and went red once on a
     * developer's laptop for it (#197) -- with 100 tokens a second, a new one arrives every 10 ms,
     * and three {@code allow} calls on a busy machine can cross that and refill a fourth.
     *
     * <p>Production passes {@link Clock#millis}, which is monotonic: a bucket refills by elapsed
     * time and the time of day is not that.
     */
    RateLimiter(int burst, double perSecond, long pruneIntervalMs, LongSupplier now) {
        this.burst = burst;
        this.perSecond = perSecond;
        this.pruneIntervalMs = pruneIntervalMs;
        this.now = now;
        this.lastPrune = now.getAsLong();
    }

    /**
     * Takes one token for the source address {@code ip}; false when it is over its limit.
     *
     * <p>Counted against the network {@link NetKey} gives rather than the address itself, which in
     * v4 is the address and in v6 is the /64. The hub serves both stacks wherever its listener is
     * bound to {@code ::}, and per address a v6 caller has every limit here for free.
     */
    boolean allow(String ip) {
        String key = NetKey.of(ip);
        long now = this.now.getAsLong();
        if (buckets.size() > MAX_KEYS && now - lastPrune >= pruneIntervalMs) {
            // Set first, so two threads arriving together scan once between them rather than twice.
            // Both scanning is harmless if it happens -- the scan is idempotent -- and this is not
            // worth a lock to make impossible.
            lastPrune = now;
            prune(now);
        }
        boolean[] allowed = new boolean[1];
        buckets.compute(key, (k, b) -> {
            double tokens = b == null ? burst : refilled(b, now);
            allowed[0] = tokens >= 1;
            return new Bucket(allowed[0] ? tokens - 1 : tokens, now);
        });
        return allowed[0];
    }

    /** Tracked keys. Only the pruning test needs this. */
    int size() {
        return buckets.size();
    }

    /** How many times the scan has run. Only the test that it is not run per call needs this. */
    long prunes() {
        return prunes.get();
    }

    private double refilled(Bucket b, long now) {
        return Math.min(burst, b.tokens() + Math.max(0, now - b.at()) * perSecond / 1000.0);
    }

    private void prune(long now) {
        prunes.incrementAndGet();
        buckets.entrySet().removeIf(e -> refilled(e.getValue(), now) >= burst);
    }
}
