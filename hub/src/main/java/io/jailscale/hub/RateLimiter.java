package io.jailscale.hub;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A per-key token bucket for the work an unauthenticated caller can make the hub do
 * (ARCHITECTURE.md §11.5): opening a Noise handshake, and presenting a credential to register.
 *
 * <p>Buckets are keyed by source address, so the map would grow without bound under an attacker
 * who rotates addresses. Once it passes {@link #MAX_KEYS} the refilled buckets are dropped; a
 * bucket back at full strength is indistinguishable from one that never existed, so nothing is
 * lost by forgetting it.
 */
final class RateLimiter {

    /** Above this many tracked keys, refilled buckets are dropped (~48 bytes each). */
    static final int MAX_KEYS = 10_000;

    private record Bucket(double tokens, long at) {}

    private final int burst;
    private final double perSecond;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    RateLimiter(int burst, double perSecond) {
        this.burst = burst;
        this.perSecond = perSecond;
    }

    /** Takes one token for {@code key}; false when that key is over its limit. */
    boolean allow(String key) {
        long now = System.currentTimeMillis();
        if (buckets.size() > MAX_KEYS) {
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

    private double refilled(Bucket b, long now) {
        return Math.min(burst, b.tokens() + Math.max(0, now - b.at()) * perSecond / 1000.0);
    }

    private void prune(long now) {
        buckets.entrySet().removeIf(e -> refilled(e.getValue(), now) >= burst);
    }
}
