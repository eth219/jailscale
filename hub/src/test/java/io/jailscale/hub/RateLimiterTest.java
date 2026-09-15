package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** ARCHITECTURE.md §11.5: the per-address token bucket behind the handshake and credential limits. */
@Timeout(30)
class RateLimiterTest {

    @Test
    void spendsItsBurstThenRefuses() {
        RateLimiter r = new RateLimiter(3, 1);
        for (int i = 0; i < 3; i++) {
            assertTrue(r.allow("10.0.0.1"), "burst token " + i + " should be free");
        }
        assertFalse(r.allow("10.0.0.1"));
        assertFalse(r.allow("10.0.0.1"), "a refused call must not refund the caller");
    }

    @Test
    void refillsOverTime() throws Exception {
        RateLimiter r = new RateLimiter(3, 100); // 100/s: the burst is back within 30 ms
        for (int i = 0; i < 3; i++) {
            assertTrue(r.allow("10.0.0.2"));
        }
        assertFalse(r.allow("10.0.0.2"));
        Thread.sleep(200);
        for (int i = 0; i < 3; i++) {
            assertTrue(r.allow("10.0.0.2"), "token " + i + " should have refilled");
        }
        assertFalse(r.allow("10.0.0.2"), "refill is capped at the burst");
    }

    @Test
    void keysAreIndependent() {
        RateLimiter r = new RateLimiter(1, 1);
        assertTrue(r.allow("10.0.0.3"));
        assertFalse(r.allow("10.0.0.3"));
        assertTrue(r.allow("10.0.0.4"), "one exhausted address must not shut out another");
    }

    @Test
    void prunesRefilledBucketsSoRotatingAddressesCannotGrowIt() throws Exception {
        RateLimiter r = new RateLimiter(1, 1000); // refills in 1 ms
        for (int i = 0; i < RateLimiter.MAX_KEYS + 200; i++) {
            r.allow("10.1." + (i / 256) + "." + (i % 256));
        }
        Thread.sleep(50); // every bucket is now back at full strength
        r.allow("10.9.9.9");
        assertTrue(r.size() <= RateLimiter.MAX_KEYS,
            "expected pruning below " + RateLimiter.MAX_KEYS + ", got " + r.size());
    }

    @Test
    void theScanThatBoundsTheMapDoesNotRunOnEveryCall() {
        // The shipped handshake numbers, and the case the scan cannot help with: at 1/s a bucket is
        // not full again until 30 s after its last use, so an attacker rotating addresses leaves
        // ten thousand of them that prune has nothing to remove. It used to scan all of them on
        // every call from then on -- 36.4 us against 0.044 us with a map of one, all of it the scan
        // and none of it doing anything.
        RateLimiter r = new RateLimiter(30, 1);
        for (int i = 0; i < RateLimiter.MAX_KEYS + 500; i++) {
            r.allow("10." + (i >> 16 & 0xff) + "." + (i >> 8 & 0xff) + "." + (i & 0xff));
        }
        assertTrue(r.size() > RateLimiter.MAX_KEYS, "nothing here is prunable yet: " + r.size());
        long before = r.prunes();
        for (int i = 0; i < 1_000; i++) {
            r.allow("198.51.100.1");
        }
        assertTrue(r.prunes() - before <= 1,
            "a thousand calls inside one interval should scan at most once, scanned " + (r.prunes() - before));
    }

    @Test
    void theScanStillRunsWhenTheIntervalHasPassed() throws Exception {
        // The other half: throttled is not disabled. Memory is what the scan bounds, and a map that
        // only ever grew would be the trade going the wrong way.
        long was = RateLimiter.pruneIntervalMs;
        RateLimiter.pruneIntervalMs = 10;
        try {
            RateLimiter r = new RateLimiter(1, 1000); // full again 1 ms after use
            for (int i = 0; i < RateLimiter.MAX_KEYS + 500; i++) {
                r.allow("10." + (i >> 16 & 0xff) + "." + (i >> 8 & 0xff) + "." + (i & 0xff));
            }
            Thread.sleep(50);
            r.allow("10.9.9.9");
            assertTrue(r.size() <= RateLimiter.MAX_KEYS, "expected a scan by now, size " + r.size());
        } finally {
            RateLimiter.pruneIntervalMs = was;
        }
    }

    @Test
    void aPrunedKeyStartsFreshWhichIsWhatAFullBucketWouldHaveDone() throws Exception {
        RateLimiter r = new RateLimiter(2, 1000);
        assertTrue(r.allow("10.0.0.5"));
        Thread.sleep(20);
        assertTrue(r.allow("10.0.0.5"));
        assertTrue(r.allow("10.0.0.5"));
        assertEquals(1, r.size());
    }
}
