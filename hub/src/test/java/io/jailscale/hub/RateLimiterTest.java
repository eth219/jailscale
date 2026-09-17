package io.jailscale.hub;

import io.jailscale.proto.util.Clock;
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
        RateLimiter r = new RateLimiter(3, 1, RateLimiter.DEFAULT_PRUNE_MS, Clock::millis);
        for (int i = 0; i < 3; i++) {
            assertTrue(r.allow("10.0.0.1"), "burst token " + i + " should be free");
        }
        assertFalse(r.allow("10.0.0.1"));
        assertFalse(r.allow("10.0.0.1"), "a refused call must not refund the caller");
    }

    @Test
    void refillsOverTime() {
        // A clock this test moves, not one it waits for (#61, #197). At 100 tokens a second one
        // arrives every 10 ms, so with a real clock the three calls after the wait could themselves
        // take long enough to refill a fourth and fail the last assertion -- which is what happened
        // once on a laptop. Nothing here is slept through, and the last assertion is now exact.
        long[] clock = {1_000};
        RateLimiter r = new RateLimiter(3, 100, RateLimiter.DEFAULT_PRUNE_MS, () -> clock[0]);
        for (int i = 0; i < 3; i++) {
            assertTrue(r.allow("10.0.0.2"));
        }
        assertFalse(r.allow("10.0.0.2"));
        clock[0] += 200;   // 20 tokens' worth, so the burst of 3 is full and no more
        for (int i = 0; i < 3; i++) {
            assertTrue(r.allow("10.0.0.2"), "token " + i + " should have refilled");
        }
        assertFalse(r.allow("10.0.0.2"), "refill is capped at the burst");
    }

    @Test
    void keysAreIndependent() {
        RateLimiter r = new RateLimiter(1, 1, RateLimiter.DEFAULT_PRUNE_MS, Clock::millis);
        assertTrue(r.allow("10.0.0.3"));
        assertFalse(r.allow("10.0.0.3"));
        assertTrue(r.allow("10.0.0.4"), "one exhausted address must not shut out another");
    }

    @Test
    void anIpv6NetworkDoesNotGetALimitPerAddress() {
        // §11.5 is a bound per caller, and in v6 a caller is not an address: a routed /64 comes with
        // every ordinary VPS, so counted per address every limit in that table would be free to
        // anyone who wanted it. The hub serves both stacks wherever its listener is bound to `::`.
        RateLimiter r = new RateLimiter(2, 1, RateLimiter.DEFAULT_PRUNE_MS, Clock::millis);
        assertTrue(r.allow("2001:db8:1:2::1"));
        assertTrue(r.allow("2001:db8:1:2::2"));
        assertFalse(r.allow("2001:db8:1:2::3"), "a third address in the same /64 is the same caller");
        assertFalse(r.allow("2001:db8:1:2:ffff:ffff:ffff:ffff"), "and so is the far end of it");
        assertTrue(r.allow("2001:db8:1:3::1"), "a different /64 is a different caller");
    }

    @Test
    void theScanThatBoundsTheMapDoesNotRunOnEveryCall() {
        // The shipped handshake numbers, and the case the scan cannot help with: at 1/s a bucket is
        // not full again until 30 s after its last use, so an attacker rotating addresses leaves
        // ten thousand of them that prune has nothing to remove. It used to scan all of them on
        // every call from then on -- 36.4 us against 0.044 us with a map of one, all of it the scan
        // and none of it doing anything.
        RateLimiter r = new RateLimiter(30, 1, RateLimiter.DEFAULT_PRUNE_MS, Clock::millis);
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
        // only ever grew would be the trade going the wrong way. This is also what says the scan
        // drops the full buckets at all -- the test that used to say it separately did so with the
        // interval set to zero, which is the one setting that turns off the thing under test.
        RateLimiter r = new RateLimiter(1, 1000, 10, Clock::millis); // full again 1 ms after use, scan every 10
        for (int i = 0; i < RateLimiter.MAX_KEYS + 500; i++) {
            r.allow("10." + (i >> 16 & 0xff) + "." + (i >> 8 & 0xff) + "." + (i & 0xff));
        }
        Thread.sleep(50);
        r.allow("10.9.9.9");
        assertTrue(r.size() <= RateLimiter.MAX_KEYS, "expected a scan by now, size " + r.size());
    }

    @Test
    void aPrunedKeyStartsFreshWhichIsWhatAFullBucketWouldHaveDone() throws Exception {
        RateLimiter r = new RateLimiter(2, 1000, RateLimiter.DEFAULT_PRUNE_MS, Clock::millis);
        assertTrue(r.allow("10.0.0.5"));
        Thread.sleep(20);
        assertTrue(r.allow("10.0.0.5"));
        assertTrue(r.allow("10.0.0.5"));
        assertEquals(1, r.size());
    }
}
