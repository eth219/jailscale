package io.jailscale.proto.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * {@link Throttle}: the once-an-interval log guard the node's refusals and stalls and the hub's DNS
 * rate warning share (ARCHITECTURE.md §9.3, §11.5).
 *
 * <p>What is pinned here is the pair of properties the three hand-written copies disagreed about
 * before this existed: the first event always speaks, and the ones behind it do not.
 */
@Timeout(30)
class ThrottleTest {

    @Test
    void theFirstOneAlwaysSpeaks() {
        // The copies that seeded their timestamp from the clock stayed silent for a whole interval
        // after the process started -- which is the interval an operator restarting into an attack
        // is watching. A fresh Throttle has said nothing, so it has something to say.
        assertTrue(new Throttle(60_000).ready(), "a throttle that has never spoken must speak");
    }

    @Test
    void andTheOnesBehindItDoNot() {
        Throttle t = new Throttle(60_000);
        assertTrue(t.ready());
        for (int i = 0; i < 1_000; i++) {
            assertFalse(t.ready(), "call " + i + " inside the interval");
        }
    }

    @Test
    void andItSpeaksAgainOnceTheIntervalHasPassed() throws Exception {
        Throttle t = new Throttle(20);
        assertTrue(t.ready());
        assertFalse(t.ready());
        Thread.sleep(60);
        assertTrue(t.ready(), "past the interval it is due again");
    }
}
