package io.jailscale.proto.util;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * {@link Clock}: the source every elapsed time and every deadline is measured against
 * (ARCHITECTURE.md §11.5, §9.3).
 *
 * <p>What it is for cannot be tested here -- nothing in a test may step the machine's clock, which
 * is the event this exists to be unaffected by. What can be pinned is that the contract holds:
 * never backwards, and moving at the rate a millisecond moves, so the arithmetic that used the time
 * of day still means what it meant.
 */
@Timeout(30)
class ClockTest {

    @Test
    void neverGoesBackwards() {
        long last = Clock.millis();
        for (int i = 0; i < 200_000; i++) {
            long now = Clock.millis();
            assertTrue(now >= last, "went backwards: " + now + " after " + last);
            last = now;
        }
    }

    @Test
    void advancesAtTheRateOfAMillisecond() throws Exception {
        // Loose on both sides: this is a sanity check on the unit, not a measurement of sleep.
        long before = Clock.millis();
        Thread.sleep(200);
        long elapsed = Clock.millis() - before;
        assertTrue(elapsed >= 150 && elapsed < 5_000, "200 ms of sleep measured as " + elapsed + " ms");
    }
}
