package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * The availability record (ARCHITECTURE.md §13.2): the process's own gaps, what it saw of a peer,
 * and the two never added together. Time is passed in rather than read, so each case is a
 * timeline and not a sleep.
 */
class AvailabilityTest {

    private static final long H = 3_600_000L;
    private static final long D = 24 * H;
    private static final long T0 = 1_800_000_000_000L;

    @Test
    void aFreshRecordIsAllUpAndSaysWhenItBegan() throws Exception {
        Path dir = TestDirs.newRoot("avail");
        Availability a = new Availability(dir, T0);
        assertEquals(T0, a.since());
        assertEquals(1.0, a.processFraction(D, T0 + H), 1e-9);
        // Over a window longer than the record, the fraction is over the record, not the window.
        assertEquals(1.0, a.processFraction(30 * D, T0 + H), 1e-9);
        assertNull(a.processFraction(D, T0), "nothing has elapsed; there is nothing to divide by");
        assertTrue(Files.exists(dir.resolve("availability.json")));
    }

    @Test
    void theGapBetweenTheLastStampAndTheNextStartCountsAsDown() throws Exception {
        Path dir = TestDirs.newRoot("avail");
        Availability first = new Availability(dir, T0);
        first.stamp(T0 + 10 * 60_000);
        // The process is gone for an hour, then comes back.
        Availability second = new Availability(dir, T0 + 70 * 60_000);
        assertEquals(T0, second.since(), "the record's start survives a restart");
        assertEquals(1.0 - 60.0 / 70.0, second.processFraction(D, T0 + 70 * 60_000), 1e-9);
        // The window that reaches past the record's start is still divided by the record's length.
        assertEquals(1.0 - 60.0 / 70.0, second.processFraction(30 * D, T0 + 70 * 60_000), 1e-9);
        // An hour later, still up: the same hour of downtime over a longer span.
        assertEquals(1.0 - 60.0 / 130.0, second.processFraction(D, T0 + 130 * 60_000), 1e-9);
    }

    @Test
    void aStampIsWhatTheNextStartMeasuresFrom() throws Exception {
        // Without the periodic stamp, a process that ran for a day and crashed would be booked as
        // down from its start: the stamp is what moves the "last known alive" forward.
        Path dir = TestDirs.newRoot("avail");
        Availability first = new Availability(dir, T0);
        first.stamp(T0 + D);
        Availability second = new Availability(dir, T0 + D + H);
        assertEquals(1.0 - 1.0 / 25.0, second.processFraction(30 * D, T0 + D + H), 1e-9);
    }

    @Test
    void gapsOlderThanTheLongestWindowAreForgotten() throws Exception {
        Path dir = TestDirs.newRoot("avail");
        Availability first = new Availability(dir, T0);
        first.stamp(T0 + H);
        // Down for forty days.
        Availability second = new Availability(dir, T0 + 40 * D);
        assertEquals(0.0, second.processFraction(30 * D, T0 + 40 * D), 1e-9, "the whole 30-day window was down");
        // Fifteen days of running later, half the window is up, and the gap's start has been
        // clipped to the horizon rather than kept from forty days back.
        second.stamp(T0 + 55 * D);
        assertEquals(0.5, second.processFraction(30 * D, T0 + 55 * D), 1e-9);
        assertEquals(1.0, second.processFraction(D, T0 + 55 * D), 1e-9);
    }

    @Test
    void aPeerIsMeasuredOnlyWhileThisProcessWasThereToLook() throws Exception {
        Path dir = TestDirs.newRoot("avail");
        Availability a = new Availability(dir, T0);
        assertNull(a.peerFraction("b", D, T0 + 100), "no peer has been seen yet");
        a.peerUp("b", T0);
        a.peerDown("b", T0 + 10);
        a.peerDown("b", T0 + 15); // idempotent while down
        a.peerUp("b", T0 + 20);
        assertEquals(0.9, a.peerFraction("b", D, T0 + 100), 1e-9);
        // The peer goes down at 90; this process last stamps at 100 and dies; it is back at 200.
        a.peerDown("b", T0 + 90);
        a.stamp(T0 + 100);
        Availability b = new Availability(dir, T0 + 200);
        // Observed for 100 of the 200 ms; the peer was down for 20 of those. The 100 ms this
        // process was away are neither up nor down for the peer: they are out of the denominator.
        assertEquals(0.8, b.peerFraction("b", D, T0 + 200), 1e-9);
        assertEquals(0.5, b.processFraction(D, T0 + 200), 1e-9);
        // Still down after the restart until it reconnects at 210.
        b.peerUp("b", T0 + 210);
        assertEquals(1.0 - 30.0 / 120.0, b.peerFraction("b", D, T0 + 220), 1e-9);
        assertEquals(java.util.List.of("b"), b.peerNames());
    }

    @Test
    void anUnreadableRecordStartsOverRatherThanRefusingToStart() throws Exception {
        Path dir = TestDirs.newRoot("avail");
        Files.writeString(dir.resolve("availability.json"), "{not json", StandardCharsets.UTF_8);
        Availability a = new Availability(dir, T0 + 5);
        assertEquals(T0 + 5, a.since());
        assertEquals(1.0, a.processFraction(D, T0 + 6), 1e-9);
    }

    @Test
    void percentShowsOnlyTheDigitsTheNumberHas() {
        assertEquals("100%", Availability.percent(1.0));
        assertEquals("100%", Availability.percent(0.99996));
        assertEquals("99.98%", Availability.percent(0.9998));
        assertEquals("99.00%", Availability.percent(0.99));
        assertEquals("97.2%", Availability.percent(0.972));
        assertEquals("0.0%", Availability.percent(0.0));
        assertEquals("n/a", Availability.percent(null));
    }
}
