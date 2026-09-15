package io.jailscale.proto.util;

/**
 * Says yes at most once an interval, and always the first time.
 *
 * <p>For the log line that reports a condition which, while it lasts, is true of every request:
 * a node at its visitor ceiling refuses continuously, a hub over its DNS answer rate drops
 * continuously. One line per event buries its own reason among its own symptoms, so each of those
 * sites kept a timestamp and compared it against an interval.
 *
 * <p><b>Three sites kept their own, and the duplication was wrong twice.</b> Once on the clock --
 * one of them measured elapsed time with the time of day after the others had moved to {@link
 * Clock}, so an NTP step backwards would have frozen it for the width of the step. Once on the
 * sentinel -- two were seeded with a clock reading, which suppressed the first sixty seconds of
 * process life, and the first sixty seconds is exactly when an operator restarting into an attack
 * is watching. Both were found by reading rather than by a test, because there is nothing about
 * five lines of timestamp arithmetic for a test to catch. One of these owns the clock, the
 * sentinel and the interval, and a fourth caller inherits all three.
 *
 * <p>Zero means never said, so the first call is always true; a monotonic clock has no defined
 * origin, so no reading can be the sentinel. Reading exactly zero would allow one extra line, once,
 * ever. Two threads arriving together can both be told yes -- the same race the hand-written
 * versions had, and a lock to close it would cost more than the duplicate line it prevents.
 */
public final class Throttle {

    private final long intervalMs;
    private volatile long last;

    public Throttle(long intervalMs) {
        this.intervalMs = intervalMs;
    }

    /** True at most once per interval, and always the first time. */
    public boolean ready() {
        long now = Clock.millis();
        long seen = last;
        if (seen != 0 && now - seen < intervalMs) {
            return false;
        }
        last = now;
        return true;
    }
}
