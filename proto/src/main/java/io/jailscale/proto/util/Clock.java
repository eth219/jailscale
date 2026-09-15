package io.jailscale.proto.util;

/**
 * Milliseconds from a clock that only goes forward, for measuring how long something took and for
 * deciding when something is due.
 *
 * <p>{@link System#currentTimeMillis()} is the wrong clock for both and is what this replaces at the
 * places that measure rather than record. It is the time of day, so it steps: NTP corrects a host
 * whose clock was wrong at boot, a virtual machine resumed from a snapshot wakes up in the past, and
 * an operator can set it by hand. A step backwards stops elapsed time passing -- a token bucket
 * stops refilling and stays empty for as long as the step was, which on the control plane means
 * nodes that cannot reconnect for an hour because a clock moved an hour. A step forwards is the
 * other half: every bucket refills at once, and every deadline in flight expires together.
 *
 * <p>{@link System#nanoTime()} has no such behaviour and no defined origin, which is exactly right
 * for a value only ever used as a difference. Divided down to milliseconds it is a drop-in for the
 * arithmetic that was there, and it may be negative, which nothing may assume anything about.
 *
 * <p><b>Not everything that reads a clock belongs here.</b> A time that is written down -- an
 * invite's expiry, a node's join date, the availability record -- has to survive a restart and be
 * the same instant to two hosts, and only the time of day is that. The rule is what the value is
 * for: recorded, {@code currentTimeMillis}; measured, this.
 */
public final class Clock {

    private Clock() {}

    /** A monotonic millisecond. Meaningful only against another one from this method. */
    public static long millis() {
        return System.nanoTime() / 1_000_000L;
    }
}
