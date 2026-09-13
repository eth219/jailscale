package io.jailscale.hub;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * How long each stage of admitting a visitor takes, in aggregate (ARCHITECTURE.md §6.3).
 *
 * <p>Written because a whole afternoon went into a question this answers in one scrape. An ordinary
 * visitor was intermittently waiting ten to sixteen seconds under load, and finding out where took
 * eight native rebuilds, each adding a timer to one stage guessed at in advance -- and every stage
 * measured came back fast. <b>The finding was that the total exceeded the sum of the parts</b>, which
 * is the one thing per-stage timers added one at a time cannot show, and which
 * {@code firstByte - (peek + resolve + open + reply)} shows immediately.
 *
 * <p><b>Sums and counts and high-water marks, not buckets.</b> A Prometheus histogram conventionally
 * carries its bucket bound in an {@code le} label, and no metric here carries a label at all: §6.3
 * says a scrape reports how much the hub is doing and never who is doing it, and
 * {@code MetricsEndpointTest} enforces that by failing on any label. A bucket bound is a number
 * rather than an identity, so it would not actually leak anything -- but a mean plus a maximum per
 * stage answered the question that motivated this, and it needed no argument about the rule. Buckets
 * are worth adding the day a percentile is what is missing.
 *
 * <p>Nothing here names anything either: these are process-wide totals, so they say the admission
 * path is slow without saying whose admission it was.
 */
final class RelayStages {

    /** Visitors that got as far as their first relayed byte, the denominator for every sum below. */
    static final LongAdder OBSERVED = new LongAdder();

    /** Accept to the ClientHello being read off the visitor's socket. */
    static final Stage PEEK = new Stage();
    /** Peek to knowing which link and node this name belongs to, hand-off waits included. */
    static final Stage RESOLVE = new Stage();
    /** Resolve to a mux stream being open on the node's session. */
    static final Stage OPEN = new Stage();
    /** Stream open to the node's first byte arriving, which is its TLS handshake answering. */
    static final Stage REPLY = new Stage();
    /**
     * Accept to the visitor's first byte, end to end. The one a visitor feels, and the one to
     * compare against the four above: a gap between it and their sum is time spent in no stage at
     * all, which is scheduling, queueing or a pause, and is invisible to every stage timer.
     */
    static final Stage FIRST_BYTE = new Stage();

    private RelayStages() {
    }

    /** A total and a high-water mark. Nanos inside, seconds on the way out. */
    static final class Stage {
        private final LongAdder nanos = new LongAdder();
        private final AtomicLong maxNanos = new AtomicLong();

        void record(long elapsedNanos) {
            if (elapsedNanos <= 0) {
                return;
            }
            nanos.add(elapsedNanos);
            // A high-water mark; racing writers can only under-report, which is the same bargain
            // NodeGroup makes for its signing peak.
            long seen = maxNanos.get();
            if (elapsedNanos > seen) {
                maxNanos.compareAndSet(seen, elapsedNanos);
            }
        }

        double totalSeconds() {
            return nanos.sum() / 1e9;
        }

        double maxSeconds() {
            return maxNanos.get() / 1e9;
        }
    }
}
