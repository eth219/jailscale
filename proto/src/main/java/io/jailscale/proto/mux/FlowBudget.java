package io.jailscale.proto.mux;

import io.jailscale.proto.util.Log;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

/**
 * How many bytes may sit in receive queues across every {@link MuxSession} sharing this budget
 * (ARCHITECTURE.md §5.3).
 *
 * <p>Per-stream flow control bounds one stream and says nothing about their sum. {@link
 * MuxStream#WINDOW} plus a frame is 272 KiB, the hub admits 1,024 visitors per name with no global
 * cap, and the product is 272 MB against a 96 MB heap ceiling. A visitor who reads its download
 * slowly makes the hub hold those bytes, and needs no registration and no authentication to do it.
 *
 * <p>What that costs was measured on the native binaries rather than argued from the arithmetic, and
 * the honest version of it is hedged twice. Under a high enough arrival rate the hub <em>can</em>
 * exhaust its heap; the {@code OutOfMemoryError} then surfaces on whichever thread allocates next,
 * and in the one run that produced it that was the thread carrying a node's control connection,
 * whose death runs the teardown in {@code NodeGroup.detach} -- taking the whole node session with
 * every link and visitor on it, after which the node reconnects a second later.
 *
 * <p>Both hedges are load-bearing. It fired once in three identical attempts, in the one with the
 * fastest ramp, and ramp time tracked the hub's peak inversely across all three -- 144s/134.8 MB,
 * 176s/121.4 MB, 218s/114.1 MB. <b>Quote the ramp time next to any peak from this axis</b>, or the
 * three runs read as unexplained 20 MB scatter. That is the same effect as 120 visitors arriving in
 * half a second filling this budget where 300 spread over 25s do not: what fills the queues is
 * arrival rate, not visitor count. The like-for-like pair is the evidence -- at a 148s ramp, three
 * percent off the run that died, the bounded hub reached 112.3 MB with its queue pinned here and 73
 * streams shed, where the unbounded one reached 134.8 and lost the session. And which thread the
 * error lands on is chance as well; a visitor thread would have cost one visitor. Whether it fires
 * and what it takes are both a lottery, which argues for bounding it rather than for waiting on a
 * cleaner repro.
 *
 * <p><b>Reclaiming is not what makes a loaded hub slow.</b> Worth recording, because the obvious
 * suspicion about a scan that runs on a reader thread is that it stalls one. With this budget
 * completely full and reclaim actively running, an ordinary visitor was served in 4 to 153 ms; at
 * ten times the load, with the budget in the same state and the same reclaim activity, ordinary
 * visitors saw 8 to 19 <em>seconds</em> during the ramp and 238 to 576 ms once it finished. The
 * difference between those two is the node saturating on its own per-visitor TLS state, not
 * anything here -- an unbounded hub showed worse outliers still, 14.0 s and 10.6 s. The long tail
 * on this axis belongs to {@code TlsEndpoint}, and is not this budget's to answer.
 *
 * <p>Two things about that measurement belong next to it, because without them it does not
 * reproduce. It needed {@code -XX:MaxHeapSize=768m} on the *node*: at the shipped 64m the node's own
 * per-visitor TLS state saturates first, the hub's queues stop at a fraction of this budget, and
 * nothing breaks -- which is why this axis read as harmless every time it was measured without that,
 * and why the queue gauge rather than peak RSS is the number to trust (peak RSS on the hub varies by
 * 2x run to run, Serial GC not returning the heap). And it demonstrated every name on one node; the
 * cross-node case follows from the heap being shared but has not been measured.
 *
 * <p><b>It is a byte bound and not a connection count on purpose.</b> Deriving a count from it
 * would have to assume the worst case per connection -- the full 272 KiB -- and would cap the hub
 * at a few hundred visitors. What it actually serves is a thousand who each hold almost nothing,
 * because they read what they asked for. The scarce resource is bytes, so the limit is in bytes,
 * enforced where the bytes arrive.
 *
 * <p><b>Over the limit the receiver reclaims rather than refuses.</b> It resets the stream holding
 * the most bytes among those that have gone {@link #STALL_MS} without consuming any. That
 * separates the two cases cleanly: a slow reader on a bad connection still consumes every few
 * milliseconds, a stalled one never does, so a stream making progress is essentially never chosen.
 * Refusing new streams instead would hand an attacker a cheaper denial than the one being fixed --
 * fill the budget and nobody else gets in -- and would not free the bytes already held.
 *
 * <p><b>Nothing is advertised on the wire.</b> RST is already in the protocol and a receiver may
 * send one whenever it likes, so the sender's credits are untouched and a node running an older
 * build needs no upgrade for this to protect the hub. Shrinking {@link MuxStream#WINDOW} instead
 * would have cost throughput, and telling the peer about a smaller window would have been a flag
 * day for every node at once.
 */
public final class FlowBudget {

    private static final Log LOG = Log.get("budget");

    /** How long a stream must go without consuming anything before reclaim prefers it. */
    static final long STALL_MS = 2_000;
    /**
     * The share of the heap ceiling that may sit in receive queues. A quarter of the hub's 96m is
     * 24 MB, which is about ninety fully stalled streams -- far more than legitimate traffic ever
     * holds at once, and a quarter of the heap is what is left for everything else.
     */
    static final int HEAP_SHARE = 4;
    /** Small heaps still get a workable budget; below this the multiplexer cannot do useful work. */
    static final long FLOOR_BYTES = 4L * 1024 * 1024;
    /** Resets one arriving frame may trigger, so a frame cannot turn into unbounded work. */
    private static final int MAX_RECLAIM_PER_FRAME = 64;

    private final long limit;
    private final AtomicLong used = new AtomicLong();
    private final LongAdder reclaimed = new LongAdder();
    private final Set<MuxSession> sessions = ConcurrentHashMap.newKeySet();
    private volatile long peak;

    private FlowBudget(long limit) {
        this.limit = limit;
    }

    /**
     * A quarter of this process's heap ceiling. Derived and not a constant of its own, because the
     * pair of constants that produced the overrun -- a per-stream window and a per-name connection
     * count -- were each chosen without reference to the heap they share. A host that raises
     * {@code -XX:MaxHeapSize=} raises this with it, which is the escape hatch ARCHITECTURE.md §12
     * already documents.
     */
    public static FlowBudget ofHeap() {
        long max = Runtime.getRuntime().maxMemory();
        // No ceiling set: maxMemory is then the collector's own guess and not a promise anyone
        // keeps, so deriving a share of it would be deriving from a number nobody enforces.
        long limit = max == Long.MAX_VALUE ? FLOOR_BYTES : Math.max(FLOOR_BYTES, max / HEAP_SHARE);
        return new FlowBudget(limit);
    }

    /** An explicit limit, for tests and for a host that wants to say the number itself. */
    public static FlowBudget of(long limitBytes) {
        if (limitBytes <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        return new FlowBudget(limitBytes);
    }

    /** No bound. For tests that are measuring something else, and for the measurement harnesses. */
    public static FlowBudget unlimited() {
        return new FlowBudget(Long.MAX_VALUE);
    }

    public long limitBytes() {
        return limit;
    }

    public long usedBytes() {
        return used.get();
    }

    /** The most that has ever been held at once. A high-water mark; racing writers under-report. */
    public long peakBytes() {
        return peak;
    }

    /** Streams reset because this budget was full. Zero on a hub nobody is pushing. */
    public long reclaimedStreams() {
        return reclaimed.sum();
    }

    /** Sessions sharing this budget right now. Tests assert the wiring; nothing else needs it. */
    public int sessionCount() {
        return sessions.size();
    }

    void register(MuxSession s) {
        sessions.add(s);
    }

    void unregister(MuxSession s) {
        sessions.remove(s);
    }

    /**
     * Counts bytes about to enter a receive queue, reclaiming if they put this over the limit.
     * Called on the session reader thread, before the payload is queued, so the total can exceed
     * the limit by at most the frame in hand per reader.
     */
    void acquire(int n) {
        long now = used.addAndGet(n);
        if (now > peak) {
            peak = now;
        }
        if (now > limit) {
            reclaim();
        }
    }

    void release(long n) {
        if (n > 0) {
            used.addAndGet(-n);
        }
    }

    /**
     * Resets stalled streams until the total is back under the limit. Only ever runs under
     * pressure, which is why walking every stream is affordable here and the common path is one
     * atomic add.
     */
    private void reclaim() {
        for (int i = 0; i < MAX_RECLAIM_PER_FRAME && used.get() > limit; i++) {
            MuxStream victim = victim();
            if (victim == null) {
                // Everything is either empty or already gone: the bytes counted here are in a
                // reader's hands and will be released without anyone being reset.
                return;
            }
            long freed = victim.reclaim();
            reclaimed.increment();
            LOG.warn("receive budget full ({} of {} bytes): reset stream {}, freeing {}",
                used.get() + freed, limit, victim.id(), freed);
        }
    }

    /**
     * The stream to give up: the fullest one that has stopped consuming, or failing that the
     * fullest one at all. The second case only happens when every queue is draining, and something
     * still has to go, or the caller would queue bytes it has no room for.
     */
    private MuxStream victim() {
        long now = System.currentTimeMillis();
        MuxStream stalled = null;
        long stalledBytes = 0;
        MuxStream fullest = null;
        long fullestBytes = 0;
        for (MuxSession s : sessions) {
            for (MuxStream m : s.streamsView()) {
                long queued = m.queuedBytes();
                if (queued <= 0) {
                    continue;
                }
                if (queued > fullestBytes) {
                    fullest = m;
                    fullestBytes = queued;
                }
                if (now - m.lastConsumedAt() >= STALL_MS && queued > stalledBytes) {
                    stalled = m;
                    stalledBytes = queued;
                }
            }
        }
        return stalled != null ? stalled : fullest;
    }

    @Override
    public String toString() {
        return "FlowBudget[used=" + used.get() + " peak=" + peak + " limit=" + limit
            + " reclaimed=" + reclaimed.sum() + "]";
    }
}
