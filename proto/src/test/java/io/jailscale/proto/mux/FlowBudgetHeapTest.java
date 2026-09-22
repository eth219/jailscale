package io.jailscale.proto.mux;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Whether {@link FlowBudget}'s gauge corresponds to the heap the process actually retains: when it
 * says 24 MB, whether the live set moved by 24 MB or by 40.
 *
 * <p>{@link FlowBudgetTest} checks the counter <b>against itself</b> -- the bounded run stops where
 * the limit says and the unbounded one does not -- which is the invariant and not the
 * correspondence. A gauge that counted half of what it queued would satisfy every assertion there
 * and would leave the hub's derived 24 MB bound holding 48. Nothing else covers this either:
 * {@code measure.sh} reports RSS, which varies by 2x on this axis and includes everything that is
 * not heap.
 *
 * <p><b>The method is two-point, and that is what makes it a test rather than a reading.</b> An
 * absolute number would be the queues plus the rig -- two sessions, two sockets, the Noise state,
 * the stream objects -- and asserting on that would be asserting on the rig. So
 * {@link #retainedHeapTracksTheGauge()} fills the same streams on the same rig to two depths and
 * compares the <em>slopes</em>: every fixed cost is in both measurements and cancels, and what is
 * left is the bytes. That is why the tolerance can be ±20% around 1.0 while the errors it exists to
 * catch are factors of two.
 *
 * <p><b>It fails in both directions, and that was run and not reasoned.</b> Queue a payload of
 * twice the length {@code MuxStream.onData} charges for -- the charge and the window accounting
 * untouched, so only the retained bytes move -- and the measured 1.00 becomes 2.00; queue half and
 * it becomes 0.50. Each trips its own assertion, and the doubled one also fails
 * {@link #theBoundHoldsInRetainedHeapAndNotOnlyInTheGauge()}, at 7.0 MB against a 3 MiB limit.
 *
 * <p><b>What it does not cover.</b>
 *
 * <ul>
 *   <li><b>Small frames, which is where the correspondence actually breaks.</b> The gauge charges
 *       the payload and not the {@code byte[]} that carries it, so the ratio measured here at
 *       {@link Frame#MAX_DATA} is 1.00 (1.03 in the smaller rig that measured the rest), at
 *       64-byte frames 1.40, at 8-byte frames 3.86 and at one-byte frames 30.3. That is
 *       <a href="https://github.com/eth219/jailscale/issues/154">#154</a>, and these tests assert
 *       the full-frame case on purpose: asserting the others would freeze the ratio that issue
 *       exists to change.
 *   <li><b>Anything that is not a receive queue.</b> A node's residency on this axis is mostly
 *       {@code TlsEndpoint}'s per-visitor buffers and {@code SSLEngine} (ARCHITECTURE.md §15), not
 *       queues at all. This measures the gauge against the thing the gauge is counting; it does not
 *       balance a process.
 *   <li><b>The binaries that ship.</b> This is a JVM heap on Temurin 25.0.4.1, read through
 *       {@code MemoryMXBean} after a forced collection. It says the accounting is right -- the
 *       counter matches the queues it counts -- and says nothing about what a native image holds
 *       for the same queues. CLAUDE.md's fourth rule is about exactly this reading.
 * </ul>
 */
@Timeout(120)
class FlowBudgetHeapTest {

    private static final byte[] PROLOGUE = "t".getBytes();

    /** Enough that the queues dominate the per-stream overhead, few enough to stay under a minute. */
    private static final int STREAMS = 48;
    /** The two depths of the slope measurement: an eighth of the window, and the whole window. */
    private static final int LOW = 32 * 1024;
    private static final int HIGH = MuxStream.WINDOW;
    /**
     * The bound under test. Small against what {@link #STREAMS} streams can hold at a full window
     * -- 12 MiB -- so the bounded and unbounded runs are told apart by a factor and not a margin.
     */
    private static final long LIMIT = 3L * 1024 * 1024;
    /** Offered per stream in the bounded runs: twice the window, so every writer runs out of credit. */
    private static final int OFFERED = 512 * 1024;
    /**
     * What the bounded run may retain, as a multiple of the limit. Measured at 1.16 -- the queues
     * plus the stream objects reclaim left behind -- against 4.08 for the same load with no budget,
     * so the threshold has a factor on either side of it and is not a tuned margin.
     */
    private static final double BOUNDED_HEAP = 2.0;

    /**
     * The correspondence. Same rig, same streams, two queue depths: the heap has to move by what
     * the gauge says it moved by.
     */
    @Test
    void retainedHeapTracksTheGauge() throws Exception {
        try (Rig r = new Rig(FlowBudget.unlimited())) {
            List<MuxStream> streams = r.open(STREAMS);

            r.push(streams, LOW);
            long gaugeLow = r.awaitGauge((long) STREAMS * LOW);
            long heapLow = usedHeap();

            r.push(streams, HIGH - LOW);
            long gaugeHigh = r.awaitGauge((long) STREAMS * HIGH);
            long heapHigh = usedHeap();

            // Exact, not approximate: nothing was reclaimed and nothing was read, so the gauge is
            // the offered bytes. If this drifts the rig stopped doing what the slope assumes.
            assertEquals((long) STREAMS * LOW, gaugeLow,
                "the low point did not come to rest where it was offered");
            assertEquals((long) STREAMS * HIGH, gaugeHigh,
                "the high point did not come to rest where it was offered");

            long gaugeMoved = gaugeHigh - gaugeLow;
            long heapMoved = heapHigh - heapLow;
            double ratio = heapMoved / (double) gaugeMoved;
            String seen = "the gauge moved " + gaugeMoved + " and the heap moved " + heapMoved
                + " (ratio " + String.format(Locale.ROOT, "%.2f", ratio) + ")";
            assertTrue(ratio <= 1.2, "the process retains more than the budget is counting: " + seen);
            assertTrue(ratio >= 0.8, "the budget is counting bytes the process does not retain: " + seen);
        }
    }

    /**
     * The bound, in the units that matter. {@link FlowBudgetTest#stalledStreamsStopAtTheBudget()}
     * asserts that the gauge stops at the limit; this asserts that stopping the gauge stopped the
     * heap, which is the claim §5.3 actually makes for the hub.
     */
    @Test
    void theBoundHoldsInRetainedHeapAndNotOnlyInTheGauge() throws Exception {
        try (Rig r = new Rig(FlowBudget.of(LIMIT))) {
            Load load = retainedUnderLoad(r);
            // Without this the test passes on a run where the writers never started: nothing
            // queued is nothing retained, and the bound would be reading its own absence.
            assertTrue(r.budget.reclaimedStreams() > 0,
                "nothing was reclaimed, so the budget was never reached and the bound was not tested");
            assertTrue(load.retained() <= BOUNDED_HEAP * LIMIT,
                "the gauge stopped at " + LIMIT + " and the heap still grew by " + load.retained());
        }
    }

    /**
     * The falsification. Identical load, no budget: the same measurement has to read far higher, or
     * the bounded run is measuring the offered bytes running out rather than the budget.
     */
    @Test
    void withoutABudgetTheSameLoadRetainsFarMore() throws Exception {
        try (Rig r = new Rig(FlowBudget.unlimited())) {
            Load load = retainedUnderLoad(r);
            // The same guard from the other side: every window full is what "the same load" means.
            assertEquals((long) STREAMS * HIGH, load.gauge(),
                "the windows did not fill, so this is not the load the bounded run was given");
            assertTrue(load.retained() > BOUNDED_HEAP * LIMIT,
                "only " + load.retained() + " came to rest without a budget, so the bounded run "
                    + "proves nothing");
        }
    }

    /**
     * Heap growth from {@link #STREAMS} stalled streams offered {@link #OFFERED} bytes each, and
     * the gauge as it stood when that growth was read -- not re-read afterwards, so a caller
     * asserting on it is asserting about the state the heap figure came from.
     */
    private Load retainedUnderLoad(Rig r) throws Exception {
        List<MuxStream> streams = r.open(STREAMS);
        // Measured with the streams open and empty, so what the comparison sees is queued bytes
        // and not the cost of having streams at all.
        long before = usedHeap();
        r.push(streams, OFFERED);
        long gauge = r.awaitGauge((long) STREAMS * HIGH); // the bounded run settles below it
        return new Load(usedHeap() - before, gauge);
    }

    /** What one loaded run produced: the heap it grew by, and the gauge at that moment. */
    private record Load(long retained, long gauge) {}

    /** The live set, after giving the collector enough turns to reach a stable answer. */
    private static long usedHeap() throws Exception {
        for (int i = 0; i < 5; i++) {
            System.gc();
            Thread.sleep(120);
        }
        return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
    }

    // --- harness ---------------------------------------------------------------------------

    /**
     * A sender with no budget and a receiver with the one under test, as in {@link FlowBudgetTest}.
     * The receiver accepts every stream and reads none of them -- the stalled local app -- so the
     * bytes come to rest in its inbound queues, which is the only place this budget counts.
     */
    private static final class Rig implements AutoCloseable {
        private final MuxSession sender;
        private final MuxSession receiver;
        private final FlowBudget budget;
        /**
         * Held so the queues stay reachable; without this the measurement is of the collector.
         * Concurrent because {@code onOpen} runs on the receiver's reader thread and {@link #open}
         * polls the size from the test thread.
         */
        private final List<MuxStream> held = new CopyOnWriteArrayList<>();
        private final ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
        /** The first writer to die of something other than backpressure; asserted after each push. */
        private final AtomicReference<RuntimeException> writerFailure = new AtomicReference<>();
        private final List<Socket> sockets;

        Rig(FlowBudget budget) throws Exception {
            this.budget = budget;
            Wire w = wire();
            this.sockets = w.sockets();
            this.sender = new MuxSession(w.senderCh(), true, listener(null), FlowBudget.unlimited());
            this.receiver = new MuxSession(w.receiverCh(), false, listener(held), budget);
            sender.start();
            receiver.start();
        }

        private static MuxSession.Listener listener(List<MuxStream> sink) {
            return new MuxSession.Listener() {
                @Override public void onControl(MuxSession s, byte[] json) {}

                @Override public void onOpen(MuxSession s, MuxStream stream) {
                    if (sink != null) {
                        sink.add(stream);
                    }
                }

                @Override public void onClosed(MuxSession s, Throwable cause) {}
            };
        }

        List<MuxStream> open(int n) throws Exception {
            List<MuxStream> streams = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                streams.add(sender.open(JsonObject.builder().put("sni", "x" + i).build()));
            }
            // Opened, accepted and empty before anything is measured: an OPEN still in flight would
            // land its stream between the two heap readings and show up as queued bytes.
            for (int i = 0; i < 100 && held.size() < n; i++) {
                Thread.sleep(50);
            }
            assertEquals(n, held.size(), "the receiver never accepted every stream");
            return streams;
        }

        /**
         * Offers {@code bytes} more on each stream, in full frames, and waits for them to settle.
         *
         * <p><b>One chunk for every writer, and that is part of the measurement.</b>
         * {@code MuxStream.write} copies out of it, so sharing a buffer nobody mutates is safe --
         * and a buffer per writer is not, because a writer blocked on credits holds its buffer
         * alive. At 48 writers that put 768 KiB of harness into the reading: the unbounded run's
         * excess over the gauge was 1,028,504 bytes with a buffer each and is 266,232 with one
         * shared, so three quarters of what looked like queue overhead was this.
         */
        void push(List<MuxStream> streams, int bytes) throws Exception {
            AtomicLong written = new AtomicLong();
            byte[] chunk = new byte[Frame.MAX_DATA];
            for (MuxStream s : streams) {
                ex.submit(() -> {
                    try {
                        for (int off = 0; off < bytes; off += chunk.length) {
                            s.out().write(chunk);
                            written.addAndGet(chunk.length);
                        }
                    } catch (IOException e) {
                        // out of credits for good, or reset: either way this writer is done
                    } catch (RuntimeException e) {
                        // Anything else is the harness breaking. Without this it vanishes into the
                        // Future nobody reads, and the run reports a heap figure for a load that
                        // never happened.
                        writerFailure.compareAndSet(null, e);
                    }
                });
            }
            settle(written);
            RuntimeException failed = writerFailure.get();
            if (failed != null) {
                throw new AssertionError("a writer died, so nothing here measured the load", failed);
            }
        }

        /**
         * The gauge once it has reached {@code expected}, or once it has stopped moving for a
         * second -- which is the bounded runs, where it comes to rest below {@code expected} and
         * waiting for that value would be waiting for the timeout.
         *
         * <p>{@link #settle} says the writers stopped, which on a loaded machine can be one writer
         * starved rather than every writer blocked, and the reader thread lags the last write in
         * any case. The caller asserts the value, so a gauge that never arrives fails there with
         * the number it reached rather than hanging.
         */
        long awaitGauge(long expected) throws InterruptedException {
            long last = -1;
            for (int i = 0, quiet = 0; i < 300 && quiet < 10; i++) {
                long now = budget.usedBytes();
                if (now == expected) {
                    return now;
                }
                quiet = now == last ? quiet + 1 : 0;
                last = now;
                Thread.sleep(100);
            }
            return budget.usedBytes();
        }

        /** Waits until no writer has made progress for a second: everyone is blocked or finished. */
        private static void settle(AtomicLong written) throws InterruptedException {
            long last = -1;
            for (int quiet = 0; quiet < 10;) {
                Thread.sleep(100);
                long now = written.get();
                quiet = now == last ? quiet + 1 : 0;
                last = now;
            }
        }

        // Every step runs even if an earlier one throws: a session that fails to close would
        // otherwise strand the sockets, and this rig is built three times in one forked JVM.
        @Override
        public void close() throws IOException {
            try (sender; receiver) {
                ex.shutdownNow();
            } finally {
                for (Socket s : sockets) {
                    s.close();
                }
            }
        }
    }

    private record Wire(List<Socket> sockets, NoiseChannel senderCh, NoiseChannel receiverCh) {}

    private static Wire wire() throws Exception {
        X25519.Keypair hk = X25519.generate();
        X25519.Keypair nk = X25519.generate();
        Socket a;
        Socket b;
        try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            a = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
            b = ss.accept();
        }
        ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
        Future<NoiseChannel> respond = ex.submit(() -> NoiseChannel.respond(
            b.getInputStream(), b.getOutputStream(), NoiseIk.responder(PROLOGUE, hk), (p, hs) -> new byte[0]));
        NoiseChannel initiate = NoiseChannel.initiate(a.getInputStream(), a.getOutputStream(),
            NoiseIk.initiator(PROLOGUE, nk, hk.publicKey()), null);
        Wire w = new Wire(List.of(a, b), respond.get(), initiate);
        ex.shutdown();
        return w;
    }
}
