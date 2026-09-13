package io.jailscale.proto.mux;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The bound on what stalled readers can make a receiver hold (ARCHITECTURE.md §5.3).
 *
 * <p>Every test here drives the same load -- streams whose receiver accepts them and never reads a
 * byte, senders pushing until their credits run out -- and changes only the budget. That is
 * deliberate: {@link #withoutABudgetTheSameLoadGrowsPastIt()} is the falsification, and if it ever
 * passes the assertions of the bounded tests then something other than the budget is holding the
 * total down and these tests are measuring that something instead.
 */
@Timeout(120)
class FlowBudgetTest {

    private static final byte[] PROLOGUE = "t".getBytes();
    /** Four stalled streams' worth, so reclaim has to run and has somewhere to stop. */
    private static final long LIMIT = 1024 * 1024;
    private static final int PER_STREAM = 512 * 1024;
    private static final int STALLED_STREAMS = 24;

    @Test
    void stalledStreamsStopAtTheBudget() throws Exception {
        try (Rig r = rig(FlowBudget.of(LIMIT))) {
            r.pushStalled(STALLED_STREAMS, PER_STREAM);

            // Offered 24 * 512 KiB; a receiver with no bound would be holding 24 * 272 KiB of it.
            // One frame of slack: the budget is charged before the queue takes the payload, so a
            // reader can be holding one 16 KiB frame that is counted and not yet queued.
            assertTrue(r.budget.usedBytes() <= LIMIT + Frame.MAX_DATA,
                "held " + r.budget.usedBytes() + " against a budget of " + LIMIT);
            assertTrue(r.budget.reclaimedStreams() > 0, "nothing was reclaimed, so nothing was bounded");
            assertFalse(r.receiver.isClosed(), "the session died instead of giving up a stream");
            assertFalse(r.receiverClosed.isDone(), "the receiver reported the session closed");
        }
    }

    /**
     * The falsification. Identical load, no budget: the total must run far past the limit the
     * bounded test asserts, or that test is not testing the budget.
     */
    @Test
    void withoutABudgetTheSameLoadGrowsPastIt() throws Exception {
        try (Rig r = rig(FlowBudget.unlimited())) {
            r.pushStalled(STALLED_STREAMS, PER_STREAM);

            assertTrue(r.budget.usedBytes() > 4 * LIMIT,
                "only " + r.budget.usedBytes() + " came to rest, so the bounded run proves nothing");
            assertEquals(0, r.budget.reclaimedStreams(), "an unlimited budget reclaimed something");
        }
    }

    /**
     * Reclaim takes the stalled stream, not the busy one. The stalled streams are given their
     * {@link FlowBudget#STALL_MS} before the draining one starts, so this asserts the preference
     * rule itself and not a race between two streams that both look idle.
     */
    @Test
    void aDrainingStreamOutlivesTheStalledOnes() throws Exception {
        try (Rig r = rig(FlowBudget.of(LIMIT))) {
            r.pushStalled(8, PER_STREAM);
            long reclaimedWhileStalling = r.budget.reclaimedStreams();
            Thread.sleep(FlowBudget.STALL_MS + 500); // now every survivor is provably stalled

            // 2 MiB through a stream that is being read, against a budget the stalled streams have
            // already filled: almost every frame arrives over the limit and has to reclaim.
            MuxStream drained = r.sender.open(JsonObject.builder().put("drain", true).build(), false);
            byte[] chunk = new byte[Frame.MAX_DATA];
            for (int i = 0; i < 2 * 1024 * 1024 / chunk.length; i++) {
                drained.out().write(chunk);
            }
            drained.close();

            assertTrue(r.budget.reclaimedStreams() > reclaimedWhileStalling,
                "the draining stream never put the budget under pressure, so nothing was chosen");
            // Waited for, not sampled: close() returns as soon as CLOSE is on the wire, so reading
            // the counter here instead would race the last frames still in flight.
            assertEquals(2L * 1024 * 1024, r.drained.get(30, TimeUnit.SECONDS),
                "the draining stream was cut short");
            assertFalse(r.receiver.isClosed(), "the session died");
        }
    }

    /**
     * The same thing again, drained by {@code MuxStream.writeTo} instead of {@code in().read}: the
     * relay's zero-copy path (ARCHITECTURE.md §15) has to hold up under the same pressure, with the
     * budget full and every arriving frame forcing a reclaim.
     *
     * <p>It does <b>not</b> stand in for {@code lastConsumedAt}, which is what it was first written
     * to cover: removing that line from the new path leaves this test green, because the victim is
     * the fullest stalled stream and a stream being drained this fast is never the fullest whatever
     * its timestamp says. {@link #writeToKeepsTheStreamOffTheStalledList} asserts it where it can
     * actually fail.
     */
    @Test
    void aStreamDrainedWithWriteToOutlivesTheStalledOnes() throws Exception {
        try (Rig r = rig(FlowBudget.of(LIMIT), true)) {
            r.pushStalled(8, PER_STREAM);
            long reclaimedWhileStalling = r.budget.reclaimedStreams();
            Thread.sleep(FlowBudget.STALL_MS + 500);

            MuxStream drained = r.sender.open(JsonObject.builder().put("drain", true).build(), false);
            byte[] chunk = new byte[Frame.MAX_DATA];
            for (int i = 0; i < 2 * 1024 * 1024 / chunk.length; i++) {
                drained.out().write(chunk);
            }
            drained.close();

            assertTrue(r.budget.reclaimedStreams() > reclaimedWhileStalling,
                "the draining stream never put the budget under pressure, so nothing was chosen");
            assertEquals(2L * 1024 * 1024, r.drained.get(30, TimeUnit.SECONDS),
                "the draining stream was cut short");
            assertFalse(r.receiver.isClosed(), "the session died");
        }
    }

    /**
     * {@code writeTo} has to mark the stream as having consumed something, or the victim scan reads
     * it as stalled. The scan wants both -- stalled <em>and</em> fullest -- so a drained stream is
     * usually saved by being empty rather than by its timestamp, and only a direct assertion fails
     * when the timestamp is the thing that is missing.
     */
    @Test
    void writeToKeepsTheStreamOffTheStalledList() throws Exception {
        try (Rig r = rig(FlowBudget.of(LIMIT), true)) {
            // No `drain` in the metadata, so the rig holds this one and reads nothing: this test is
            // the only consumer, which is what the one-drainer rule requires.
            MuxStream sent = r.sender.open(JsonObject.builder().put("sni", "timestamp").build(), false);
            MuxStream received = null;
            for (int i = 0; i < 100 && received == null; i++) {
                received = r.held.isEmpty() ? null : r.held.get(0);
                if (received == null) {
                    Thread.sleep(50);
                }
            }
            assertNotNull(received, "the receiver never saw the stream");

            Thread.sleep(FlowBudget.STALL_MS + 300);
            assertTrue(System.currentTimeMillis() - received.lastConsumedAt() >= FlowBudget.STALL_MS,
                "it should look stalled before anything is drained");

            sent.out().write(new byte[Frame.MAX_DATA]);
            assertEquals(Frame.MAX_DATA, received.writeTo(java.io.OutputStream.nullOutputStream()));

            assertTrue(System.currentTimeMillis() - received.lastConsumedAt() < FlowBudget.STALL_MS,
                "writeTo moved bytes without recording that it had, so the scan still reads this "
                    + "stream as stalled: " + received.flowState());
            sent.close();
        }
    }

    /**
     * The reason the relay drains this way, and it is not speed: **bytes waiting on a slow visitor
     * stay charged to the budget.** {@code in().read} hands them to the caller and releases them at
     * that moment, so they sit in the caller's buffer, still held, still costing the process memory,
     * and invisible to the bound -- one buffer per stalled visitor, which is megabytes at the
     * concurrency this budget exists to survive. {@code writeTo} keeps the chunk queued and charged
     * until the socket has taken it.
     */
    @Test
    void bytesWaitingOnASlowSinkStayChargedToTheBudget() throws Exception {
        try (Rig r = rig(FlowBudget.of(LIMIT), true)) {
            MuxStream sent = r.sender.open(JsonObject.builder().put("sni", "slowsink").build(), false);
            MuxStream received = null;
            for (int i = 0; i < 100 && received == null; i++) {
                received = r.held.isEmpty() ? null : r.held.get(0);
                if (received == null) {
                    Thread.sleep(50);
                }
            }
            assertNotNull(received);
            sent.out().write(new byte[Frame.MAX_DATA]);
            for (int i = 0; i < 100 && r.budget.usedBytes() < Frame.MAX_DATA; i++) {
                Thread.sleep(50);
            }
            long charged = r.budget.usedBytes();
            assertEquals(Frame.MAX_DATA, charged, "the chunk should be on the budget before anyone drains it");

            // A sink that has stopped taking bytes: exactly the visitor this budget is about.
            CountDownLatch writing = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            MuxStream target = received;
            Thread drainer = Thread.ofVirtual().start(() -> {
                try {
                    target.writeTo(new java.io.OutputStream() {
                        @Override
                        public void write(byte[] b, int off, int len) throws IOException {
                            writing.countDown();
                            try {
                                release.await(30, TimeUnit.SECONDS);
                            } catch (InterruptedException e) {
                                throw new IOException(e);
                            }
                        }

                        @Override
                        public void write(int b) {
                        }
                    });
                } catch (IOException e) {
                    // the stream went while we were parked; the assertion below is what matters
                }
            });
            assertTrue(writing.await(10, TimeUnit.SECONDS), "the drain never reached the sink");
            assertEquals(charged, r.budget.usedBytes(),
                "the bytes were released while the sink still had not taken them, so the budget is "
                    + "short by what every stalled visitor is holding");

            release.countDown();
            drainer.join(TimeUnit.SECONDS.toMillis(30));
            for (int i = 0; i < 100 && r.budget.usedBytes() > 0; i++) {
                Thread.sleep(50);
            }
            assertEquals(0, r.budget.usedBytes(), "and released once the sink had them");
            sent.close();
        }
    }

    /**
     * A peer that sends past its window loses that stream and keeps the session. The session is
     * every other visitor on that node (§5.3), which is why this is not fatal.
     */
    @Test
    void aWindowOverrunCostsTheStreamAndNotTheSession() throws Exception {
        try (RawRig r = rawRig()) {
            r.overrun(1);

            Frame rst = r.awaitReset(1);
            assertNotNull(rst, "the receiver did not reset the overrunning stream");
            assertEquals(Frame.RST_WINDOW_OVERRUN, rst.payload()[0] & 0xff);
            assertFalse(r.receiver.isClosed(), "one overrun took the whole session down");

            // Still serving: a fresh stream on the same session is accepted.
            r.write(new Frame(3, Frame.OPEN, 0, "{}".getBytes()));
            assertNotNull(r.accepted.poll(5, TimeUnit.SECONDS), "the session stopped accepting streams");
        }
    }

    @Test
    void repeatedWindowOverrunsEndTheSession() throws Exception {
        try (RawRig r = rawRig()) {
            for (int i = 0; i <= MuxSession.MAX_WINDOW_OVERRUNS; i++) {
                r.overrun(1 + 2L * i);
            }
            assertNotNull(r.receiverClosed.get(30, TimeUnit.SECONDS),
                "a peer that never honours the window kept its session");
        }
    }

    // --- harness ---------------------------------------------------------------------------

    /**
     * A sender with no budget and a receiver with the one under test. The receiver holds every
     * stream it is given and reads nothing, except a stream whose OPEN metadata says {@code drain},
     * which it reads as fast as it arrives: the stalled local app and the healthy one.
     */
    private final class Rig implements AutoCloseable {
        private final MuxSession sender;
        private final MuxSession receiver;
        private final FlowBudget budget;
        private final CompletableFuture<Throwable> receiverClosed = new CompletableFuture<>();
        private final AtomicLong drainedBytes = new AtomicLong();
        /** Completes with the total at EOF, or exceptionally if the stream was reset under us. */
        private final CompletableFuture<Long> drained = new CompletableFuture<>();
        private final List<MuxStream> held = new ArrayList<>();
        private final ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
        private final List<Socket> sockets;

        /** Whether the draining stream is read with {@code writeTo} rather than {@code in().read}. */
        private boolean zeroCopy;

        Rig(FlowBudget budget, List<Socket> sockets, NoiseChannel senderCh, NoiseChannel receiverCh) {
            this.budget = budget;
            this.sockets = sockets;
            this.sender = new MuxSession(senderCh, true, new MuxSession.Listener() {
                @Override public void onControl(MuxSession s, byte[] json) {}

                @Override public void onOpen(MuxSession s, MuxStream stream) {}

                @Override public void onClosed(MuxSession s, Throwable cause) {}
            }, FlowBudget.unlimited());
            this.receiver = new MuxSession(receiverCh, false, new MuxSession.Listener() {
                @Override public void onControl(MuxSession s, byte[] json) {}

                @Override public void onOpen(MuxSession s, MuxStream stream) {
                    if (stream.meta().optBool("drain", false)) {
                        ex.submit(() -> drain(stream));
                    } else {
                        held.add(stream); // never read: the stalled local app
                    }
                }

                @Override public void onClosed(MuxSession s, Throwable cause) {
                    receiverClosed.complete(cause == null ? new IOException("closed") : cause);
                }
            }, budget);
            sender.start();
            receiver.start();
        }

        private void drain(MuxStream stream) {
            byte[] buf = new byte[Frame.MAX_DATA];
            java.io.OutputStream sink = java.io.OutputStream.nullOutputStream();
            try {
                int n;
                while ((n = zeroCopy ? stream.writeTo(sink) : stream.in().read(buf)) >= 0) {
                    drainedBytes.addAndGet(n);
                }
                drained.complete(drainedBytes.get());
            } catch (IOException e) {
                // A reset lands here, which is what aDrainingStreamOutlivesTheStalledOnes denies:
                // the cause travels to the assertion rather than showing up as a short count.
                drained.completeExceptionally(e);
            }
        }

        /** Opens {@code n} streams the receiver will never read and offers each {@code bytes}. */
        void pushStalled(int n, int bytes) throws Exception {
            AtomicLong written = new AtomicLong();
            for (int i = 0; i < n; i++) {
                MuxStream s = sender.open(JsonObject.builder().put("sni", "x" + i).build(), false);
                ex.submit(() -> {
                    byte[] chunk = new byte[Frame.MAX_DATA];
                    try {
                        for (int off = 0; off < bytes; off += chunk.length) {
                            s.out().write(chunk);
                            written.addAndGet(chunk.length);
                        }
                    } catch (IOException e) {
                        // out of credits for good, or reset: either way this writer is done
                    }
                });
            }
            settle(written);
        }

        /** Waits until no writer has made progress for a second: everyone is blocked or finished. */
        private void settle(AtomicLong written) throws InterruptedException {
            long last = -1;
            for (int quiet = 0; quiet < 10;) {
                Thread.sleep(100);
                long now = written.get();
                quiet = now == last ? quiet + 1 : 0;
                last = now;
            }
        }

        // Narrower than AutoCloseable allows on purpose: nothing here interrupts, and declaring
        // Exception makes every try-with-resources warn that it might.
        @Override
        public void close() throws IOException {
            sender.close();
            receiver.close();
            ex.shutdownNow();
            for (Socket s : sockets) {
                s.close();
            }
        }
    }

    private Rig rig(FlowBudget budget, boolean zeroCopy) throws Exception {
        Rig r = rig(budget);
        r.zeroCopy = zeroCopy;
        return r;
    }

    private Rig rig(FlowBudget budget) throws Exception {
        Wire w = wire();
        return new Rig(budget, w.sockets, w.senderCh, w.receiverCh);
    }

    /**
     * The receiver as a real session, the sender as a bare channel, so this side can put frames on
     * the wire that a {@link MuxSession} would never produce.
     */
    private static final class RawRig implements AutoCloseable {
        private final NoiseChannel raw;
        private final MuxSession receiver;
        private final CompletableFuture<Throwable> receiverClosed = new CompletableFuture<>();
        private final LinkedBlockingQueue<MuxStream> accepted = new LinkedBlockingQueue<>();
        private final List<Socket> sockets;

        RawRig(List<Socket> sockets, NoiseChannel raw, NoiseChannel receiverCh) {
            this.sockets = sockets;
            this.raw = raw;
            this.receiver = new MuxSession(receiverCh, true, new MuxSession.Listener() {
                @Override public void onControl(MuxSession s, byte[] json) {}

                @Override public void onOpen(MuxSession s, MuxStream stream) {
                    accepted.add(stream); // never read, so no WINDOW frame ever comes back
                }

                @Override public void onClosed(MuxSession s, Throwable cause) {
                    receiverClosed.complete(cause == null ? new IOException("closed") : cause);
                }
            }, FlowBudget.unlimited());
            receiver.start();
        }

        void write(Frame f) throws Exception {
            raw.write(f);
        }

        /** Opens {@code id} and sends one frame more than the window it was granted. */
        void overrun(long id) throws Exception {
            write(new Frame(id, Frame.OPEN, 0, "{}".getBytes()));
            byte[] chunk = new byte[Frame.MAX_DATA];
            int frames = (MuxStream.WINDOW + Frame.MAX_DATA) / Frame.MAX_DATA + 1;
            for (int i = 0; i < frames; i++) {
                write(Frame.data(id, chunk));
            }
        }

        /** The next RST for {@code id}, skipping anything else the receiver sends. */
        Frame awaitReset(long id) throws Exception {
            for (int i = 0; i < 64; i++) {
                Frame f = raw.read();
                if (f == null) {
                    return null;
                }
                if (f.type() == Frame.RST && f.streamId() == id) {
                    return f;
                }
            }
            return null;
        }

        @Override
        public void close() throws IOException {
            receiver.close();
            for (Socket s : sockets) {
                s.close();
            }
        }
    }

    private RawRig rawRig() throws Exception {
        Wire w = wire();
        return new RawRig(w.sockets, w.senderCh, w.receiverCh);
    }

    private record Wire(List<Socket> sockets, NoiseChannel senderCh, NoiseChannel receiverCh) {}

    private static Wire wire() throws Exception {
        X25519.Keypair hk = X25519.generate();
        X25519.Keypair nk = X25519.generate();
        ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        Socket a = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
        Socket b = ss.accept();
        ss.close();
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
