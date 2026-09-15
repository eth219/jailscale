package io.jailscale.proto.mux;

import com.sun.management.HotSpotDiagnosticMXBean;
import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.json.JsonObject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Timeout(30)
class MuxSessionTest {

    private static final byte[] PROLOGUE = "t".getBytes();

    /** Two sessions over a loopback socket pair, hub side (even ids) and node side (odd ids). */
    private record Pair(MuxSession hub, MuxSession node, LinkedBlockingQueue<MuxStream> hubOpened,
        LinkedBlockingQueue<MuxStream> nodeOpened, LinkedBlockingQueue<byte[]> hubCtrl, LinkedBlockingQueue<byte[]> nodeCtrl,
        CompletableFuture<Throwable> hubClosed, CompletableFuture<Throwable> nodeClosed) {}

    /**
     * Every thread whose stack touches jailscale code, virtual ones included.
     * {@code Thread.getAllStackTraces()} lists platform threads only, and everything carrying a
     * stream here is virtual, so the first version of this reported "none" and taught us nothing.
     */
    private static String stacks() {
        try {
            Path dir = Files.createTempDirectory("threaddump");
            Path out = dir.resolve("threads.txt");
            ManagementFactory.getPlatformMXBean(HotSpotDiagnosticMXBean.class)
                .dumpThreads(out.toString(), HotSpotDiagnosticMXBean.ThreadDumpFormat.TEXT_PLAIN);
            StringBuilder b = new StringBuilder();
            for (String block : Files.readString(out).split("\n\n")) {
                if (block.contains("io.jailscale")) {
                    b.append("\n    ").append(block.strip().replace("\n", "\n    "));
                }
            }
            Files.deleteIfExists(out);
            Files.deleteIfExists(dir);
            return b.length() == 0 ? "none" : b.toString();
        } catch (Exception e) {
            return "unavailable: " + e;
        }
    }

    /**
     * Both sessions eventually drop every fully closed stream. "Eventually" is the guarantee:
     * {@code onClose} wakes the blocked reader inside the stream lock and only calls
     * {@code maybeRemove} after releasing it, so a reader can see -1 a few instructions before
     * the entry leaves the map. Asserting it the moment {@code read()} returns failed 6 times in
     * 240 runs. A real leak still fails here, just five seconds later.
     */
    private static void awaitNoStreams(Pair p) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5_000;
        while (System.currentTimeMillis() < deadline
            && (p.hub().streamCount() != 0 || p.node().streamCount() != 0)) {
            Thread.sleep(10);
        }
        assertEquals(0, p.hub().streamCount(), "hub kept a closed stream registered");
        assertEquals(0, p.node().streamCount(), "node kept a closed stream registered");
    }

    private static Pair pair() throws Exception {
        return pair(FlowBudget.unlimited());
    }

    private static Pair pair(FlowBudget budget) throws Exception {
        X25519.Keypair hk = X25519.generate();
        X25519.Keypair nk = X25519.generate();
        ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        Socket a = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
        Socket b = ss.accept();
        ss.close();
        ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
        Future<NoiseChannel> hubCh = ex.submit(() -> NoiseChannel.respond(b.getInputStream(), b.getOutputStream(),
            NoiseIk.responder(PROLOGUE, hk), (p, hs) -> new byte[0]));
        NoiseChannel nodeCh = NoiseChannel.initiate(a.getInputStream(), a.getOutputStream(), NoiseIk.initiator(PROLOGUE, nk, hk.publicKey()), null);
        LinkedBlockingQueue<MuxStream> ho = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<MuxStream> no = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> hc = new LinkedBlockingQueue<>();
        LinkedBlockingQueue<byte[]> nc = new LinkedBlockingQueue<>();
        CompletableFuture<Throwable> hcl = new CompletableFuture<>();
        CompletableFuture<Throwable> ncl = new CompletableFuture<>();
        MuxSession hub = new MuxSession(hubCh.get(), true, listener(ho, hc, hcl), FlowBudget.unlimited());
        MuxSession node = new MuxSession(nodeCh, false, listener(no, nc, ncl), budget);
        hub.start();
        node.start();
        ex.shutdown();
        return new Pair(hub, node, ho, no, hc, nc, hcl, ncl);
    }

    private static MuxSession.Listener listener(LinkedBlockingQueue<MuxStream> opened, LinkedBlockingQueue<byte[]> ctrl,
        CompletableFuture<Throwable> closed) {
        return new MuxSession.Listener() {
            @Override
            public void onControl(MuxSession s, byte[] json) {
                ctrl.add(json);
            }

            @Override
            public void onOpen(MuxSession s, MuxStream stream) {
                opened.add(stream);
            }

            @Override
            public void onClosed(MuxSession s, Throwable cause) {
                closed.complete(cause);
            }
        };
    }

    @Test
    void controlAndStreamsBothWays() throws Exception {
        Pair p = pair();
        p.node().control("{\"t\":\"Ping\"}".getBytes());
        assertEquals("{\"t\":\"Ping\"}", new String(p.hubCtrl().poll(5, TimeUnit.SECONDS)));

        MuxStream hs = p.hub().open(JsonObject.builder().put("sni", "x.hub.test").build(), false);
        assertEquals(2, hs.id());
        MuxStream ns = p.nodeOpened().poll(5, TimeUnit.SECONDS);
        assertNotNull(ns);
        assertEquals("x.hub.test", ns.meta().string("sni"));

        hs.out().write("hello".getBytes());
        byte[] buf = new byte[5];
        assertEquals(5, ns.in().readNBytes(buf, 0, 5));
        assertEquals("hello", new String(buf));
        ns.out().write("world".getBytes());
        assertEquals("world", new String(hs.in().readNBytes(5)));

        hs.close(); // half-close
        assertEquals(-1, ns.in().read());
        ns.out().write("late".getBytes()); // still allowed
        assertEquals("late", new String(hs.in().readNBytes(4)));
        ns.close();
        assertEquals(-1, hs.in().read());
        awaitNoStreams(p);

        MuxStream odd = p.node().open(JsonObject.builder().put("k", "v").build(), false);
        assertEquals(1, odd.id());
        assertNotNull(p.hubOpened().poll(5, TimeUnit.SECONDS));
        p.hub().close();
        p.node().close();
    }

    /**
     * {@link MuxStream#readDeadline}: the bound the node puts on a visitor that has not spoken yet
     * (ARCHITECTURE.md §9.3). Three properties, because the deadline is only useful if it gives up
     * when it should, does not give up on bytes that did arrive, and can be taken off again.
     */
    @Test
    void aReadDeadlineEndsAWaitAndNothingElse() throws Exception {
        Pair p = pair();
        MuxStream hs = p.hub().open(JsonObject.builder().build(), false);
        MuxStream ns = p.nodeOpened().poll(5, TimeUnit.SECONDS);
        assertNotNull(ns);

        // Nothing sent: the read gives up, near the deadline rather than at once or much later.
        long at = System.currentTimeMillis() + 300;
        ns.readDeadline(at);
        long before = System.currentTimeMillis();
        assertThrows(MuxTimeoutException.class, () -> ns.in().read());
        long waited = System.currentTimeMillis() - before;
        assertTrue(waited >= 250, "gave up after only " + waited + " ms");
        assertTrue(waited < 5_000, "took " + waited + " ms to give up");

        // The stream is left as it was rather than reset, and bytes already queued are read out
        // even though the deadline is behind us: only a *wait* is bounded, never data that arrived.
        // That is the visitor whose first byte lands in the last millisecond, and it has to be
        // served rather than cut. Queued first and read after, because a deadline in the past turns
        // any wait into a throw, and this is about the path that does not wait.
        hs.out().write("in time".getBytes());
        long queuedBy = System.currentTimeMillis() + 5_000;
        while (ns.queuedBytes() == 0 && System.currentTimeMillis() < queuedBy) {
            Thread.sleep(10);
        }
        assertEquals(7, ns.queuedBytes(), "the peer's bytes should be queued before the read");
        assertEquals("in time", new String(ns.in().readNBytes(7)));
        // ...and once that queue is empty the next read is over the deadline again.
        assertThrows(MuxTimeoutException.class, () -> ns.in().read());

        // Cleared, the stream is an ordinary one again: this read waits with no clock on it, which
        // is what an established visitor needs -- an SSE stream may say nothing for hours.
        ns.readDeadline(0);
        Thread late = Thread.ofVirtual().start(() -> {
            try {
                Thread.sleep(400);
                hs.out().write("later".getBytes());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertEquals("later", new String(ns.in().readNBytes(5)));
        late.join();

        p.hub().close();
        p.node().close();
    }

    @Test
    void largeTransferRespectsFlowControl() throws Exception {
        Pair p = pair();
        MuxStream hs = p.hub().open(JsonObject.builder().build(), false);
        MuxStream ns = p.nodeOpened().poll(5, TimeUnit.SECONDS);
        byte[] data = new byte[3 * MuxStream.WINDOW + 12345];
        new Random(1).nextBytes(data);
        // Writer would block without WINDOW refills; the reader on the other side drains it.
        Thread w = Thread.ofVirtual().start(() -> {
            try {
                hs.out().write(data);
                hs.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        Thread watchdog = Thread.ofVirtual().start(() -> {
            try {
                Thread.sleep(20_000);
            } catch (InterruptedException e) {
                return;
            }
            System.err.println("largeTransferRespectsFlowControl stalled"
                + "\n  writer side: " + hs.flowState()
                + "\n  reader side: " + ns.flowState()
                + "\n  threads:" + stacks());
        });
        byte[] got;
        try {
            got = ns.in().readAllBytes();
        } finally {
            watchdog.interrupt();
        }
        w.join();
        assertArrayEquals(data, got);
        p.hub().close();
        p.node().close();
    }

    /**
     * {@code writeTo} moves the same bytes as {@code read} without a buffer of the caller's, and --
     * the part worth testing -- keeps the same accounting: the window has to refill or the writer
     * stalls forever, and against a real budget the release has to happen or the budget fills and
     * the stream is reclaimed. Both are checked by sending several windows through a budget small
     * enough to notice.
     */
    @Test
    void writeToMovesTheBytesAndKeepsTheAccounting() throws Exception {
        Pair p = pair(FlowBudget.of(2 * MuxStream.WINDOW));
        MuxStream hs = p.hub().open(JsonObject.builder().build(), false);
        MuxStream ns = p.nodeOpened().poll(5, TimeUnit.SECONDS);
        byte[] data = new byte[3 * MuxStream.WINDOW + 4321];
        new Random(7).nextBytes(data);
        Thread w = Thread.ofVirtual().start(() -> {
            try {
                hs.out().write(data);
                hs.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });

        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        int chunks = 0;
        for (int n; (n = ns.writeTo(sink)) >= 0; ) {
            chunks++;
        }
        w.join();

        assertArrayEquals(data, sink.toByteArray());
        // More than one chunk, or the loop never exercised a refill and the budget never released.
        assertTrue(chunks > 3, "expected several chunks, got " + chunks);
        p.hub().close();
        p.node().close();
    }

    @Test
    void resetAndSessionCloseUnblockReaders() throws Exception {
        Pair p = pair();
        MuxStream hs = p.hub().open(JsonObject.builder().build(), false);
        MuxStream ns = p.nodeOpened().poll(5, TimeUnit.SECONDS);
        hs.reset(3);
        assertThrows(IOException.class, () -> ns.in().read());
        assertThrows(IOException.class, () -> ns.out().write(1));

        MuxStream hs2 = p.hub().open(JsonObject.builder().build(), false);
        MuxStream ns2 = p.nodeOpened().poll(5, TimeUnit.SECONDS);
        p.hub().close();
        assertThrows(IOException.class, () -> ns2.in().read());
        assertNotNull(p.nodeClosed().get(5, TimeUnit.SECONDS));
        assertTrue(p.node().isClosed());
        assertThrows(IOException.class, () -> hs2.out().write(1));
    }

    @Test
    void datagramStreamsKeepBoundaries() throws Exception {
        Pair p = pair();
        MuxStream hs = p.hub().open(JsonObject.builder().put("linkId", "u1").build(), true);
        MuxStream ns = p.nodeOpened().poll(5, TimeUnit.SECONDS);
        assertTrue(ns.isDatagram());
        hs.send(new byte[] {1, 2, 3});
        hs.send(new byte[] {4});
        assertArrayEquals(new byte[] {1, 2, 3}, ns.receive());
        assertArrayEquals(new byte[] {4}, ns.receive());
        ns.send(new byte[1200]);
        assertEquals(1200, hs.receive().length);
        hs.close();
        assertEquals(null, ns.receive());
        p.hub().close();
        p.node().close();
    }

    /**
     * A datagram send after this side half-closed is refused, the same as {@code out().write}.
     * It used to be let through: the credit wait ends on localClosed as well as on credits
     * arriving, and only {@code error} was re-checked afterwards, so the datagram went out on a
     * closed stream and subtracted from `credits` on the way. A stream left with negative credits
     * blocks every later send against a debt no WINDOW frame repays.
     */
    @Test
    void sendingADatagramAfterHalfCloseIsRefused() throws Exception {
        Pair p = pair();
        MuxStream hs = p.hub().open(JsonObject.builder().put("linkId", "u1").build(), true);
        MuxStream ns = p.nodeOpened().poll(5, TimeUnit.SECONDS);
        hs.send(new byte[] {1});
        assertArrayEquals(new byte[] {1}, ns.receive());
        hs.close();
        assertThrows(IOException.class, () -> hs.send(new byte[] {2}), "a half-closed stream may not send");
        // And the peer sees the close, not a stray datagram after it.
        assertEquals(null, ns.receive());
        p.hub().close();
        p.node().close();
    }

    /**
     * The same when the close lands while a sender is parked for credits: the waiter must wake to
     * a refusal rather than to permission it never had.
     */
    @Test
    void aDatagramSenderParkedForCreditsIsRefusedWhenTheStreamCloses() throws Exception {
        Pair p = pair();
        MuxStream hs = p.hub().open(JsonObject.builder().put("linkId", "u1").build(), true);
        assertNotNull(p.nodeOpened().poll(5, TimeUnit.SECONDS));
        // Spend the window without the peer reading, so the next send has to wait for credits.
        byte[] full = new byte[Frame.MAX_DATA];
        for (int sent = 0; sent < MuxStream.WINDOW; sent += full.length) {
            hs.send(full);
        }
        AtomicReference<Throwable> thrown = new AtomicReference<>();
        CountDownLatch parked = new CountDownLatch(1);
        Thread w = Thread.ofVirtual().start(() -> {
            parked.countDown();
            try {
                hs.send(new byte[] {9});
            } catch (Throwable t) {
                thrown.set(t);
            }
        });
        assertTrue(parked.await(5, TimeUnit.SECONDS));
        Thread.sleep(200); // let it reach the wait
        hs.close();
        w.join(5000);
        assertNotNull(thrown.get(), "the parked sender should have been refused, not released to send");
        assertTrue(thrown.get() instanceof IOException, "expected an IOException, got " + thrown.get());
        p.hub().close();
        p.node().close();
    }

    @Test
    void wrongParityOpenKillsSession() throws Exception {
        Pair p = pair();
        // Forge an OPEN with an even id from the node side (the hub's parity).
        java.lang.reflect.Field f = MuxSession.class.getDeclaredField("ch");
        f.setAccessible(true);
        NoiseChannel raw = (NoiseChannel) f.get(p.node());
        raw.write(new Frame(4, Frame.OPEN, 0, "{}".getBytes()));
        Throwable cause = p.hubClosed().get(5, TimeUnit.SECONDS);
        assertTrue(cause instanceof MuxException, String.valueOf(cause));
        p.node().close();
    }

    @Test
    void aFrameTypeThisBuildDoesNotKnowIsSkipped() throws Exception {
        // The other half of §5.4: a newer peer may add a frame type, and dropping the session over
        // one would make every added type a flag day. The frame is fully read before dispatch, so
        // skipping it leaves the stream in sync -- which is what the traffic afterwards proves.
        Pair p = pair();
        java.lang.reflect.Field f = MuxSession.class.getDeclaredField("ch");
        f.setAccessible(true);
        NoiseChannel raw = (NoiseChannel) f.get(p.node());
        raw.write(new Frame(0, 99, 0, "a payload from the future".getBytes()));

        // Still alive, still in sync: control and a stream both work after the unknown frame.
        p.node().control("{\"t\":\"Ping\",\"id\":1}".getBytes());
        assertArrayEquals("{\"t\":\"Ping\",\"id\":1}".getBytes(), p.hubCtrl().poll(5, TimeUnit.SECONDS));
        MuxStream hs = p.hub().open(JsonObject.builder().put("sni", "x.hub.test").build(), false);
        MuxStream ns = p.nodeOpened().poll(5, TimeUnit.SECONDS);
        assertNotNull(ns);
        hs.out().write("hello".getBytes());
        assertEquals("hello", new String(ns.in().readNBytes(5)));
        assertEquals(null, p.hubClosed().getNow(null));
        p.hub().close();
        p.node().close();
    }

    static InputStream nullIn() {
        return InputStream.nullInputStream();
    }

    static OutputStream nullOut() {
        return OutputStream.nullOutputStream();
    }
}
