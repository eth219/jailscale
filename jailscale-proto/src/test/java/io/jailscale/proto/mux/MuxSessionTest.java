package io.jailscale.proto.mux;

import com.sun.management.HotSpotDiagnosticMXBean;
import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.json.JsonObject;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
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

    private static Pair pair() throws Exception {
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
        MuxSession hub = new MuxSession(hubCh.get(), true, listener(ho, hc, hcl));
        MuxSession node = new MuxSession(nodeCh, false, listener(no, nc, ncl));
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
        assertEquals(0, p.hub().streamCount());
        assertEquals(0, p.node().streamCount());

        MuxStream odd = p.node().open(JsonObject.builder().put("k", "v").build(), false);
        assertEquals(1, odd.id());
        assertNotNull(p.hubOpened().poll(5, TimeUnit.SECONDS));
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

    static InputStream nullIn() {
        return InputStream.nullInputStream();
    }

    static OutputStream nullOut() {
        return OutputStream.nullOutputStream();
    }
}
