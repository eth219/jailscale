package io.jailscale.proto.mux;

import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.json.JsonObject;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Scratch measurement, not a gate: what a stalled reader costs the receiver.
 *
 * <p>The sender blocks when its credits run out, so the bytes come to rest in the receiver's
 * {@link MuxStream} inbound queue, capped at {@code WINDOW + MAX_DATA} per stream. This measures
 * the retained heap that produces, and what stream count it takes to reach the shipped ceilings
 * (64 MB on the node, 96 MB on the hub).
 */
@Tag("load")
@Timeout(300)
class SaturationMeasure {

    private static final byte[] PROLOGUE = "t".getBytes();

    /** Runnable outside surefire, so the heap ceiling can be set: java -Xmx64m -cp ... */
    public static void main(String[] args) throws Exception {
        new SaturationMeasure().stalledStreamsRetainedHeap();
    }

    @Test
    void stalledStreamsRetainedHeap() throws Exception {
        System.out.printf("WINDOW=%d KiB  MAX_DATA=%d KiB  cap/stream=%d KiB%n",
            MuxStream.WINDOW / 1024, Frame.MAX_DATA / 1024,
            (MuxStream.WINDOW + Frame.MAX_DATA) / 1024);
        System.out.printf("%6s %14s %14s %12s %10s %10s%n",
            "N", "accepted/str", "heap/stream", "heap total", "n@64MB", "n@96MB");

        String spec = System.getProperty("saturation.n", "32,64,128,256");
        for (String s : spec.split(",")) {
            run(Integer.parseInt(s.trim()));
        }
    }

    private void run(int n) throws Exception {
        X25519.Keypair hk = X25519.generate();
        X25519.Keypair nk = X25519.generate();
        ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        Socket a = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
        Socket b = ss.accept();
        ss.close();
        ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
        Future<NoiseChannel> hubCh = ex.submit(() -> NoiseChannel.respond(
            b.getInputStream(), b.getOutputStream(), NoiseIk.responder(PROLOGUE, hk), (p, hs) -> new byte[0]));
        NoiseChannel nodeCh = NoiseChannel.initiate(a.getInputStream(), a.getOutputStream(),
            NoiseIk.initiator(PROLOGUE, nk, hk.publicKey()), null);

        // The node side accepts streams and never reads them: the stalled local app.
        LinkedBlockingQueue<MuxStream> accepted = new LinkedBlockingQueue<>();
        MuxSession hub = new MuxSession(hubCh.get(), true, sink(null));
        MuxSession node = new MuxSession(nodeCh, false, sink(accepted));
        hub.start();
        node.start();

        long base = usedHeap();

        List<MuxStream> streams = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            streams.add(hub.open(JsonObject.builder().put("sni", "x" + i + ".hub.test").build(), false));
        }
        for (int i = 0; i < n; i++) {
            accepted.take();
        }

        // Each writer pushes until it runs out of credits and blocks there.
        AtomicLong written = new AtomicLong();
        byte[] chunk = new byte[Frame.MAX_DATA];
        for (MuxStream s : streams) {
            ex.submit(() -> {
                try {
                    for (int i = 0; i < 64; i++) { // 1 MiB offered per stream
                        s.out().write(chunk);
                        written.addAndGet(chunk.length);
                    }
                } catch (Exception e) {
                    // blocked writers are interrupted at the end; that is the expected exit
                }
            });
        }

        // Settle: wait until no writer has made progress for a while.
        long last = -1;
        for (int quiet = 0; quiet < 20;) {
            Thread.sleep(100);
            long now = written.get();
            quiet = now == last ? quiet + 1 : 0;
            last = now;
        }

        long used = usedHeap() - base;
        long perStream = used / n;
        System.out.printf("%6d %11d KiB %11d KiB %9d MiB %10d %10d%n",
            n, written.get() / n / 1024, perStream / 1024, used / (1024 * 1024),
            perStream == 0 ? -1 : 64L * 1024 * 1024 / perStream,
            perStream == 0 ? -1 : 96L * 1024 * 1024 / perStream);

        hub.close();
        node.close();
        ex.shutdownNow();
        a.close();
        b.close();
    }

    private static MuxSession.Listener sink(LinkedBlockingQueue<MuxStream> opened) {
        return new MuxSession.Listener() {
            @Override
            public void onControl(MuxSession s, byte[] json) {}

            @Override
            public void onOpen(MuxSession s, MuxStream stream) {
                if (opened != null) {
                    opened.add(stream); // held, never read
                }
            }

            @Override
            public void onClosed(MuxSession s, Throwable cause) {}
        };
    }

    private static long usedHeap() throws Exception {
        for (int i = 0; i < 4; i++) {
            System.gc();
            Thread.sleep(120);
        }
        return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
    }
}
