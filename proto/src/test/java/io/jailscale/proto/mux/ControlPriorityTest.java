package io.jailscale.proto.mux;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * A control frame does not wait behind queued data (ARCHITECTURE.md §5.3).
 *
 * <p>The deterministic form of an outlier {@code measure.sh SLOW=} produces about once a run: an
 * ordinary visitor waiting ten to nineteen seconds for its first byte, because the
 * {@code SignResponse} its handshake needed sat behind other visitors' data.
 *
 * <p><b>This asserts order, not latency</b>, and the first version of it asserted latency and was
 * vacuous -- it passed with the priority removed, because it depended on kernel socket buffers to
 * make data block and they were larger than it assumed. The send side here is a gate this test opens
 * and closes itself, so "data is stuck" is a fact rather than a hope, and what is measured is which
 * frame the peer sees first once it moves again.
 */
@Timeout(120)
class ControlPriorityTest {

    private static final byte[] PROLOGUE = "t".getBytes();

    /** An OutputStream that stops passing bytes on command, so a blocked write is not a guess. */
    private static final class Gate extends OutputStream {
        private final OutputStream real;
        private final AtomicBoolean shut = new AtomicBoolean();

        Gate(OutputStream real) {
            this.real = real;
        }

        private void hold() throws IOException {
            while (shut.get()) {
                try {
                    Thread.sleep(5);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted");
                }
            }
        }

        @Override
        public void write(int b) throws IOException {
            hold();
            real.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            hold();
            real.write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            real.flush();
        }
    }

    @Test
    void aControlFrameOvertakesQueuedData() throws Exception {
        X25519.Keypair hk = X25519.generate();
        X25519.Keypair nk = X25519.generate();
        ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        Socket a = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
        Socket b = ss.accept();
        ss.close();
        ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
        Future<NoiseChannel> respond = ex.submit(() -> NoiseChannel.respond(
            b.getInputStream(), b.getOutputStream(), NoiseIk.responder(PROLOGUE, hk), (p, hs) -> new byte[0]));
        Gate gate = new Gate(a.getOutputStream());
        NoiseChannel senderCh = NoiseChannel.initiate(a.getInputStream(), gate,
            NoiseIk.initiator(PROLOGUE, nk, hk.publicKey()), null);
        NoiseChannel peerCh = respond.get();

        MuxSession sender = new MuxSession(senderCh, true, sink(), FlowBudget.unlimited());
        sender.start();
        try {
            // Shut the gate first: from here nothing the sender writes reaches the peer, so the
            // writer blocks on its first frame and everything after it queues behind that.
            gate.shut.set(true);

            MuxStream s = sender.open(JsonObject.builder().put("sni", "x").build(), false);
            AtomicInteger offered = new AtomicInteger();
            ex.submit(() -> {
                byte[] chunk = new byte[Frame.MAX_DATA];
                try {
                    while (true) {
                        s.out().write(chunk);
                        offered.incrementAndGet();
                    }
                } catch (Exception e) {
                    // blocked for good on queue room or credits, which is the state this wants
                }
            });
            // Wait until the data queue cannot take another frame: one in the writer's hands and
            // DATA_QUEUE_BYTES worth behind it. Until that holds there is nothing for control to
            // overtake and the test would prove nothing.
            int queued = MuxSession.DATA_QUEUE_BYTES / Frame.MAX_DATA;
            waitUntil(() -> offered.get() >= queued, 30_000);
            int dataAhead = offered.get();

            // Sent from a thread of its own, and this matters. Without a priority the control frame
            // is a data frame, so it waits for room in a queue nothing is draining -- on the test's
            // own thread that is a deadlock, and a test that hangs instead of failing is not a gate.
            // Off-thread, the same regression shows up as the frame arriving late, which is an
            // assertion.
            ex.submit(() -> {
                try {
                    sender.control("{\"type\":\"Ping\"}".getBytes());
                } catch (IOException e) {
                    // the session went; the read loop below reports it as a miss
                }
            });
            Thread.sleep(200); // long enough that a frame with somewhere to go has gone
            gate.shut.set(false); // let it move

            // What order does the peer actually see?
            List<Integer> types = new ArrayList<>();
            for (int i = 0; i < dataAhead + 2; i++) {
                Frame f = peerCh.read();
                if (f == null) {
                    break;
                }
                types.add(f.type());
                if (f.type() == Frame.CTRL) {
                    break;
                }
            }

            int ctrlAt = types.indexOf(Frame.CTRL);
            assertTrue(ctrlAt >= 0, "the control frame never arrived; saw " + types.size() + " frames");
            // One data frame was already committed to the write when the gate shut, so position 1 is
            // the best possible. Without a priority the control frame lands after every one of the
            // dataAhead frames queued in front of it.
            assertTrue(ctrlAt <= 1,
                "control frame arrived after " + ctrlAt + " data frames; " + dataAhead + " were queued ahead of it");
        } finally {
            sender.close();
            ex.shutdownNow();
            a.close();
            b.close();
        }
    }

    private static void waitUntil(java.util.function.BooleanSupplier c, long timeoutMs) throws Exception {
        long end = System.currentTimeMillis() + timeoutMs;
        while (!c.getAsBoolean()) {
            if (System.currentTimeMillis() > end) {
                throw new IllegalStateException("condition never held");
            }
            Thread.sleep(20);
        }
    }

    private static MuxSession.Listener sink() {
        return new MuxSession.Listener() {
            @Override public void onControl(MuxSession s, byte[] json) {}

            @Override public void onOpen(MuxSession s, MuxStream stream) {}

            @Override public void onClosed(MuxSession s, Throwable cause) {}
        };
    }
}
