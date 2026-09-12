package io.jailscale.proto.mux;

import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * MuxSessionTest.largeTransferRespectsFlowControl, in a loop, outside JUnit: the same two sessions
 * over a loopback socket pair and the same 800 KB transfer against a 256 KB window, so the count it
 * prints is the stall rate of jailscale's own code rather than of a socket reproducer.
 *
 * <p>Usage: MuxLoop &lt;iterations&gt; &lt;per-run timeout s&gt; &lt;budget s&gt;
 */
public final class MuxLoop {

    private static final byte[] PROLOGUE = "t".getBytes();

    public static void main(String[] args) throws Exception {
        int iterations = args.length > 0 ? Integer.parseInt(args[0]) : 3000;
        long timeoutSec = args.length > 1 ? Long.parseLong(args[1]) : 10;
        long budgetSec = args.length > 2 ? Long.parseLong(args[2]) : 900;
        System.out.println(System.getProperty("java.vm.version") + "  cpus="
            + Runtime.getRuntime().availableProcessors());

        byte[] data = new byte[3 * MuxStream.WINDOW + 12345];
        new Random(1).nextBytes(data);
        int hangs = 0;
        int errors = 0;
        int done = 0;
        long start = System.currentTimeMillis();
        for (int i = 1; i <= iterations; i++) {
            if ((System.currentTimeMillis() - start) / 1000 >= budgetSec) {
                System.out.println("budget reached after " + done + " iterations");
                break;
            }
            done = i;
            Object r = once(data, timeoutSec);
            if ("HANG".equals(r)) {
                hangs++;
                System.out.println("iteration " + i + ": HANG");
            } else if (r instanceof Exception e) {
                errors++;
                if (errors <= 5) {
                    System.out.println("iteration " + i + " error: " + e);
                }
            }
            if (i % 500 == 0) {
                System.out.println("  ... " + i + " hangs=" + hangs + " errors=" + errors);
            }
        }
        System.out.println("MUXRESULT hangs=" + hangs + " errors=" + errors + " of " + done
            + " in " + (System.currentTimeMillis() - start) / 1000 + "s");
    }

    private static Object once(byte[] data, long timeoutSec) {
        ServerSocket ss = null;
        Socket a = null;
        Socket b = null;
        MuxSession hub = null;
        MuxSession node = null;
        try {
            X25519.Keypair hk = X25519.generate();
            X25519.Keypair nk = X25519.generate();
            ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
            a = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
            b = ss.accept();
            ss.close();
            ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
            final Socket bf = b;
            Future<NoiseChannel> hubCh = ex.submit(() -> NoiseChannel.respond(bf.getInputStream(), bf.getOutputStream(),
                NoiseIk.responder(PROLOGUE, hk), (p, hs) -> new byte[0]));
            NoiseChannel nodeCh = NoiseChannel.initiate(a.getInputStream(), a.getOutputStream(),
                NoiseIk.initiator(PROLOGUE, nk, hk.publicKey()), null);
            LinkedBlockingQueue<MuxStream> opened = new LinkedBlockingQueue<>();
            hub = new MuxSession(hubCh.get(), true, listener(new LinkedBlockingQueue<>()));
            node = new MuxSession(nodeCh, false, listener(opened));
            hub.start();
            node.start();
            ex.shutdown();

            MuxStream hs = hub.open(JsonObject.builder().build(), false);
            MuxStream ns = opened.poll(5, TimeUnit.SECONDS);
            if (ns == null) {
                return new IOException("no stream opened");
            }
            CompletableFuture<byte[]> got = new CompletableFuture<>();
            Thread reader = Thread.ofVirtual().start(() -> {
                try {
                    got.complete(ns.in().readAllBytes());
                } catch (IOException e) {
                    got.completeExceptionally(e);
                }
            });
            Thread writer = Thread.ofVirtual().start(() -> {
                try {
                    hs.out().write(data);
                    hs.close();
                } catch (IOException ignored) {
                    // the reader reports the outcome
                }
            });
            try {
                byte[] read = got.get(timeoutSec, TimeUnit.SECONDS);
                writer.join();
                reader.join();
                return java.util.Arrays.equals(data, read) ? "OK" : new IOException("short read " + read.length);
            } catch (TimeoutException e) {
                return "HANG";
            }
        } catch (Exception e) {
            return e;
        } finally {
            closeQuietly(hub);
            closeQuietly(node);
            closeQuietly(a);
            closeQuietly(b);
            closeQuietly(ss);
        }
    }

    private static void closeQuietly(AutoCloseable c) {
        if (c != null) {
            try {
                c.close();
            } catch (Exception ignored) {
                // going away anyway
            }
        }
    }

    private static MuxSession.Listener listener(LinkedBlockingQueue<MuxStream> opened) {
        return new MuxSession.Listener() {
            @Override
            public void onControl(MuxSession s, byte[] json) { }

            @Override
            public void onOpen(MuxSession s, MuxStream stream) {
                opened.add(stream);
            }

            @Override
            public void onClosed(MuxSession s, Throwable cause) { }
        };
    }
}
