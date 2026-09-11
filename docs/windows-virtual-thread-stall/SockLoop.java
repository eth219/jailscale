import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The stall without any jailscale code: one loopback socket pair carrying length-prefixed 16 KB
 * frames, 800 KB per iteration, the shape MuxSession puts on the wire.
 *
 * <p>uni: data one way only. bidi: adds the piece uni was missing -- the reader returns a window
 * update every 128 KB and the writer blocks when its credits run out, so both directions carry
 * traffic and the writer can park waiting on the peer, which is what a third of the real dumps
 * were doing.
 *
 * <p>Usage: SockLoop &lt;iterations&gt; &lt;timeout s&gt; &lt;budget s&gt; &lt;virtual|platform&gt; &lt;uni|bidi&gt;
 */
public final class SockLoop {

    private static final int FRAME = 16 * 1024;
    private static final int WINDOW = 256 * 1024;
    private static final int TOTAL = 3 * WINDOW + 12345;

    public static void main(String[] args) throws Exception {
        int iterations = args.length > 0 ? Integer.parseInt(args[0]) : 5000;
        long timeoutSec = args.length > 1 ? Long.parseLong(args[1]) : 10;
        long budgetSec = args.length > 2 ? Long.parseLong(args[2]) : 600;
        boolean virtual = args.length <= 3 || !"platform".equals(args[3]);
        boolean bidi = args.length > 4 && "bidi".equals(args[4]);
        System.out.println(System.getProperty("java.vm.version") + "  cpus=" + Runtime.getRuntime().availableProcessors()
            + "  threads=" + (virtual ? "virtual" : "platform") + "  mode=" + (bidi ? "bidi" : "uni"));
        int hangs = 0;
        int errors = 0;
        int done = 0;
        int logged = 0;
        long start = System.currentTimeMillis();
        for (int i = 1; i <= iterations; i++) {
            if ((System.currentTimeMillis() - start) / 1000 >= budgetSec) {
                System.out.println("budget reached after " + done + " iterations");
                break;
            }
            done = i;
            Object r = once(timeoutSec, virtual, bidi);
            if ("HANG".equals(r)) {
                hangs++;
                System.out.println("iteration " + i + ": HANG");
            } else if (r instanceof Exception e) {
                errors++;
                if (logged < 5) {
                    logged++;
                    System.out.println("iteration " + i + " error: " + e);
                }
            }
            if (i % 1000 == 0) {
                System.out.println("  ... " + i + " hangs=" + hangs + " errors=" + errors);
            }
        }
        System.out.println("SOCKRESULT threads=" + (virtual ? "virtual" : "platform") + " mode=" + (bidi ? "bidi" : "uni")
            + " hangs=" + hangs + " errors=" + errors + " of " + done + " in " + (System.currentTimeMillis() - start) / 1000 + "s");
    }

    private static Thread spawn(boolean virtual, Runnable body) {
        return virtual ? Thread.ofVirtual().start(body) : Thread.ofPlatform().start(body);
    }

    /** "OK", "HANG", or the exception that ended it. */
    private static Object once(long timeoutSec, boolean virtual, boolean bidi) {
        try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
             Socket a = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
             Socket b = ss.accept()) {
            CompletableFuture<Integer> read = new CompletableFuture<>();
            AtomicInteger credits = new AtomicInteger(WINDOW);
            Object lock = new Object();

            Thread reader = spawn(virtual, () -> {
                try {
                    DataInputStream in = new DataInputStream(b.getInputStream());
                    DataOutputStream back = new DataOutputStream(b.getOutputStream());
                    int total = 0;
                    int since = 0;
                    while (total < TOTAL) {
                        int len = in.readUnsignedShort();
                        in.readFully(new byte[len]);
                        total += len;
                        since += len;
                        if (bidi && since >= WINDOW / 2) {
                            synchronized (back) {
                                back.writeInt(since);
                                back.flush();
                            }
                            since = 0;
                        }
                    }
                    read.complete(total);
                } catch (IOException e) {
                    read.completeExceptionally(e);
                }
            });

            Thread acks = bidi ? spawn(virtual, () -> {
                try {
                    DataInputStream ackIn = new DataInputStream(a.getInputStream());
                    while (!read.isDone()) {
                        int delta = ackIn.readInt();
                        synchronized (lock) {
                            credits.addAndGet(delta);
                            lock.notifyAll();
                        }
                    }
                } catch (IOException ignored) {
                    // the transfer finished or the socket went away
                }
            }) : null;

            Thread writer = spawn(virtual, () -> {
                try {
                    DataOutputStream out = new DataOutputStream(a.getOutputStream());
                    byte[] chunk = new byte[FRAME];
                    int sent = 0;
                    while (sent < TOTAL) {
                        int n = Math.min(FRAME, TOTAL - sent);
                        if (bidi) {
                            synchronized (lock) {
                                while (credits.get() < n) {
                                    lock.wait(5000);
                                }
                                credits.addAndGet(-n);
                            }
                        }
                        out.writeShort(n);
                        out.write(chunk, 0, n);
                        out.flush();
                        sent += n;
                    }
                } catch (IOException | InterruptedException ignored) {
                    // the reader reports the outcome
                }
            });

            try {
                int got = read.get(timeoutSec, TimeUnit.SECONDS);
                writer.join();
                reader.join();
                if (acks != null) {
                    acks.interrupt();
                }
                return got == TOTAL ? "OK" : new IOException("short read " + got);
            } catch (TimeoutException e) {
                return "HANG";
            }
        } catch (Exception e) {
            return e;
        }
    }
}
