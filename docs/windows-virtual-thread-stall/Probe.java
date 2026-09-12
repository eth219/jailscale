import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Which precondition does the Windows stall need? SockLoop.java showed that Windows + virtual
 * threads + bidirectional traffic stalls and that removing any one of the three does not. This
 * narrows the third: "bidirectional" in SockLoop means one socket is parked for read and for
 * write at the same time, which on Windows means the same handle sits in the read wepoll instance
 * and the write wepoll instance at once (Poller.readPoller/writePoller, WEPollPoller does
 * EPOLL_CTL_ADD per park).
 *
 * Variants keep the traffic identical and move only which thread is virtual, or which socket
 * carries the window updates:
 *
 *   uni       no window updates at all (the SockLoop control)
 *   bidi      window updates back over the same socket pair (the SockLoop baseline)
 *   split     window updates over a SECOND socket pair, so no socket is ever parked for both
 *             directions, everything still virtual and still bidirectional
 *   pwriter   bidi, but the writer is a platform thread: the data socket never enters the write
 *             poller, everything else unchanged
 *   packs     bidi, but the ack reader is a platform thread: the data socket never enters the
 *             read poller
 *   preader   bidi, but the frame reader is a platform thread (the other side of the pair)
 *   platform  every thread platform (the second SockLoop control)
 *
 * On a stall it prints what each thread is parked in and, decisively, available() on the socket
 * the stalled reader is waiting on: bytes sitting in the receive buffer of a parked reader is a
 * lost wake-up, not a peer that never sent.
 *
 * Usage: Probe <variant> <iterations> <per-run timeout s> <budget s>
 */
public final class Probe {

    private static final int FRAME = 16 * 1024;
    private static final int WINDOW = 256 * 1024;
    private static final int TOTAL = 3 * WINDOW + 12345;

    private static String variant;

    public static void main(String[] args) throws Exception {
        variant = args.length > 0 ? args[0] : "bidi";
        int iterations = args.length > 1 ? Integer.parseInt(args[1]) : 5000;
        long timeoutSec = args.length > 2 ? Long.parseLong(args[2]) : 10;
        long budgetSec = args.length > 3 ? Long.parseLong(args[3]) : 600;
        System.out.println(System.getProperty("java.vm.version") + "  cpus="
            + Runtime.getRuntime().availableProcessors() + "  variant=" + variant);

        int hangs = 0;
        int errors = 0;
        int done = 0;
        int dumped = 0;
        long start = System.currentTimeMillis();
        for (int i = 1; i <= iterations; i++) {
            if ((System.currentTimeMillis() - start) / 1000 >= budgetSec) {
                System.out.println("budget reached after " + done + " iterations");
                break;
            }
            done = i;
            Object r = once(timeoutSec, dumped < 3);
            if (r instanceof String s && s.startsWith("HANG")) {
                hangs++;
                if (dumped < 3) {
                    dumped++;
                    System.out.println("iteration " + i + ": " + s);
                } else {
                    System.out.println("iteration " + i + ": HANG");
                }
            } else if (r instanceof Exception e) {
                errors++;
                if (errors <= 5) {
                    System.out.println("iteration " + i + " error: " + e);
                }
            }
            if (i % 1000 == 0) {
                System.out.println("  ... " + i + " hangs=" + hangs + " errors=" + errors);
            }
        }
        System.out.println("PROBERESULT variant=" + variant + " hangs=" + hangs + " errors=" + errors
            + " of " + done + " in " + (System.currentTimeMillis() - start) / 1000 + "s");
    }

    private static boolean virtualWriter() { return !variant.equals("pwriter") && !variant.equals("platform"); }
    private static boolean virtualAcks()   { return !variant.equals("packs")   && !variant.equals("platform"); }
    private static boolean virtualReader() { return !variant.equals("preader") && !variant.equals("platform"); }
    private static boolean bidi()          { return !variant.equals("uni"); }
    private static boolean split()         { return variant.equals("split"); }

    private static Thread spawn(boolean virtual, String name, Runnable body) {
        return virtual ? Thread.ofVirtual().name(name).start(body)
                       : Thread.ofPlatform().name(name).start(body);
    }

    /** "OK", "HANG ...", or the exception that ended it. */
    private static Object once(long timeoutSec, boolean dump) {
        List<Socket> open = new ArrayList<>();
        try (ServerSocket ss = new ServerSocket(0, 2, InetAddress.getLoopbackAddress())) {
            Socket a = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
            open.add(a);
            Socket b = ss.accept();
            open.add(b);

            // the sockets the window updates travel over: the same pair, or a second one
            Socket ackSrc = b;   // the frame reader writes updates here
            Socket ackSink = a;  // the ack thread reads them here
            if (split()) {
                Socket c = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
                open.add(c);
                Socket d = ss.accept();
                open.add(d);
                ackSrc = d;
                ackSink = c;
            }
            final Socket ackSrcF = ackSrc;
            final Socket ackSinkF = ackSink;

            CompletableFuture<Integer> read = new CompletableFuture<>();
            AtomicInteger credits = new AtomicInteger(WINDOW);
            Object lock = new Object();

            Thread reader = spawn(virtualReader(), "reader", () -> {
                try {
                    DataInputStream in = new DataInputStream(b.getInputStream());
                    DataOutputStream back = new DataOutputStream(ackSrcF.getOutputStream());
                    int total = 0;
                    int since = 0;
                    while (total < TOTAL) {
                        int len = in.readUnsignedShort();
                        in.readFully(new byte[len]);
                        total += len;
                        since += len;
                        if (bidi() && since >= WINDOW / 2) {
                            back.writeInt(since);
                            back.flush();
                            since = 0;
                        }
                    }
                    read.complete(total);
                } catch (IOException e) {
                    read.completeExceptionally(e);
                }
            });

            Thread acks = bidi() ? spawn(virtualAcks(), "acks", () -> {
                try {
                    DataInputStream ackIn = new DataInputStream(ackSinkF.getInputStream());
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

            Thread writer = spawn(virtualWriter(), "writer", () -> {
                try {
                    OutputStream raw = a.getOutputStream();
                    DataOutputStream out = new DataOutputStream(raw);
                    byte[] chunk = new byte[FRAME];
                    int sent = 0;
                    while (sent < TOTAL) {
                        int n = Math.min(FRAME, TOTAL - sent);
                        if (bidi()) {
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
                String why = dump ? diagnose(reader, acks, writer, b, ackSinkF, credits) : "";
                return "HANG" + why;
            }
        } catch (Exception e) {
            return e;
        } finally {
            for (Socket s : open) {
                try {
                    s.close();
                } catch (IOException ignored) {
                    // going away anyway
                }
            }
        }
    }

    /**
     * What the three threads are doing and whether the bytes they are waiting for already arrived.
     * available() on a socket whose reader is parked is the whole point: it reads the receive
     * buffer without taking the read lock, so a non-zero count under a parked reader is a
     * wake-up that was dropped.
     */
    private static String diagnose(Thread reader, Thread acks, Thread writer,
                                   Socket readerSock, Socket ackSock, AtomicInteger credits) {
        StringBuilder sb = new StringBuilder();
        sb.append("\n  credits=").append(credits.get());
        sb.append("\n  reader-socket available=").append(available(readerSock));
        sb.append(" ack-socket available=").append(available(ackSock));
        sb.append(where("reader", reader));
        sb.append(where("acks", acks));
        sb.append(where("writer", writer));
        return sb.toString();
    }

    private static String available(Socket s) {
        try {
            InputStream in = s.getInputStream();
            return String.valueOf(in.available());
        } catch (IOException e) {
            return "err:" + e;
        }
    }

    private static String where(String label, Thread t) {
        if (t == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder("\n  ").append(label)
            .append(" state=").append(t.getState())
            .append(t.isVirtual() ? " virtual" : " platform");
        StackTraceElement[] st = t.getStackTrace();
        for (int i = 0; i < Math.min(6, st.length); i++) {
            sb.append("\n      at ").append(st[i]);
        }
        return sb.toString();
    }
}
