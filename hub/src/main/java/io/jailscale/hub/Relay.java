package io.jailscale.hub;

import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.net.DuplexThread;
import io.jailscale.proto.tls.Tls13;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/** Copies bytes between a visitor socket and a mux stream in both directions (ARCHITECTURE.md §8.1). */
final class Relay {

    private static final Log LOG = Log.get("relay");
    private static final int BUF = 16 * 1024;
    /**
     * How long the hub keeps a visitor socket after the node has finished with it. Both sides are
     * half-closes (§5.3), so the hub waits for the visitor to close its own half before letting go.
     * A visitor under no obligation to ever do that would otherwise pin the socket, the thread
     * reading it and the half-open stream for as long as it liked. The wait only starts once the
     * node has closed its side, so a stream that is meant to stay open -- WebSocket, SSE, a long
     * download (§14) -- never reaches it.
     */
    static volatile long lingerMs = 10_000;

    private Relay() {}

    /**
     * Runs on the calling thread until both directions are done. {@code consumed} is written to
     * the stream first (the peeked ClientHello).
     */
    static void pump(Socket visitor, MuxStream stream, byte[] consumed) {
        pump(visitor, stream, consumed, new Tls13.Tap());
    }

    /**
     * As above, with {@code clientSide} seeing every byte the visitor sends until its plaintext
     * handshake is over: the ClientHello the hub delivered is what a signature is bound to (§9.2).
     */
    static void pump(Socket visitor, MuxStream stream, byte[] consumed, Tls13.Tap clientSide) {
        CountDownLatch visitorDone = new CountDownLatch(1);
        Thread toVisitor = DuplexThread.start("relay-in", () -> {
            try {
                drain(stream, visitor.getOutputStream());
                visitor.shutdownOutput();
            } catch (IOException e) {
                closeQuietly(visitor);
                return;
            }
            try {
                if (!visitorDone.await(lingerMs, TimeUnit.MILLISECONDS)) {
                    LOG.debug("visitor did not close its half within {} ms; closing", lingerMs);
                    closeQuietly(visitor);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                closeQuietly(visitor);
            }
        });
        try {
            OutputStream out = stream.out();
            clientSide.accept(consumed);
            out.write(consumed);
            copy(visitor.getInputStream(), out, clientSide);
            stream.close();
        } catch (IOException e) {
            LOG.debug("visitor -> node ended: {}", e.getMessage());
            stream.reset(1);
        } finally {
            visitorDone.countDown();
        }
        try {
            toVisitor.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        closeQuietly(visitor);
    }

    /**
     * Node to visitor, without the buffer. The bytes are already a private array in the stream's
     * queue, so they go to the socket from there (ARCHITECTURE.md §15). The other direction has no
     * such shortcut -- a socket read has to land somewhere -- which is why only this one changed.
     */
    static void drain(MuxStream stream, OutputStream out) throws IOException {
        for (int n; (n = stream.writeTo(out)) >= 0; ) {
            if (n > 0) {
                out.flush();
                Metrics.RELAY_BYTES.add(n);
            }
        }
    }

    static void copy(InputStream in, OutputStream out) throws IOException {
        copy(in, out, null);
    }

    static void copy(InputStream in, OutputStream out, Tls13.Tap tap) throws IOException {
        byte[] buf = new byte[BUF];
        int n;
        while ((n = in.read(buf)) >= 0) {
            if (n > 0) {
                if (tap != null && !tap.done()) {
                    tap.accept(buf, 0, n);
                }
                out.write(buf, 0, n);
                out.flush();
                Metrics.RELAY_BYTES.add(n);
            }
        }
    }

    static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // closing
        }
    }
}
