package io.jailscale.hub;

import io.jailscale.proto.mux.MuxStream;
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
        CountDownLatch visitorDone = new CountDownLatch(1);
        Thread toVisitor = Thread.ofVirtual().name("relay-in").start(() -> {
            try {
                copy(stream.in(), visitor.getOutputStream());
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
            out.write(consumed);
            copy(visitor.getInputStream(), out);
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

    static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[BUF];
        int n;
        while ((n = in.read(buf)) >= 0) {
            if (n > 0) {
                out.write(buf, 0, n);
                out.flush();
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
