package io.jailscale.hub;

import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/** Copies bytes between a visitor socket and a mux stream in both directions (DESIGN.md §9.1). */
final class Relay {

    private static final Log LOG = Log.get("relay");
    private static final int BUF = 16 * 1024;

    private Relay() {}

    /**
     * Runs on the calling thread until both directions are done. {@code consumed} is written to
     * the stream first (the peeked ClientHello).
     */
    static void pump(Socket visitor, MuxStream stream, byte[] consumed) {
        Thread toVisitor = Thread.ofVirtual().name("relay-in").start(() -> {
            try {
                copy(stream.in(), visitor.getOutputStream());
                visitor.shutdownOutput();
            } catch (IOException e) {
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
