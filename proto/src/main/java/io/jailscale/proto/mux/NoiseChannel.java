package io.jailscale.proto.mux;

import io.jailscale.crypto.NoiseException;
import io.jailscale.crypto.NoiseIk;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * The byte stream after the HTTP 101: {@code [2B len BE][Noise transport message]} frames, each
 * carrying exactly one {@link Frame} (ARCHITECTURE.md §5.1, §5.3). Handshake messages use the same
 * length prefix.
 *
 * <p>Reads and writes are independently single-threaded: one reader thread, one writer thread.
 * Writes are serialised with a lock so several producers may share the writer side.
 */
public final class NoiseChannel implements AutoCloseable {

    private static final int MAX_MESSAGE = 65535;

    private final DataInputStream in;
    private final DataOutputStream out;
    private final NoiseIk.Transport transport;
    private final Object writeLock = new Object();

    private NoiseChannel(InputStream in, OutputStream out, NoiseIk.Transport transport) {
        this.in = new DataInputStream(in);
        this.out = new DataOutputStream(out);
        this.transport = transport;
    }

    /** Runs the initiator side of the handshake over the stream and returns the channel. */
    public static NoiseChannel initiate(InputStream in, OutputStream out, NoiseIk hs, byte[] payload)
        throws IOException, NoiseException {
        return initiate(in, out, hs, payload, null);
    }

    /** Same, and stores the responder's message-2 payload in {@code payload2Out[0]} if non-null. */
    public static NoiseChannel initiate(InputStream in, OutputStream out, NoiseIk hs, byte[] payload, byte[][] payload2Out)
        throws IOException, NoiseException {
        if (!hs.isInitiator()) {
            throw new IllegalArgumentException("handshake state is not an initiator");
        }
        writeRaw(new DataOutputStream(out), hs.writeMessage(payload));
        byte[] m2 = readRaw(new DataInputStream(in));
        byte[] p2 = hs.readMessage(m2);
        if (payload2Out != null) {
            payload2Out[0] = p2;
        }
        return new NoiseChannel(in, out, hs.transport());
    }

    /** Wraps streams around an already finished handshake. */
    public static NoiseChannel fromFinished(InputStream in, OutputStream out, NoiseIk hs) {
        if (!hs.isFinished()) {
            throw new IllegalArgumentException("handshake not finished");
        }
        return new NoiseChannel(in, out, hs.transport());
    }

    /**
     * Runs the responder side. {@code onMessage1} receives the initiator's payload and returns
     * the responder's payload for message 2.
     */
    public static NoiseChannel respond(InputStream in, OutputStream out, NoiseIk hs, PayloadHandler onMessage1)
        throws IOException, NoiseException {
        return respond(in, out, java.util.List.of(hs), onMessage1);
    }

    /**
     * Responder that accepts message 1 under any of {@code candidates} (each built with a
     * different static key), for the hub key rotation grace period (ARCHITECTURE.md §5.2). Message 1
     * encrypts the initiator's static key under the responder's static key, so only the matching
     * candidate decrypts it; the others fail authentication without side effects.
     */
    public static NoiseChannel respond(InputStream in, OutputStream out, java.util.List<NoiseIk> candidates,
        PayloadHandler onMessage1) throws IOException, NoiseException {
        byte[] m1 = readRaw(new DataInputStream(in));
        NoiseException last = null;
        for (NoiseIk hs : candidates) {
            if (hs.isInitiator()) {
                throw new IllegalArgumentException("handshake state is not a responder");
            }
            byte[] p1;
            try {
                p1 = hs.readMessage(m1);
            } catch (NoiseException e) {
                last = e;
                continue;
            }
            byte[] p2 = onMessage1.handle(p1, hs);
            writeRaw(new DataOutputStream(out), hs.writeMessage(p2));
            return new NoiseChannel(in, out, hs.transport());
        }
        throw last == null ? new NoiseException("no responder keys") : last;
    }

    /** Callback between handshake messages on the responder side. */
    @FunctionalInterface
    public interface PayloadHandler {
        byte[] handle(byte[] initiatorPayload, NoiseIk handshake) throws NoiseException;
    }

    public byte[] handshakeHash() {
        return transport.handshakeHash();
    }

    /** Blocks until the next frame arrives. Returns null on clean EOF before a length prefix. */
    public Frame read() throws IOException, NoiseException, MuxException {
        byte[] ct;
        try {
            ct = readRaw(in);
        } catch (EOFException e) {
            return null;
        }
        byte[] pt = transport.decrypt(ct);
        return Frame.decode(pt);
    }

    public void write(Frame frame) throws IOException, NoiseException {
        byte[] pt = frame.encode();
        // Encrypt inside the lock: the nonce counter must advance in wire order.
        synchronized (writeLock) {
            byte[] ct = transport.encrypt(pt);
            writeRaw(out, ct);
        }
    }

    @Override
    public void close() throws IOException {
        transport.destroy();
        try {
            out.close();
        } finally {
            in.close();
        }
    }

    private static byte[] readRaw(DataInputStream in) throws IOException {
        int len = in.readUnsignedShort(); // throws EOFException at a clean boundary
        byte[] buf = new byte[len];
        in.readFully(buf);
        return buf;
    }

    private static void writeRaw(DataOutputStream out, byte[] msg) throws IOException {
        if (msg.length > MAX_MESSAGE) {
            throw new IOException("message exceeds 65535 bytes");
        }
        out.writeShort(msg.length);
        out.write(msg);
        out.flush();
    }
}
