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
 * carrying exactly one {@link Frame} (DESIGN.md §6.1, §8). Handshake messages use the same
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
        if (!hs.isInitiator()) {
            throw new IllegalArgumentException("handshake state is not an initiator");
        }
        writeRaw(new DataOutputStream(out), hs.writeMessage(payload));
        byte[] m2 = readRaw(new DataInputStream(in));
        hs.readMessage(m2);
        return new NoiseChannel(in, out, hs.transport());
    }

    /**
     * Runs the responder side. {@code onMessage1} receives the initiator's payload and returns
     * the responder's payload for message 2.
     */
    public static NoiseChannel respond(InputStream in, OutputStream out, NoiseIk hs, PayloadHandler onMessage1)
        throws IOException, NoiseException {
        if (hs.isInitiator()) {
            throw new IllegalArgumentException("handshake state is not a responder");
        }
        byte[] m1 = readRaw(new DataInputStream(in));
        byte[] p1 = hs.readMessage(m1);
        byte[] p2 = onMessage1.handle(p1, hs);
        writeRaw(new DataOutputStream(out), hs.writeMessage(p2));
        return new NoiseChannel(in, out, hs.transport());
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
        byte[] ct = transport.encrypt(frame.encode());
        synchronized (writeLock) {
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
