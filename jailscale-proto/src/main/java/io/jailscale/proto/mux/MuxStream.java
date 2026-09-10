package io.jailscale.proto.mux;

import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;

/**
 * One byte stream (or datagram stream) inside a {@link MuxSession} (DESIGN.md §8). The session's
 * reader thread feeds {@link #onData} etc.; application threads use {@link #in()}/{@link #out()}.
 * Flow control: the receiver advertises {@link #WINDOW} bytes and refills it with WINDOW frames
 * once half is consumed; the sender blocks when out of credits.
 */
public final class MuxStream {

    public static final int WINDOW = 256 * 1024;

    private final MuxSession session;
    private final long id;
    private final JsonObject meta;
    private final boolean dgram;
    private final Object lock = new Object();

    private final ArrayDeque<byte[]> inbound = new ArrayDeque<>();
    private int inboundBytes;
    private byte[] current;
    private int currentPos;
    private int consumedSinceWindow;
    private boolean remoteClosed;
    private boolean localClosed;
    private IOException error;
    private int credits = WINDOW;

    private final InputStream in = new InputStream() {
        @Override
        public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : one[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            byte[] chunk;
            int pos;
            synchronized (lock) {
                while (current == null && inbound.isEmpty() && !remoteClosed && error == null) {
                    try {
                        lock.wait();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("interrupted");
                    }
                }
                if (current == null) {
                    if (!inbound.isEmpty()) {
                        current = inbound.poll();
                        currentPos = 0;
                    } else if (error != null) {
                        throw error;
                    } else {
                        return -1;
                    }
                }
                chunk = current;
                pos = currentPos;
                int n = Math.min(len, chunk.length - pos);
                System.arraycopy(chunk, pos, b, off, n);
                currentPos += n;
                if (currentPos == chunk.length) {
                    current = null;
                }
                inboundBytes -= n;
                consumedSinceWindow += n;
                int refill = 0;
                if (consumedSinceWindow >= WINDOW / 2) {
                    refill = consumedSinceWindow;
                    consumedSinceWindow = 0;
                }
                if (refill > 0) {
                    session.sendWindow(id, refill);
                }
                return n;
            }
        }
    };

    private final OutputStream out = new OutputStream() {
        @Override
        public void write(int b) throws IOException {
            write(new byte[] {(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            while (len > 0) {
                int n;
                synchronized (lock) {
                    while (credits == 0 && !localClosed && error == null) {
                        try {
                            lock.wait();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IOException("interrupted");
                        }
                    }
                    if (error != null) {
                        throw error;
                    }
                    if (localClosed) {
                        throw new IOException("stream closed");
                    }
                    n = Math.min(Math.min(len, credits), Frame.MAX_DATA);
                    credits -= n;
                }
                byte[] chunk = new byte[n];
                System.arraycopy(b, off, chunk, 0, n);
                session.sendData(id, chunk, dgram);
                off += n;
                len -= n;
            }
        }

        @Override
        public void close() throws IOException {
            MuxStream.this.close();
        }
    };

    MuxStream(MuxSession session, long id, JsonObject meta, boolean dgram) {
        this.session = session;
        this.id = id;
        this.meta = meta;
        this.dgram = dgram;
    }

    public long id() {
        return id;
    }

    public JsonObject meta() {
        return meta;
    }

    public boolean isDatagram() {
        return dgram;
    }

    public InputStream in() {
        return in;
    }

    public OutputStream out() {
        return out;
    }

    /** Datagram streams: the next whole datagram, or null when the peer closed. */
    public byte[] receive() throws IOException {
        synchronized (lock) {
            while (inbound.isEmpty() && !remoteClosed && error == null) {
                try {
                    lock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted");
                }
            }
            if (!inbound.isEmpty()) {
                byte[] d = inbound.poll();
                inboundBytes -= d.length;
                consumedSinceWindow += d.length;
                if (consumedSinceWindow >= WINDOW / 2) {
                    session.sendWindow(id, consumedSinceWindow);
                    consumedSinceWindow = 0;
                }
                return d;
            }
            if (error != null) {
                throw error;
            }
            return null;
        }
    }

    /** Datagram streams: sends one datagram (at most {@link Frame#MAX_DATA} bytes). */
    public void send(byte[] datagram) throws IOException {
        if (datagram.length > Frame.MAX_DATA) {
            throw new IOException("datagram exceeds " + Frame.MAX_DATA);
        }
        synchronized (lock) {
            while (credits < datagram.length && !localClosed && error == null) {
                try {
                    lock.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("interrupted");
                }
            }
            if (error != null) {
                throw error;
            }
            credits -= datagram.length;
        }
        session.sendData(id, datagram, true);
    }

    /** Half-close: no more data from this side. The peer may still send. */
    public void close() throws IOException {
        synchronized (lock) {
            if (localClosed) {
                return;
            }
            localClosed = true;
            lock.notifyAll();
        }
        session.sendClose(id);
        session.maybeRemove(this);
    }

    /** Abort both directions. */
    public void reset(int reason) {
        synchronized (lock) {
            if (error == null) {
                error = new IOException("stream reset (" + reason + ")");
            }
            localClosed = true;
            remoteClosed = true;
            lock.notifyAll();
        }
        session.sendReset(id, reason);
        session.remove(this);
    }

    boolean isFullyClosed() {
        synchronized (lock) {
            return localClosed && remoteClosed;
        }
    }

    // --- called by the session reader --------------------------------------------------------

    void onData(byte[] payload) throws MuxException {
        synchronized (lock) {
            if (remoteClosed) {
                return;
            }
            if (inboundBytes + payload.length > WINDOW + Frame.MAX_DATA) {
                throw new MuxException("peer exceeded the receive window on stream " + id);
            }
            inbound.add(payload);
            inboundBytes += payload.length;
            lock.notifyAll();
        }
    }

    void onWindow(int delta) {
        synchronized (lock) {
            credits = Math.min(credits + delta, Integer.MAX_VALUE / 2);
            lock.notifyAll();
        }
    }

    void onClose() {
        synchronized (lock) {
            remoteClosed = true;
            lock.notifyAll();
        }
        session.maybeRemove(this);
    }

    void onReset(int reason) {
        synchronized (lock) {
            if (error == null) {
                error = new IOException("stream reset by peer (" + reason + ")");
            }
            remoteClosed = true;
            localClosed = true;
            lock.notifyAll();
        }
        session.remove(this);
    }

    void onSessionClosed(IOException cause) {
        synchronized (lock) {
            if (error == null) {
                error = cause;
            }
            remoteClosed = true;
            localClosed = true;
            lock.notifyAll();
        }
    }
}
