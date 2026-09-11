package io.jailscale.proto.mux;

import io.jailscale.crypto.NoiseException;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonException;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The multiplexer over one {@link NoiseChannel} (ARCHITECTURE.md §5.3): stream 0 carries control JSON,
 * other streams carry bytes with per-stream flow control. One reader thread dispatches frames;
 * a keepalive thread sends KEEPALIVE every 25 s.
 *
 * <p>The hub opens even stream ids, the node odd ones.
 */
public final class MuxSession implements AutoCloseable {

    private static final Log LOG = Log.get("mux");
    public static final int KEEPALIVE_SECONDS = 25;

    /** Events for the owner of the session. Callbacks run on the reader thread; keep them short. */
    public interface Listener {
        void onControl(MuxSession session, byte[] json) throws IOException;

        /** A peer-opened stream. The listener must hand it to its own thread. */
        void onOpen(MuxSession session, MuxStream stream);

        void onClosed(MuxSession session, Throwable cause);
    }

    private final NoiseChannel ch;
    private final boolean opensEven;
    private final Listener listener;
    private final Map<Long, MuxStream> streams = new ConcurrentHashMap<>();
    private final AtomicLong nextId;
    private volatile boolean closed;
    private Thread reader;
    private Thread keepalive;

    public MuxSession(NoiseChannel ch, boolean opensEven, Listener listener) {
        this.ch = ch;
        this.opensEven = opensEven;
        this.listener = listener;
        this.nextId = new AtomicLong(opensEven ? 2 : 1);
    }

    public void start() {
        reader = Thread.ofVirtual().name("mux-reader").start(this::readLoop);
        keepalive = Thread.ofVirtual().name("mux-keepalive").start(this::keepaliveLoop);
    }

    /** Runs the reader on the calling thread instead of starting one (for a session-owning thread). */
    public void run() {
        keepalive = Thread.ofVirtual().name("mux-keepalive").start(this::keepaliveLoop);
        readLoop();
    }

    public byte[] handshakeHash() {
        return ch.handshakeHash();
    }

    public boolean isClosed() {
        return closed;
    }

    public int streamCount() {
        return streams.size();
    }

    public MuxStream stream(long id) {
        return streams.get(id);
    }

    public List<MuxStream> streams() {
        return new ArrayList<>(streams.values());
    }

    public void control(byte[] json) throws IOException {
        write(Frame.ctrl(json));
    }

    /** Opens a stream toward the peer with the given metadata. */
    public MuxStream open(JsonObject meta, boolean dgram) throws IOException {
        long id = nextId.getAndAdd(2);
        if (id > 0xFFFFFFFFL) {
            throw new IOException("stream ids exhausted");
        }
        MuxStream s = new MuxStream(this, id, meta, dgram);
        streams.put(id, s);
        write(new Frame(id, Frame.OPEN, dgram ? Frame.FLAG_DGRAM : 0, Json.writeUtf8(meta.asMap())));
        return s;
    }

    void sendData(long id, byte[] chunk, boolean dgram) throws IOException {
        write(new Frame(id, Frame.DATA, dgram ? Frame.FLAG_DGRAM : 0, chunk));
    }

    void sendWindow(long id, int delta) throws IOException {
        write(Frame.window(id, delta));
    }

    void sendClose(long id) throws IOException {
        write(Frame.close(id));
    }

    void sendReset(long id, int reason) {
        try {
            write(Frame.rst(id, reason));
        } catch (IOException ignored) {
            // session is going away
        }
    }

    void maybeRemove(MuxStream s) {
        if (s.isFullyClosed()) {
            streams.remove(s.id(), s);
        }
    }

    void remove(MuxStream s) {
        streams.remove(s.id(), s);
    }

    private void write(Frame f) throws IOException {
        if (closed) {
            throw new IOException("session closed");
        }
        try {
            ch.write(f);
        } catch (NoiseException e) {
            throw new IOException("encrypt failed", e);
        }
    }

    private void readLoop() {
        Throwable cause = null;
        try {
            while (!closed) {
                Frame f;
                try {
                    f = ch.read();
                } catch (SocketTimeoutException e) {
                    throw new IOException("peer idle too long");
                } catch (NoiseException e) {
                    throw new IOException("undecryptable frame", e);
                }
                if (f == null) {
                    throw new IOException("peer closed the connection");
                }
                dispatch(f);
            }
        } catch (IOException | MuxException e) {
            cause = e;
        } catch (RuntimeException e) {
            cause = e;
            LOG.warn("mux reader failed", e);
        } finally {
            shutdown(cause);
        }
    }

    private void dispatch(Frame f) throws IOException, MuxException {
        long id = f.streamId();
        switch (f.type()) {
            case Frame.KEEPALIVE -> { }
            case Frame.CTRL -> {
                if (id != Frame.CONTROL_STREAM) {
                    throw new MuxException("CTRL on stream " + id);
                }
                listener.onControl(this, f.payload());
            }
            case Frame.OPEN -> {
                if (id == 0 || (id % 2 == 0) == opensEven) {
                    throw new MuxException("peer opened stream " + id + " with our parity");
                }
                if (streams.containsKey(id)) {
                    throw new MuxException("stream " + id + " already open");
                }
                JsonObject meta;
                try {
                    meta = Json.parseObject(f.payload());
                } catch (JsonException e) {
                    throw new MuxException("bad OPEN metadata: " + e.getMessage());
                }
                MuxStream s = new MuxStream(this, id, meta, (f.flags() & Frame.FLAG_DGRAM) != 0);
                streams.put(id, s);
                listener.onOpen(this, s);
            }
            case Frame.DATA -> {
                MuxStream s = streams.get(id);
                if (s != null) {
                    s.onData(f.payload());
                }
            }
            case Frame.WINDOW -> {
                MuxStream s = streams.get(id);
                if (s != null) {
                    s.onWindow(f.windowDelta());
                }
            }
            case Frame.CLOSE -> {
                MuxStream s = streams.get(id);
                if (s != null) {
                    s.onClose();
                }
            }
            case Frame.RST -> {
                MuxStream s = streams.get(id);
                if (s != null) {
                    s.onReset(f.payload().length > 0 ? f.payload()[0] & 0xff : 0);
                }
            }
            default -> throw new MuxException("unknown frame type " + f.type());
        }
    }

    private void keepaliveLoop() {
        try {
            while (!closed) {
                Thread.sleep(KEEPALIVE_SECONDS * 1000L);
                if (!closed) {
                    write(Frame.keepalive());
                }
            }
        } catch (InterruptedException ignored) {
            // session ended
        } catch (IOException e) {
            shutdown(e);
        }
    }

    private void shutdown(Throwable cause) {
        boolean first;
        synchronized (this) {
            first = !closed;
            closed = true;
        }
        if (!first) {
            return;
        }
        IOException err = cause instanceof IOException io ? io : new IOException("session closed", cause);
        for (MuxStream s : streams.values()) {
            s.onSessionClosed(err);
        }
        streams.clear();
        if (keepalive != null) {
            keepalive.interrupt();
        }
        try {
            ch.close();
        } catch (IOException ignored) {
            // closing
        }
        listener.onClosed(this, cause);
    }

    @Override
    public void close() {
        shutdown(null);
        if (reader != null) {
            reader.interrupt();
        }
    }
}
