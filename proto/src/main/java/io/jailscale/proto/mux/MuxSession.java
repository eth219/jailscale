package io.jailscale.proto.mux;

import io.jailscale.crypto.NoiseException;
import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonException;
import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.net.DuplexThread;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
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
    /**
     * Window overruns this session tolerates before it treats the peer as broken rather than
     * unlucky. One overrun costs one stream (§5.3); a peer that keeps producing them is not
     * honouring flow control at all, and there is nothing to be gained by staying connected.
     */
    static final int MAX_WINDOW_OVERRUNS = 8;

    /**
     * Protocol messages -- CTRL, RST, KEEPALIVE -- this session will hold for the writer before it
     * treats the peer as gone. A peer that has not taken 256 of them is not taking anything, and
     * blocking the producer instead would be worse, because one of the producers is the reader
     * thread.
     *
     * <p><b>Refills are not counted against this and must not be.</b> Their depth is set by how many
     * streams are draining, which is up to 20,480 on one connection (§12), so any fixed count would
     * be a cap on healthy traffic that ends the session when it is exceeded -- and this one nearly
     * was: 400 streams reached 32 deep before they were coalesced, on the way to 256. A coalesced
     * refill is one small entry per stream and costs kilobytes at the ceiling, so it is bounded by
     * something real without being counted here.
     */
    static final int CONTROL_QUEUE_FRAMES = 256;
    /**
     * Bytes of data frames held for the writer. A handoff, not a second window: a producer that
     * fills it blocks, which is the same backpressure it already had from stream credits, and eight
     * frames is enough that a writer with a draining socket is never idle waiting for one.
     */
    static final int DATA_QUEUE_BYTES = 8 * Frame.MAX_DATA;

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
    private final FlowBudget budget;
    private final Map<Long, MuxStream> streams = new ConcurrentHashMap<>();
    private final AtomicLong nextId;
    private volatile boolean closed;
    /**
     * Frames waiting for the socket, in two FIFOs the writer drains control-first (§5.3).
     *
     * <p>{@link NoiseChannel#write} holds one lock across the encryption and the socket write,
     * because the nonce has to advance in wire order. With every producer calling it directly, one
     * blocked write stalled every frame on the session -- so a visitor's handshake waited on its
     * {@code SignResponse} behind other visitors' data, measured at 12.8 s, and the keepalive waited
     * behind it too. One writer thread and a priority makes the wait depend on what a frame is
     * rather than on who else is sending.
     *
     * <p><b>Two queues and not a priority queue.</b> Order within a class has to hold: control
     * messages refer to each other, and {@code PriorityBlockingQueue} does not order equal
     * priorities. Two FIFOs give that for free and there are only two classes.
     */
    private final ArrayDeque<Frame> controlQueue = new ArrayDeque<>();
    private final ArrayDeque<Frame> dataQueue = new ArrayDeque<>();
    /** Enqueue times, parallel to the queues above, so a frame's wait for the writer is measurable. */
    private final ArrayDeque<Long> controlAt = new ArrayDeque<>();
    private final ArrayDeque<Long> dataAt = new ArrayDeque<>();
    private final Object sendLock = new Object();
    private int dataQueueBytes;
    /** Stream id to refill not yet sent, so repeated refills are one frame. Guarded by sendLock. */
    private final Map<Long, Integer> pendingWindow = new java.util.HashMap<>();
    /** Queued CTRL/RST/KEEPALIVE, which is what {@link #CONTROL_QUEUE_FRAMES} bounds. */
    private int protocolQueued;
    private Thread writer;
    /** Frames of a type this build has no case for; only the first one is logged. */
    private int unknownFrames;
    private final AtomicInteger windowOverruns = new AtomicInteger();
    private Thread reader;
    private Thread keepalive;

    /**
     * {@code budget} bounds the bytes this session's receive queues may hold, together with every
     * other session sharing it (§5.3). There is no overload that leaves it out: the hub and the
     * node each have exactly one call site, and a default would be an unbounded process waiting for
     * someone to notice.
     */
    public MuxSession(NoiseChannel ch, boolean opensEven, Listener listener, FlowBudget budget) {
        this.ch = ch;
        this.opensEven = opensEven;
        this.listener = listener;
        this.budget = budget;
        this.nextId = new AtomicLong(opensEven ? 2 : 1);
        budget.register(this);
    }

    FlowBudget budget() {
        return budget;
    }

    /**
     * One stream overran the window it was granted. The stream goes; the session stays, unless this
     * peer has done it {@link #MAX_WINDOW_OVERRUNS} times.
     */
    void onWindowOverrun(MuxStream s) throws MuxException {
        LOG.warn("stream {} exceeded its receive window; resetting it", s.id());
        s.reset(Frame.RST_WINDOW_OVERRUN);
        int n = windowOverruns.incrementAndGet();
        if (n > MAX_WINDOW_OVERRUNS) {
            throw new MuxException("peer exceeded the receive window on " + n + " streams");
        }
    }

    public void start() {
        startWriter();
        reader = DuplexThread.start("mux-reader", this::readLoop);
        keepalive = Thread.ofVirtual().name("mux-keepalive").start(this::keepaliveLoop);
    }

    /**
     * The writer sits on the send side of this socket while the reader sits on the receive side,
     * which is exactly what {@link DuplexThread} is for: on Windows both are platform threads, so
     * the socket enters no poller at all and the pair JDK-8334574 needs cannot form.
     */
    private void startWriter() {
        writer = DuplexThread.start("mux-writer", this::writeLoop);
    }

    /**
     * Runs the reader on the calling thread instead of starting one (for a session-owning thread).
     *
     * <p>Where the reader needs a thread of its own kind ({@link DuplexThread} -- every other
     * thread here writes this same socket), it gets one and this waits for it, which is the same
     * thing from the caller's side: it returns when the session is over either way.
     */
    public void run() {
        startWriter();
        keepalive = Thread.ofVirtual().name("mux-keepalive").start(this::keepaliveLoop);
        if (!DuplexThread.needed()) {
            readLoop();
            return;
        }
        reader = DuplexThread.start("mux-reader", this::readLoop);
        try {
            reader.join();
        } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
            close();
        }
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

    /**
     * The live stream collection, not a copy. Only for {@link FlowBudget}'s victim scan, which runs
     * on a reader thread while the heap is at its limit: copying a thousand streams per arriving
     * frame allocates hardest exactly when there is least room, and the scan does not need a
     * stable snapshot to pick the fullest queue. Weakly consistent iteration is the right
     * guarantee here -- a stream that appears or vanishes mid-scan is one the next frame will see.
     */
    Collection<MuxStream> streamsView() {
        return streams.values();
    }

    public void control(byte[] json) throws IOException {
        write(Frame.ctrl(json));
    }

    /** Opens a stream toward the peer with the given metadata. */
    public MuxStream open(JsonObject meta, boolean dgram) throws IOException {
        return open(meta, dgram, s -> { });
    }

    /**
     * As above, running {@code beforeThePeerKnows} after the stream exists here and before the
     * OPEN frame that tells the peer about it is written.
     *
     * <p>That gap is the whole reason this exists. Whatever the opener has to record about a
     * stream, the peer can ask about the moment the OPEN frame lands -- and a peer on the other
     * side of a loopback socket is quick. The hub opened a visitor stream, then recorded it, and a
     * node that asked the hub to sign for it in between was told {@code not-your-stream}: 238
     * times in 155 ms on one run of the load test, which is
     * <a href="https://github.com/eth219/jailscale/issues/201">#201</a>.
     *
     * <p>If it throws, the stream is taken back out and the OPEN frame is never written, so the
     * peer never hears of a stream whose registration failed.
     */
    public MuxStream open(JsonObject meta, boolean dgram, java.util.function.Consumer<MuxStream> beforeThePeerKnows)
        throws IOException {
        long id = nextId.getAndAdd(2);
        if (id > 0xFFFFFFFFL) {
            throw new IOException("stream ids exhausted");
        }
        MuxStream s = new MuxStream(this, budget, id, meta, dgram);
        streams.put(id, s);
        try {
            beforeThePeerKnows.accept(s);
            write(new Frame(id, Frame.OPEN, dgram ? Frame.FLAG_DGRAM : 0, Json.writeUtf8(meta.asMap())));
        } catch (IOException | RuntimeException e) {
            streams.remove(id);
            throw e;
        }
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
        } catch (IOException _) {
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

    /**
     * Hands a frame to the writer. Every send on this session goes through here, which is what makes
     * one priority decision enough.
     *
     * <p>A socket failure now surfaces on the writer thread rather than to this caller, so it
     * arrives as the session shutting down: the next call throws, and a stream's reader or writer
     * sees the error {@link MuxStream#onSessionClosed} set. One step later than before, and the same
     * outcome -- nothing retries a frame either way.
     */
    private void write(Frame f) throws IOException {
        if (closed) {
            throw new IOException("session closed");
        }
        synchronized (sendLock) {
            if (isControl(f)) {
                if (f.type() != Frame.WINDOW && ++protocolQueued > CONTROL_QUEUE_FRAMES) {
                    protocolQueued--;
                    throw new IOException("control queue full after " + CONTROL_QUEUE_FRAMES
                        + " protocol frames; the peer is not reading");
                }
                if (f.type() == Frame.WINDOW) {
                    // Coalesced, not queued one per refill. A reader draining fast emits a refill
                    // every half window per stream, and while the writer is inside one socket write
                    // those pile up -- measured at 32 deep with 400 streams, on the way to a bound
                    // that used to end the session. Deltas are additive, so N refills for a stream
                    // are one frame carrying their sum, and the queue can hold at most one entry
                    // per stream however hard the reader works.
                    long id = f.streamId();
                    int delta = f.windowDelta();
                    Integer prior = pendingWindow.put(id, pendingWindow.getOrDefault(id, 0) + delta);
                    if (prior == null) {
                        controlQueue.add(f); // a placeholder; the sum is read when it is sent
                        controlAt.add(System.nanoTime());
                    }
                } else {
                    controlQueue.add(f);
                    controlAt.add(System.nanoTime());
                }
            } else {
                while (!dataQueue.isEmpty() && dataQueueBytes + f.payload().length > DATA_QUEUE_BYTES && !closed) {
                    try {
                        sendLock.wait();
                    } catch (InterruptedException _) {
                        Thread.currentThread().interrupt();
                        throw new IOException("interrupted");
                    }
                }
                if (closed) {
                    throw new IOException("session closed");
                }
                dataQueue.add(f);
                dataAt.add(System.nanoTime());
                dataQueueBytes += f.payload().length;
            }
            sendLock.notifyAll();
        }
    }

    /**
     * Whether a frame may go ahead of queued data. CTRL, WINDOW, RST and KEEPALIVE may; everything
     * else, including a type a newer build adds, keeps its place in line.
     *
     * <p><b>CLOSE is deliberately not here</b>, and it is the one that looks like it belongs.
     * {@link MuxStream#onData} drops payloads once the peer has closed, so a CLOSE that overtook
     * data already sent would silently truncate the stream -- a short HTTP response that only
     * appears under load. WINDOW is safe because credit deltas are additive, and RST is safe
     * because discarding what is queued is what RST means. OPEN stays with data so that it cannot
     * arrive after the frames that belong to the stream it opens.
     */
    private static boolean isControl(Frame f) {
        return switch (f.type()) {
            case Frame.CTRL, Frame.WINDOW, Frame.RST, Frame.KEEPALIVE -> true;
            default -> false;
        };
    }

    /**
     * How long frames wait for the writer, how long a write takes, and how long a peer-opened stream
     * waits for its listener. Process-wide sums, counts and high-water marks, no labels, no names --
     * the same bargain as the hub's stage metrics and for the same reason: the gap that mattered was
     * never in the stage anyone had thought to time, and one number per stage measured at once beats
     * one rebuild per guess. Nanos in, seconds out.
     */
    public static final class Timing {
        private final java.util.concurrent.atomic.LongAdder nanos = new java.util.concurrent.atomic.LongAdder();
        private final java.util.concurrent.atomic.LongAdder count = new java.util.concurrent.atomic.LongAdder();
        private final AtomicLong maxNanos = new AtomicLong();

        void record(long elapsed) {
            if (elapsed <= 0) {
                return;
            }
            nanos.add(elapsed);
            count.increment();
            long seen = maxNanos.get();
            if (elapsed > seen) {
                maxNanos.compareAndSet(seen, elapsed);
            }
        }

        public long observations() {
            return count.sum();
        }

        public double totalSeconds() {
            return nanos.sum() / 1e9;
        }

        public double maxSeconds() {
            return maxNanos.get() / 1e9;
        }
    }

    /** A frame's wait between being handed over and the writer taking it. */
    public static final Timing QUEUE_WAIT = new Timing();
    /** One encrypt-and-write, which is where a congested peer shows up. */
    public static final Timing SOCKET_WRITE = new Timing();
    /** A peer-opened stream's wait between the frame arriving and the listener being done with it. */
    public static final Timing OPEN_DISPATCH = new Timing();
    /**
     * One frame's handling on the reader thread. The symmetric gap: a peer's write blocking for
     * seconds means this end is not draining the socket, and nothing measured whether it was.
     */
    public static final Timing READ_DISPATCH = new Timing();
    /** Waiting for the next frame to arrive, which is idle time and not a fault. */
    public static final Timing READ_WAIT = new Timing();

    /** Drains control before data, one frame at a time, until the session ends. */
    private void writeLoop() {
        Throwable cause = null;
        try {
            while (true) {
                Frame f;
                Long queuedAt = null;
                synchronized (sendLock) {
                    while (controlQueue.isEmpty() && dataQueue.isEmpty()) {
                        if (closed) {
                            return;
                        }
                        sendLock.wait();
                    }
                    f = controlQueue.poll();
                    if (f != null) {
                        queuedAt = controlAt.poll();
                    }
                    if (f != null && f.type() == Frame.WINDOW) {
                        Integer sum = pendingWindow.remove(f.streamId());
                        if (sum == null) {
                            continue; // already sent with an earlier frame's sum
                        }
                        f = Frame.window(f.streamId(), sum);
                    } else if (f != null) {
                        protocolQueued--;
                    }
                    if (f == null) {
                        f = dataQueue.poll();
                        queuedAt = dataAt.poll();
                        dataQueueBytes -= f.payload().length;
                        sendLock.notifyAll(); // a producer may be waiting for the room this freed
                    }
                }
                long beforeWrite = System.nanoTime();
                if (queuedAt != null) {
                    QUEUE_WAIT.record(beforeWrite - queuedAt);
                }
                try {
                    ch.write(f);
                } catch (NoiseException e) {
                    throw new IOException("encrypt failed", e);
                }
                SOCKET_WRITE.record(System.nanoTime() - beforeWrite);
            }
        } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
        } catch (IOException e) {
            cause = e;
        } finally {
            if (cause != null) {
                shutdown(cause);
            }
        }
    }

    private void readLoop() {
        Throwable cause = null;
        try {
            while (!closed) {
                Frame f;
                long beforeRead = System.nanoTime();
                try {
                    f = ch.read();
                } catch (SocketTimeoutException _) {
                    throw new IOException("peer idle too long");
                } catch (NoiseException e) {
                    throw new IOException("undecryptable frame", e);
                }
                if (f == null) {
                    throw new IOException("peer closed the connection");
                }
                long afterRead = System.nanoTime();
                READ_WAIT.record(afterRead - beforeRead);
                dispatch(f);
                READ_DISPATCH.record(System.nanoTime() - afterRead);
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
                MuxStream s = new MuxStream(this, budget, id, meta, (f.flags() & Frame.FLAG_DGRAM) != 0);
                streams.put(id, s);
                long beforeOpen = System.nanoTime();
                listener.onOpen(this, s);
                OPEN_DISPATCH.record(System.nanoTime() - beforeOpen);
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
            // Skipped, not fatal (ARCHITECTURE.md §5.4). The frame was fully read before dispatch,
            // so a type this build has no case for costs nothing to drop, and dropping the session
            // instead would make every added frame type a flag day. Logged once per session: the
            // peer that sends one type usually sends many.
            default -> {
                if (unknownFrames++ == 0) {
                    LOG.info("ignoring frame type {}, which this build does not know", f.type());
                }
            }
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
        } catch (InterruptedException _) {
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
        // The writer may be parked on an empty queue and a producer on a full one; both check
        // `closed` once woken. Queued frames are dropped, as they were when a send raced a shutdown.
        synchronized (sendLock) {
            sendLock.notifyAll();
        }
        IOException err = cause instanceof IOException io ? io : new IOException("session closed", cause);
        for (MuxStream s : streams.values()) {
            s.onSessionClosed(err);
        }
        streams.clear();
        budget.unregister(this);
        if (keepalive != null) {
            keepalive.interrupt();
        }
        try {
            ch.close();
        } catch (IOException _) {
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
        if (writer != null) {
            writer.interrupt();
        }
    }
}
