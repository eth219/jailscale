package io.jailscale.proto.mux;

import io.jailscale.proto.json.JsonObject;
import io.jailscale.proto.util.Clock;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;

/**
 * One byte stream (or datagram stream) inside a {@link MuxSession} (ARCHITECTURE.md §5.3). The session's
 * reader thread feeds {@link #onData} etc.; application threads use {@link #in()}/{@link #out()}.
 * Flow control: the receiver advertises {@link #WINDOW} bytes and refills it with WINDOW frames
 * once half is consumed; the sender blocks when out of credits. That bounds one stream; what bounds
 * their sum is the {@link FlowBudget} the session shares, which resets a stalled stream rather than
 * let the process run out of memory.
 */
public final class MuxStream {

    public static final int WINDOW = 256 * 1024;

    private final MuxSession session;
    private final FlowBudget budget;
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
    /**
     * Whether {@link #inboundBytes} is still counted against the budget. An abort releases the
     * whole queue at once, and without this a reader draining what an abort left behind would
     * release those bytes a second time, talking the budget down below what is really held.
     */
    private boolean accounted = true;
    /**
     * When a reader last took bytes out: what tells a slow stream from a stalled one. <b>Zero until
     * one has</b>, not the creation time, which is a difference the budget turns on.
     *
     * <p>Seeded with the clock, a stream that has never read a byte looks freshly active for its
     * first {@code STALL_MS}. A burst of stalled streams arriving at once is then invisible to
     * reclaim's first choice, it falls through to "fullest queue", and the fullest queue belongs to
     * the established slow reader that has had time to accumulate one -- so the burst survives and
     * the legitimate visitor is reset, which is backwards and is reachable on purpose by anyone who
     * opens streams in a burst. A stream that has consumed nothing has, factually, not consumed
     * since forever; zero says that. It costs nothing in the other direction, because a stream
     * holding nothing is skipped on queue depth before its timestamp is ever read.
     */
    private volatile long lastConsumedAt;
    /**
     * {@link #inboundBytes} while it is still accounted, published for reading without {@link #lock}.
     * The budget's victim scan looks at every stream on a reader thread to choose one, and taking a
     * thousand monitors to do it blocks every other stream on that connection for as long as it
     * takes -- the head-of-line stall the per-stream window exists to prevent, reintroduced by the
     * thing meant to protect it. Written only under {@code lock}, so it is never a torn value.
     */
    private volatile int queued;
    /**
     * When an inbound wait gives up, on {@link Clock}'s scale, meaningful
     * only while {@link #hasDeadline}. A separate flag rather than a sentinel value: the moment is
     * a sum involving a clock with no defined origin, so every long is a value it might legitimately
     * take, and picking one to mean "no deadline" means a stream that lands on it waits for ever.
     */
    private volatile long readDeadline;
    private volatile boolean hasDeadline;

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
            int n;
            int refill = 0;
            synchronized (lock) {
                while (current == null && inbound.isEmpty() && !remoteClosed && error == null) {
                    awaitInbound();
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
                n = Math.min(len, chunk.length - pos);
                System.arraycopy(chunk, pos, b, off, n);
                currentPos += n;
                if (currentPos == chunk.length) {
                    current = null;
                }
                inboundBytes -= n;
                queued = accounted ? inboundBytes : 0;
                if (accounted) {
                    budget.release(n);
                }
                lastConsumedAt = System.currentTimeMillis();
                consumedSinceWindow += n;
                if (consumedSinceWindow >= WINDOW / 2) {
                    refill = consumedSinceWindow;
                    consumedSinceWindow = 0;
                }
            }
            sendRefill(refill);
            return n;
        }
    };

    /**
     * The thread that drains this stream with {@link #writeTo}, once one has. That path narrows the
     * contract {@link #in()} does not have -- one consumer at a time -- because it leaves the chunk
     * in the queue while it writes, so a second caller would send the same bytes again.
     */
    private volatile Thread drainer;

    /**
     * Writes the next queued chunk straight to {@code sink}, without copying it into a buffer of
     * the caller's first, and returns how many bytes went or -1 at end of stream. What is queued is
     * already a private array -- {@link Frame#decode} allocated it for this stream and nobody else
     * holds it -- so a relay that is only moving bytes to a socket needs no intermediate at all
     * (ARCHITECTURE.md §15).
     *
     * <p><b>The chunk stays queued and accounted until it has been written.</b> Taking it out first
     * and releasing the budget before the write is the obvious shape and it loosens the bound: a
     * visitor that has stopped reading blocks that write for as long as it likes, so at a thousand
     * of them a chunk each would be megabytes the budget cannot see. So: look under the lock, write
     * outside it, then take it out and account for it under the lock again. A write that throws
     * leaves the chunk where it was, which is the true state -- the stream is about to be reset.
     *
     * <p>The cost is that <b>one thread may drain a stream</b>, which {@link #in()} never required;
     * a second caller would write a chunk the first has not removed yet. Both relays give a stream
     * one thread per direction, and a second one is refused here rather than left to corrupt the
     * output.
     */
    public int writeTo(OutputStream sink) throws IOException {
        Thread me = Thread.currentThread();
        Thread other = drainer;
        if (other == null) {
            drainer = me;
        } else if (other != me) {
            throw new IllegalStateException("a stream may be drained by one thread; " + other + " already is");
        }
        byte[] chunk;
        int pos;
        int n;
        synchronized (lock) {
            while (current == null && inbound.isEmpty() && !remoteClosed && error == null) {
                awaitInbound();
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
            n = chunk.length - pos;
        }

        sink.write(chunk, pos, n);

        int refill = 0;
        synchronized (lock) {
            // An abort during the write clears the queue and releases its bytes in one go, so there
            // is nothing here to account for; anything else and this is still the chunk we wrote.
            if (current == chunk && currentPos == pos) {
                current = null;
                currentPos = 0;
                inboundBytes -= n;
                queued = accounted ? inboundBytes : 0;
                if (accounted) {
                    budget.release(n);
                }
                lastConsumedAt = System.currentTimeMillis();
                consumedSinceWindow += n;
                if (consumedSinceWindow >= WINDOW / 2) {
                    refill = consumedSinceWindow;
                    consumedSinceWindow = 0;
                }
            }
        }
        sendRefill(refill);
        return n;
    }

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

    MuxStream(MuxSession session, FlowBudget budget, long id, JsonObject meta, boolean dgram) {
        this.session = session;
        this.budget = budget;
        this.id = id;
        this.meta = meta;
        this.dgram = dgram;
    }

    /**
     * Flow-control state, for a stream that stopped moving. A stall here is always one of two
     * things: the writer is out of credits because a WINDOW frame never arrived, or the reader is
     * waiting for data the peer believes it already sent. Printing both sides tells them apart.
     */
    public String flowState() {
        synchronized (lock) {
            return "credits=" + credits + " inboundBytes=" + inboundBytes
                + " consumedSinceWindow=" + consumedSinceWindow + " queued=" + inbound.size()
                + " localClosed=" + localClosed + " remoteClosed=" + remoteClosed
                + " accounted=" + accounted + " error=" + error;
        }
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

    /**
     * Sends a flow-control refill, never while holding {@link #lock}. The reason has changed and the
     * rule has not. It used to matter absolutely: {@code sendWindow} ended in a blocking socket write
     * under the session's write lock, so a reader that refilled inside the lock stalled its own
     * stream whenever the send buffer was full, and when both directions congested at once each
     * side's reader sat on the lock its peer's writer needed. Sending is now an enqueue behind a
     * writer thread (§5.3), so that deadlock is gone -- but a producer can still block waiting for
     * room in the data queue, and holding this lock while it did would stall this stream's readers
     * for no reason. Deltas are additive, so emitting them after the lock cannot lose or reorder
     * credit.
     */
    private void sendRefill(int refill) throws IOException {
        if (refill > 0) {
            session.sendWindow(id, refill);
        }
    }

    public OutputStream out() {
        return out;
    }

    /**
     * Bounds the next {@code millis} of reads on this stream: past that moment a read throws
     * {@link MuxTimeoutException} and leaves the stream as it was, so what to do about it stays
     * with the caller, which is normally to reset it. There is no deadline until this is called and
     * {@link #noReadDeadline()} takes it off again.
     *
     * <p><b>A duration in, a moment inside.</b> The bound is absolute once set -- that is the whole
     * point, below -- but taking the moment from the caller meant taking a bare {@code long} that
     * had to come from the right clock, and a value from the wrong one does not fail, it waits for
     * twenty-five thousand years. This has no such argument to get wrong: the moment is computed
     * here, from {@link Clock}, which is monotonic because a wall clock that
     * steps forwards would expire every deadline in flight at once.
     *
     * <p><b>A deadline and not a {@code setSoTimeout}</b>, which is the shape of every other timeout
     * around this and the wrong one here. An idle timeout restarts on each byte, so a peer that
     * sends one byte just inside it holds the stream for ever: the bound buys nothing against
     * exactly the caller it would be set for. The phases anyone has wanted to bound -- a visitor's
     * TLS handshake, its first request (ARCHITECTURE.md §9.3) -- are each finished by some moment or
     * not at all, and a moment is what this takes.
     *
     * <p><b>Reads only.</b> A blocked write is waiting on the peer's flow-control credit, and
     * whether to cut that off is {@link FlowBudget}'s question: it can see what the wait is costing
     * in queued bytes, which is what makes a victim choosable there and not here.
     *
     * <p>Nothing sets one unless it means to bound a phase, and no stream carries one for its whole
     * life: a link that is idle by design -- a websocket, an SSE stream, a database session over a
     * raw port -- is a stream nobody may put a clock on.
     */
    public void readDeadlineIn(long millis) {
        long now = Clock.millis();
        long at = now + Math.max(1, millis);
        // Saturating, because the sum is the caller's number plus a clock reading: a caller passing
        // Long.MAX_VALUE to mean "effectively never" would otherwise wrap to a moment already past
        // and every read on the stream would give up at once.
        readDeadline = at < now ? Long.MAX_VALUE : at;
        hasDeadline = true;                 // after the moment, so a reader never sees a stale one
    }

    /** Takes the deadline off: reads wait for the peer for as long as it likes again. */
    public void noReadDeadline() {
        hasDeadline = false;
    }

    /**
     * One inbound wait, bounded by {@link #readDeadlineIn}. The caller holds {@code lock}, which is
     * what makes the {@code wait} here the same wait it replaced; with no deadline set the argument
     * is 0, which is {@code Object.wait}'s own "for ever", so that path is unchanged.
     */
    private void awaitInbound() throws IOException {
        long left = 0;
        if (hasDeadline) {
            left = readDeadline - Clock.millis();
            if (left <= 0) {
                throw new MuxTimeoutException("stream " + id + ": nothing arrived by its read deadline");
            }
        }
        try {
            lock.wait(left);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted");
        }
    }

    /** Datagram streams: the next whole datagram, or null when the peer closed. */
    public byte[] receive() throws IOException {
        byte[] d;
        int refill = 0;
        synchronized (lock) {
            while (inbound.isEmpty() && !remoteClosed && error == null) {
                awaitInbound();
            }
            if (inbound.isEmpty()) {
                if (error != null) {
                    throw error;
                }
                return null;
            }
            d = inbound.poll();
            inboundBytes -= d.length;
            queued = accounted ? inboundBytes : 0;
            if (accounted) {
                budget.release(d.length);
            }
            lastConsumedAt = System.currentTimeMillis();
            consumedSinceWindow += d.length;
            if (consumedSinceWindow >= WINDOW / 2) {
                refill = consumedSinceWindow;
                consumedSinceWindow = 0;
            }
        }
        sendRefill(refill);
        return d;
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
            // The wait above also ends when this side closes, and that is not permission to send.
            // Without this the close raced past the credit check: the datagram went out on a
            // half-closed stream and took `credits` negative on the way, so every later send on
            // it blocked against a debt no WINDOW frame was ever going to repay. `write` has
            // always refused here; this is the same refusal for the datagram path.
            if (localClosed) {
                throw new IOException("stream closed");
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
        budget.release(abort(new IOException("stream reset (" + reason + ")"), true));
        session.sendReset(id, reason);
        session.remove(this);
    }

    /**
     * Gives this stream's queued bytes back to the budget and sends the RST. Returns what was freed.
     *
     * <p>This used to hand the RST to a virtual thread of its own: the caller is a session reader
     * thread that is not necessarily this stream's, and {@code sendReset} ended in a blocking socket
     * write, so doing it here let one congested peer stall an unrelated peer's reader -- the shape of
     * the problem this budget exists to fix. Sending is now an enqueue behind a writer thread
     * (§5.3), so the reason is gone and so is the thread.
     */
    long reclaim() {
        long freed = abort(new IOException("stream reset: the hub's receive budget was full"), true);
        budget.release(freed);
        session.remove(this);
        session.sendReset(id, Frame.RST_NO_BUDGET);
        return freed;
    }

    /**
     * The local half of an abort: fail both directions, wake everyone waiting, and optionally drop
     * what is queued. Returns the bytes that were still counted against the budget, for the caller
     * to release -- once, which is what {@link #accounted} is for.
     */
    private long abort(IOException cause, boolean discard) {
        synchronized (lock) {
            if (error == null) {
                error = cause;
            }
            localClosed = true;
            remoteClosed = true;
            long held = accounted ? inboundBytes : 0;
            accounted = false;
            if (discard) {
                inbound.clear();
                current = null;
                currentPos = 0;
                inboundBytes = 0;
            }
            queued = 0;
            lock.notifyAll();
            return held;
        }
    }

    /** Bytes in this stream's receive queue that the budget is counting. Lock-free by design. */
    long queuedBytes() {
        return queued;
    }

    /** When a reader last took bytes out of the queue. */
    long lastConsumedAt() {
        return lastConsumedAt;
    }

    boolean isFullyClosed() {
        synchronized (lock) {
            return localClosed && remoteClosed;
        }
    }

    // --- called by the session reader --------------------------------------------------------

    /**
     * Queues one DATA payload. The budget is charged before the queue takes it and outside the
     * lock, because charging it can reclaim, reclaiming takes another stream's lock, and the stream
     * it picks may be this one.
     */
    void onData(byte[] payload) throws MuxException {
        budget.acquire(payload.length);
        boolean overrun = false;
        boolean accepted = false;
        synchronized (lock) {
            if (!remoteClosed) {
                if (inboundBytes + payload.length > WINDOW + Frame.MAX_DATA) {
                    overrun = true;
                } else {
                    inbound.add(payload);
                    inboundBytes += payload.length;
                    queued = inboundBytes;
                    accepted = true;
                    lock.notifyAll();
                }
            }
        }
        if (!accepted) {
            budget.release(payload.length);
        }
        if (overrun) {
            // Not fatal to the session. The peer broke flow control on one stream, and cutting the
            // connection would take every other visitor on that node down with it -- the same
            // blast radius the budget is here to avoid. The session counts repeats and gives up on
            // a peer that keeps doing it.
            session.onWindowOverrun(this);
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
        budget.release(abort(new IOException("stream reset by peer (" + reason + ")"), true));
        session.remove(this);
    }

    void onSessionClosed(IOException cause) {
        // The queue is left where it is: a reader draining the last bytes before it sees the error
        // is what this has always done, and half a response beats none. The budget stops counting
        // them, because the session is gone and no reader is obliged to come back and release them.
        budget.release(abort(cause, false));
    }
}
