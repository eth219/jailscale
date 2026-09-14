package io.jailscale.node;

import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.tls.Tls13;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

/**
 * Server-side TLS over an arbitrary byte stream (ARCHITECTURE.md §9.2): drives an {@link SSLEngine}
 * between the visitor's mux stream and plaintext streams for the relay. The engine's
 * {@code wrap}/{@code unwrap} serialise internally, so one thread may read plaintext while
 * another writes it.
 */
final class TlsEndpoint implements AutoCloseable {

    /**
     * The one key-exchange group offered, and the one ALPN protocol. Fixed so the node can
     * reconstruct what JSSE puts in its ServerHello and EncryptedExtensions ({@link Transcript}):
     * every TLS 1.3 client in use supports X25519, and a ClientHello whose key share is for
     * something else gets a HelloRetryRequest, which the reconstruction covers.
     */
    static final String[] GROUPS = {"x25519"};
    static final int[] GROUP_IDS = {Tls13.GROUP_X25519};
    static final String ALPN = "http/1.1";

    private final SSLEngine engine;
    private final InputStream netIn;
    private final OutputStream netOut;
    /** The plaintext handshake messages of each direction, for the signature's transcript (§9.2). */
    private final Tls13.Tap clientSide = new Tls13.Tap();
    private final Tls13.Tap serverSide = new Tls13.Tap();
    private final ByteBuffer netInBuf;
    private final ByteBuffer appInBuf;
    /** Size of a wrap destination for this engine; the buffer itself comes from {@link OutBuffers}. */
    private final int packetSize;
    private final Object writeLock = new Object();
    private boolean netEof;
    private volatile Runnable onFirstApplicationRead;

    TlsEndpoint(SSLContext ctx, InputStream netIn, OutputStream netOut) {
        this.engine = ctx.createSSLEngine();
        engine.setUseClientMode(false);
        SSLParameters p = engine.getSSLParameters();
        // TLS 1.3 only: the hub signs nothing but a TLS 1.3 server CertificateVerify (§9.2), and a
        // TLS 1.2 ECDHE handshake would ask it to sign a ServerKeyExchange instead.
        p.setProtocols(Tls.TLS13_ONLY);
        p.setApplicationProtocols(Tls.ALPN_HTTP11);
        p.setNamedGroups(GROUPS);
        p.setUseCipherSuitesOrder(true);
        engine.setSSLParameters(p);
        this.netIn = netIn;
        this.netOut = netOut;
        int pkt = engine.getSession().getPacketBufferSize();
        int app = engine.getSession().getApplicationBufferSize();
        this.netInBuf = ByteBuffer.allocate(pkt);
        this.appInBuf = ByteBuffer.allocate(app);
        this.packetSize = pkt;
        appInBuf.flip(); // start empty in read mode
    }

    /**
     * The wrap destinations, shared by every endpoint in the process (§15).
     *
     * <p>{@code netInBuf} and {@code appInBuf} belong to a connection: one holds a TLS record that
     * has not all arrived, the other plaintext nobody has read yet, and both have to survive
     * between calls. The wrap destination does not. {@link #wrapAndWrite} clears it on entry and
     * has written every byte out before it returns, and both consumers copy — {@code Tls13.Tap}
     * into a {@code ByteArrayOutputStream}, {@code MuxStream.write} into a chunk of its own — so
     * nothing outlives the call. It is a buffer that belongs to the work, and it was being
     * allocated per connection: measured against the 1,000-visitor load of §14, 256 of the 1,000
     * were ever in a wrap at once, so about 12 MB of the 16 MB was held by connections doing
     * nothing with it.
     *
     * <p>An exhausted pool allocates rather than waits. Waiting would be the worse bug: the write
     * inside {@code writeLock} blocks when the mux stream is out of flow-control credit (§5.3), so
     * a borrowed buffer can be held for as long as a slow visitor likes, and making others queue
     * behind it would couple connections that share nothing. Allocating instead means the worst
     * case is what the code did before — a buffer per concurrent wrap — and the common case is
     * {@link #MAX_IDLE} of them.
     *
     * <p>Not a {@code ThreadLocal}, which is the obvious shape and the wrong one here: a visitor
     * owns two virtual threads (§12), so thread-locals would hold <em>more</em> buffers than the
     * per-connection fields they replace, not fewer.
     */
    private static final class OutBuffers {

        /** Buffers kept for reuse. Beyond this, a returned buffer is dropped for the GC to take. */
        static final int MAX_IDLE = 64;

        private static final java.util.Queue<ByteBuffer> IDLE = new java.util.concurrent.ConcurrentLinkedQueue<>();
        private static final java.util.concurrent.atomic.AtomicInteger IDLE_COUNT =
            new java.util.concurrent.atomic.AtomicInteger();

        private OutBuffers() {}

        static ByteBuffer acquire(int size) {
            ByteBuffer b = IDLE.poll();
            if (b != null) {
                IDLE_COUNT.decrementAndGet();
                if (b.capacity() >= size) {
                    return b;
                }
                // An engine wanting a larger record than the pooled buffers were sized for: drop it.
            }
            return ByteBuffer.allocate(size);
        }

        static void release(ByteBuffer b) {
            // Claim the slot before taking it: a plain get-then-increment lets every releaser in a
            // burst read the same under-cap value and keep its buffer, so the cap holds only when
            // nobody contends for it -- which is exactly when it does not matter.
            int n;
            do {
                n = IDLE_COUNT.get();
                if (n >= MAX_IDLE) {
                    return;
                }
            } while (!IDLE_COUNT.compareAndSet(n, n + 1));
            IDLE.add(b);
        }

        /** Buffers held for reuse right now. Tests assert the cap; nothing else reads it. */
        static int idle() {
            return IDLE_COUNT.get();
        }
    }

    /** Wrap buffers held for reuse right now (tests). */
    static int pooledBuffers() {
        return OutBuffers.idle();
    }

    /** The cap on buffers kept for reuse (tests). */
    static int maxIdleBuffers() {
        return OutBuffers.MAX_IDLE;
    }

    /** Runs the handshake to completion on the calling thread. */
    void handshake() throws IOException {
        engine.beginHandshake();
        while (true) {
            switch (engine.getHandshakeStatus()) {
                case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
                    SSLEngineResult r = unwrapOnce();
                    if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                        throw new SSLException("peer closed during handshake");
                    }
                }
                case NEED_WRAP -> wrapAndWrite(ByteBuffer.allocate(0));
                case NEED_TASK -> runTasks();
                case FINISHED, NOT_HANDSHAKING -> {
                    return;
                }
                default -> throw new SSLException("unexpected handshake status " + engine.getHandshakeStatus());
            }
        }
    }

    /**
     * Writes whatever plaintext has been decrypted straight to {@code sink}, and returns how many
     * bytes went or -1 at end of stream. The relay's other shape -- {@code plainIn().read(buf)} --
     * needs a 16 KiB buffer per visitor that exists only to be copied out of, and a visitor's
     * buffers are what the node's memory is (ARCHITECTURE.md §15). The bytes are already decrypted
     * in {@code appInBuf}; a relay that is only moving them to a socket can take them from there.
     *
     * <p>The write is done outside the monitor, on a slice taken under it, so a local app that
     * stops reading cannot block the engine. {@code appInBuf} is only ever filled by the thread
     * that drains it, so the slice cannot be overwritten while it is in flight.
     */
    int drainTo(OutputStream sink) throws IOException {
        while (true) {
            byte[] array;
            int off;
            int n;
            synchronized (appInBuf) {
                if (appInBuf.hasRemaining()) {
                    array = appInBuf.array();
                    off = appInBuf.arrayOffset() + appInBuf.position();
                    n = appInBuf.remaining();
                    appInBuf.position(appInBuf.position() + n);
                    firstApplicationRead();
                } else {
                    array = null;
                    off = 0;
                    n = 0;
                }
            }
            if (array != null) {
                sink.write(array, off, n);
                sink.flush();
                return n;
            }
            if (engine.isInboundDone()) {
                return -1;
            }
            SSLEngineResult r = unwrapOnce();
            if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                return -1;
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                wrapAndWrite(ByteBuffer.allocate(0));
            } else if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                runTasks();
            }
            if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW && netEof) {
                return -1;
            }
        }
    }

    InputStream plainIn() {
        return new InputStream() {
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
                while (true) {
                    synchronized (appInBuf) {
                        if (appInBuf.hasRemaining()) {
                            int n = Math.min(len, appInBuf.remaining());
                            appInBuf.get(b, off, n);
                            firstApplicationRead();
                            return n;
                        }
                    }
                    if (engine.isInboundDone()) {
                        return -1;
                    }
                    SSLEngineResult r = unwrapOnce();
                    if (r.getStatus() == SSLEngineResult.Status.CLOSED) {
                        return -1;
                    }
                    if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_WRAP) {
                        wrapAndWrite(ByteBuffer.allocate(0));
                    } else if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                        runTasks();
                    }
                    if (r.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW && netEof) {
                        return -1;
                    }
                }
            }
        };
    }

    OutputStream plainOut() {
        return new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                write(new byte[] {(byte) b}, 0, 1);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                ByteBuffer src = ByteBuffer.wrap(b, off, len);
                while (src.hasRemaining()) {
                    wrapAndWrite(src);
                }
            }

            @Override
            public void flush() throws IOException {
                netOut.flush();
            }
        };
    }

    /** One unwrap: fills the network buffer from the stream as needed. */
    private SSLEngineResult unwrapOnce() throws IOException {
        synchronized (appInBuf) {
            appInBuf.compact(); // to write mode
            try {
                while (true) {
                    netInBuf.flip();
                    SSLEngineResult r;
                    try {
                        r = engine.unwrap(netInBuf, appInBuf);
                    } finally {
                        netInBuf.compact();
                    }
                    switch (r.getStatus()) {
                        case BUFFER_UNDERFLOW -> {
                            if (netEof) {
                                return r;
                            }
                            int n = netIn.read(netInBuf.array(), netInBuf.position(), netInBuf.remaining());
                            if (n > 0 && !clientSide.done()) {
                                clientSide.accept(netInBuf.array(), netInBuf.position(), n);
                            }
                            if (n < 0) {
                                netEof = true;
                                if (engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING
                                    && engine.getHandshakeStatus() != SSLEngineResult.HandshakeStatus.FINISHED) {
                                    throw new EOFException("visitor closed during handshake");
                                }
                                return r;
                            }
                            netInBuf.position(netInBuf.position() + n);
                        }
                        case BUFFER_OVERFLOW -> {
                            return r; // caller drains appInBuf and retries
                        }
                        default -> {
                            return r;
                        }
                    }
                }
            } finally {
                appInBuf.flip(); // back to read mode
            }
        }
    }

    private void wrapAndWrite(ByteBuffer src) throws IOException {
        synchronized (writeLock) {
            ByteBuffer out = OutBuffers.acquire(packetSize);
            try {
                out.clear(); // a borrowed buffer still holds the last record written through it
                SSLEngineResult r = engine.wrap(src, out);
                if (r.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    throw new SSLException("wrap overflow");
                }
                out.flip();
                // Only [position, limit) is ever read, and wrap just filled it. Anything past the
                // limit is the previous borrower's ciphertext, so reading beyond it here would
                // hand one visitor another's bytes -- which is why the reads below are bounded by
                // remaining() and why OutBuffersTest exists.
                if (out.hasRemaining()) {
                    if (!serverSide.done()) {
                        serverSide.accept(out.array(), out.position(), out.remaining());
                    }
                    netOut.write(out.array(), out.position(), out.remaining());
                    netOut.flush();
                }
                if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    runTasks();
                }
            } finally {
                OutBuffers.release(out);
            }
        }
    }

    private void runTasks() {
        Runnable task;
        while ((task = engine.getDelegatedTask()) != null) {
            task.run();
        }
    }

    @Override
    public void close() {
        try {
            engine.closeOutbound();
            wrapAndWrite(ByteBuffer.allocate(0));
        } catch (IOException ignored) {
            // best effort close_notify
        }
    }

    /** The negotiated session, for {@link SelfProbe} keying material. */
    SSLSession session() {
        return engine.getSession();
    }

    /** The session being negotiated (its cipher suite is known before the signature is asked for). */
    SSLSession handshakeSession() {
        return engine.getHandshakeSession();
    }

    /** The visitor's plaintext handshake messages so far: one ClientHello, or two around a retry. */
    java.util.List<byte[]> clientMessages() {
        return clientSide.messages();
    }

    /** This side's plaintext handshake messages so far: a HelloRetryRequest, if one went out. */
    java.util.List<byte[]> serverMessages() {
        return serverSide.messages();
    }

    /**
     * Runs once, the first time application bytes arrive from the peer.
     *
     * <p>{@link #handshake} returning is not enough for the RFC 5705 exporter on the server side
     * of TLS 1.3: the peer's Finished may not have been processed yet, and until it is, JSSE
     * refuses to export. Application data cannot arrive before that, so this is the first moment
     * the exporter is certain to work.
     */
    void onFirstApplicationRead(Runnable r) {
        this.onFirstApplicationRead = r;
    }

    private void firstApplicationRead() {
        Runnable r = onFirstApplicationRead;
        if (r != null) {
            onFirstApplicationRead = null;
            r.run();
        }
    }
}
