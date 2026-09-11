package io.jailscale.node;

import io.jailscale.proto.tls.Tls;
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
 * Server-side TLS over an arbitrary byte stream (DESIGN.md §10.2): drives an {@link SSLEngine}
 * between the visitor's mux stream and plaintext streams for the relay. The engine's
 * {@code wrap}/{@code unwrap} serialise internally, so one thread may read plaintext while
 * another writes it.
 */
final class TlsEndpoint implements AutoCloseable {

    private final SSLEngine engine;
    private final InputStream netIn;
    private final OutputStream netOut;
    private final ByteBuffer netInBuf;
    private final ByteBuffer appInBuf;
    private final ByteBuffer netOutBuf;
    private final Object writeLock = new Object();
    private boolean netEof;
    private volatile Runnable onFirstApplicationRead;

    TlsEndpoint(SSLContext ctx, InputStream netIn, OutputStream netOut) {
        this.engine = ctx.createSSLEngine();
        engine.setUseClientMode(false);
        SSLParameters p = engine.getSSLParameters();
        p.setProtocols(Tls.PROTOCOLS);
        p.setApplicationProtocols(Tls.ALPN_HTTP11);
        p.setUseCipherSuitesOrder(true);
        engine.setSSLParameters(p);
        this.netIn = netIn;
        this.netOut = netOut;
        int pkt = engine.getSession().getPacketBufferSize();
        int app = engine.getSession().getApplicationBufferSize();
        this.netInBuf = ByteBuffer.allocate(pkt);
        this.appInBuf = ByteBuffer.allocate(app);
        this.netOutBuf = ByteBuffer.allocate(pkt);
        appInBuf.flip(); // start empty in read mode
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

    String applicationProtocol() {
        return engine.getApplicationProtocol();
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
            netOutBuf.clear();
            SSLEngineResult r = engine.wrap(src, netOutBuf);
            if (r.getStatus() == SSLEngineResult.Status.BUFFER_OVERFLOW) {
                throw new SSLException("wrap overflow");
            }
            netOutBuf.flip();
            if (netOutBuf.hasRemaining()) {
                netOut.write(netOutBuf.array(), netOutBuf.position(), netOutBuf.remaining());
                netOut.flush();
            }
            if (r.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                runTasks();
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
