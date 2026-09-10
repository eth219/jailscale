package io.jailscale.proto.mux;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.jailscale.crypto.NoiseException;
import io.jailscale.crypto.NoiseIk;
import io.jailscale.crypto.X25519;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(10)
class NoiseChannelTest {

    private static final byte[] PROLOGUE = "jailscale-control-v1".getBytes();

    /** A loopback socket pair: unlike piped streams it has no thread affinity and closes like a real peer. */
    private record Duplex(Socket a, Socket b) implements AutoCloseable {
        static Duplex create() throws IOException {
            try (ServerSocket ss = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
                Socket a = new Socket(InetAddress.getLoopbackAddress(), ss.getLocalPort());
                Socket b = ss.accept();
                a.setTcpNoDelay(true);
                b.setTcpNoDelay(true);
                return new Duplex(a, b);
            }
        }

        InputStream aIn() throws IOException { return a.getInputStream(); }
        OutputStream aOut() throws IOException { return a.getOutputStream(); }
        InputStream bIn() throws IOException { return b.getInputStream(); }
        OutputStream bOut() throws IOException { return b.getOutputStream(); }

        @Override
        public void close() throws IOException {
            a.close();
            b.close();
        }
    }

    @Test
    void handshakeThenFramesBothWays() throws Exception {
        X25519.Keypair hub = X25519.generate();
        X25519.Keypair node = X25519.generate();
        Duplex d = Duplex.create();
        ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
        try {
            Future<NoiseChannel> hubSide = ex.submit(() -> NoiseChannel.respond(d.bIn(), d.bOut(),
                NoiseIk.responder(PROLOGUE, hub), (p1, hs) -> {
                    assertArrayEquals("hi".getBytes(), p1);
                    assertArrayEquals(node.publicKey(), hs.remoteStatic());
                    return "welcome".getBytes();
                }));
            NoiseChannel nodeSide = NoiseChannel.initiate(d.aIn(), d.aOut(),
                NoiseIk.initiator(PROLOGUE, node, hub.publicKey()), "hi".getBytes());
            NoiseChannel hubCh = hubSide.get();
            assertArrayEquals(nodeSide.handshakeHash(), hubCh.handshakeHash());

            nodeSide.write(Frame.ctrl("{\"t\":\"Ping\",\"id\":5}".getBytes()));
            nodeSide.write(Frame.keepalive());
            Frame f1 = hubCh.read();
            Frame f2 = hubCh.read();
            assertEquals(Frame.CTRL, f1.type());
            assertEquals("{\"t\":\"Ping\",\"id\":5}", new String(f1.payload()));
            assertEquals(Frame.KEEPALIVE, f2.type());

            byte[] big = new byte[Frame.MAX_DATA];
            big[0] = 1;
            hubCh.write(Frame.data(2, big));
            Frame f3 = nodeSide.read();
            assertEquals(2, f3.streamId());
            assertArrayEquals(big, f3.payload());

            nodeSide.close();
            assertNull(hubCh.read()); // clean EOF
        } finally {
            ex.shutdownNow();
            d.close();
        }
    }

    @Test
    void wrongHubKeyFailsHandshake() throws Exception {
        X25519.Keypair hub = X25519.generate();
        X25519.Keypair other = X25519.generate();
        X25519.Keypair node = X25519.generate();
        Duplex d = Duplex.create();
        ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
        try {
            // A real peer closes the socket when its handshake fails; emulate that on the pipe so
            // the initiator, which is waiting for message 2, sees EOF instead of hanging.
            Future<?> hubSide = ex.submit(() -> {
                try {
                    return NoiseChannel.respond(d.bIn(), d.bOut(), NoiseIk.responder(PROLOGUE, hub), (p1, hs) -> new byte[0]);
                } finally {
                    d.b().close();
                }
            });
            assertThrows(Exception.class, () -> {
                NoiseChannel.initiate(d.aIn(), d.aOut(), NoiseIk.initiator(PROLOGUE, node, other.publicKey()), null);
            });
            assertThrows(Exception.class, hubSide::get);
        } finally {
            ex.shutdownNow();
            d.close();
        }
    }

    @Test
    void tamperedFrameIsRejected() throws Exception {
        X25519.Keypair hub = X25519.generate();
        X25519.Keypair node = X25519.generate();
        Duplex d = Duplex.create();
        ExecutorService ex = Executors.newVirtualThreadPerTaskExecutor();
        try {
            Future<NoiseChannel> hubSide = ex.submit(() -> NoiseChannel.respond(d.bIn(), d.bOut(),
                NoiseIk.responder(PROLOGUE, hub), (p1, hs) -> new byte[0]));
            NoiseChannel nodeSide = NoiseChannel.initiate(d.aIn(), d.aOut(),
                NoiseIk.initiator(PROLOGUE, node, hub.publicKey()), null);
            NoiseChannel hubCh = hubSide.get();
            // Write a bogus ciphertext straight onto the wire, bypassing the channel.
            d.aOut().write(new byte[] {0, 20});
            d.aOut().write(new byte[20]);
            d.aOut().flush();
            assertThrows(NoiseException.class, hubCh::read);
            nodeSide.close();
        } finally {
            ex.shutdownNow();
            d.close();
        }
    }
}
