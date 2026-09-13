package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.mux.MuxStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The socket to the local app holds no more in the kernel than the stream may hold on the wire
 * (ARCHITECTURE.md §9.3). A kernel reports a size it was given with its own bookkeeping on top --
 * macOS adds about six percent, Linux doubles it -- so "as set" is a narrow band around the window
 * or around twice it. The defaults fall outside both bands on both platforms (macOS 408,300 and
 * 146,988 on loopback, Linux 212,992 for either), which is what makes this a test: with the two
 * calls removed it fails on the numbers the kernel chose.
 */
@Timeout(30)
class LocalSocketTest {

    @Test
    void localAppSocketBuffersArePinnedToTheStreamWindow() throws Exception {
        try (ServerSocket app = new ServerSocket(0, 8, InetAddress.getLoopbackAddress())) {
            NodeState.LinkRec rec = new NodeState.LinkRec(Message.LinkOpen.HTTPS, "127.0.0.1", app.getLocalPort(), "demo");
            try (Socket s = Visitors.connectLocal(rec)) {
                app.accept().close();
                int rcv = s.getReceiveBufferSize();
                int snd = s.getSendBufferSize();
                assertTrue(reportsAsSet(rcv), "receive buffer " + rcv + " is not the stream window " + MuxStream.WINDOW);
                assertTrue(reportsAsSet(snd), "send buffer " + snd + " is not the stream window " + MuxStream.WINDOW);
                assertTrue(s.getTcpNoDelay(), "TCP_NODELAY is still set");
            }
        }
    }

    /** Within an eighth above the window, or above twice it: the kernel's rounding, not its choice. */
    private static boolean reportsAsSet(int reported) {
        int w = MuxStream.WINDOW;
        return (reported >= w && reported <= w + w / 8) || (reported >= 2 * w && reported <= 2 * w + w / 4);
    }
}
