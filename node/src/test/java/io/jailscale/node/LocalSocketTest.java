package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.mux.MuxStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The socket to the local app holds no more in the kernel than the stream may hold on the wire
 * (ARCHITECTURE.md §9.3).
 *
 * <p>What a kernel reports is not what it was handed. It adds its own bookkeeping -- macOS about
 * six percent, Linux a doubling -- and before that it clamps the request to a machine-wide cap,
 * {@code net.core.rmem_max} and {@code net.core.wmem_max}, which an operator may have set below the
 * window. So "as set" is a band around whichever of the window and that cap is smaller, and the cap
 * is read here rather than assumed: an earlier version of this test assumed the doubling and nothing
 * else, passed on macOS, and failed on every Linux runner from the commit that introduced it.
 *
 * <p>A second socket to the same listener, with neither call made on it, is connected alongside. It
 * is not asserted on by itself -- it is what tells the two assertions below apart from a kernel that
 * ignored the calls entirely, and both failure messages carry it.
 */
@Timeout(30)
class LocalSocketTest {

    @Test
    void localAppSocketBuffersArePinnedToTheStreamWindow() throws Exception {
        try (ServerSocket app = new ServerSocket(0, 8, InetAddress.getLoopbackAddress())) {
            NodeState.LinkRec rec = new NodeState.LinkRec(Message.LinkOpen.HTTPS, "127.0.0.1", app.getLocalPort(), "demo");
            try (Socket untouched = new Socket()) {
                untouched.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), app.getLocalPort()));
                app.accept().close();
                int defaultRcv = untouched.getReceiveBufferSize();
                int defaultSnd = untouched.getSendBufferSize();
                try (Socket s = Visitors.connectLocal(rec)) {
                    app.accept().close();
                    int rcv = s.getReceiveBufferSize();
                    int snd = s.getSendBufferSize();
                    assertTrue(pinned(rcv, defaultRcv, cap("rmem_max")),
                        why("receive", rcv, defaultRcv, cap("rmem_max")));
                    assertTrue(pinned(snd, defaultSnd, cap("wmem_max")),
                        why("send", snd, defaultSnd, cap("wmem_max")));
                    assertTrue(s.getTcpNoDelay(), "TCP_NODELAY is still set");
                }
            }
        }
    }

    /**
     * Set, and seen to have been set. Within an eighth above what the kernel was left to work with,
     * or above twice it, and not the size this machine hands a socket nobody configured.
     */
    private static boolean pinned(int reported, int untouched, int cap) {
        int w = Math.min(MuxStream.WINDOW, cap);
        boolean asSet = (reported >= w && reported <= w + w / 8) || (reported >= 2 * w && reported <= 2 * w + w / 4);
        return asSet && reported != untouched;
    }

    /**
     * This machine's cap on one socket buffer. Linux keeps it where it can be read; everywhere else
     * this test has no way to ask, and no cap below the window has been seen there.
     */
    private static int cap(String knob) {
        try {
            Path p = Path.of("/proc/sys/net/core/" + knob);
            if (Files.exists(p)) {
                return Integer.parseInt(Files.readString(p).trim());
            }
        } catch (IOException | NumberFormatException e) {
            return Integer.MAX_VALUE; // unreadable is the same as unknown
        }
        return Integer.MAX_VALUE;
    }

    /** Everything the next person needs, so a failure here does not cost a round trip to read. */
    private static String why(String side, int reported, int untouched, int cap) {
        return side + " buffer is " + reported + ", which is not the stream window " + MuxStream.WINDOW
            + " as this kernel would report it. Unconfigured socket on this machine: " + untouched
            + ". Cap: " + (cap == Integer.MAX_VALUE ? "unknown" : Integer.toString(cap))
            + ". Equal to the unconfigured socket means the call did not take; between the two means "
            + "the cap is below the window and §9.3's bound is not in force on this machine.";
    }
}
