package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.control.Message;
import io.jailscale.proto.mux.MuxStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The socket to the local app holds no more in the kernel than the stream may hold on the wire
 * (ARCHITECTURE.md §9.3).
 *
 * <p>What the kernel reports is not what it was handed, and the ways it differs are not worth
 * predicting. It adds its own bookkeeping, and it clamps the request to a machine-wide cap it does
 * not tell you about: on the linux-amd64 runner the receive side comes back as exactly the window
 * and the send side as 212,992, which is {@code net.core.wmem_max} rather than anything this code
 * asked for. Two earlier versions of this test tried to predict that arithmetic -- first assuming
 * Linux doubles the request, then reading the cap out of {@code /proc} -- and both were wrong on a
 * machine they had not run on.
 *
 * <p>So this measures instead of predicting. A second socket to the same listener, with neither call
 * made on it, gives this machine's answer for an unconfigured socket, and what is asserted is what
 * §9.3 actually claims: no more than the window, with room for a kernel that doubles. A kernel that
 * clamps lands below it, which is the machine holding less than it was allowed to -- not a failure
 * of this code.
 *
 * <p><b>That the call took effect is only checked where it can be.</b> It is the configured socket
 * differing from the unconfigured one, and that says nothing on a machine whose own default is
 * already inside the window: 262,144 set over a 65,536 default reads the same either way. So the
 * check is skipped exactly there, which on today's machines leaves the receive side on macOS
 * carrying it -- a 408,300 default, well above the window, and the one that fails when the two
 * calls are deleted. Linux starts both sides below the window and can only be held to the bound.
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
                    assertTrue(pinned(rcv, defaultRcv), why("receive", rcv, defaultRcv));
                    assertTrue(pinned(snd, defaultSnd), why("send", snd, defaultSnd));
                    assertTrue(s.getTcpNoDelay(), "TCP_NODELAY is still set");
                }
            }
        }
    }

    /**
     * No larger than the window, with room for a kernel that doubles what it is given; and, where
     * the machine's own default is above the window and so the difference is visible, not that
     * default.
     */
    private static boolean pinned(int reported, int untouched) {
        boolean bounds = reported <= 2 * MuxStream.WINDOW + MuxStream.WINDOW / 4;
        boolean tookOrCannotTell = reported != untouched || untouched <= MuxStream.WINDOW;
        return bounds && tookOrCannotTell;
    }

    /** Both numbers, so a failure here says which half gave way without a second run. */
    private static String why(String side, int reported, int untouched) {
        return side + " buffer is " + reported + " against a stream window of " + MuxStream.WINDOW
            + " and " + untouched + " on a socket this test did not configure. Above the window means"
            + " it did not bound; equal to that second number, with that number above the window,"
            + " means the call did not take.";
    }
}
