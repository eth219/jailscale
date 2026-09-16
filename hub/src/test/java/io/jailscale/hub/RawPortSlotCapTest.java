package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.node.Daemon;
import io.jailscale.node.NodeConfig;
import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * ARCHITECTURE.md §8.1's per-network cap, on the raw ports of §8.4.
 *
 * <p>443 exempts a visitor it cannot attribute: a forwarder on this host that sends no PROXY header
 * folds every visitor in the world onto 127.0.0.1, and capping that address at
 * {@link SniRouter#MAX_PER_IP} caps the world. The raw listener takes the same slot and did not have
 * the same carve-out, so one hub capped nobody on 443 and everybody at 64 on a raw port.
 *
 * <p>Both halves are here, because the exemption is only safe while the cap it is an exception to
 * still applies to everyone else: a test that only held the unattributed case would pass just as
 * well with the cap deleted.
 */
@Timeout(120)
class RawPortSlotCapTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
    /** Above the cap, and above what one test holds open at once. */
    private static final int CEILING = 256;

    private Path root;
    private Hub hub;
    private Daemon node;
    private ServerSocket echo;
    private int rawPort;

    @AfterEach
    void stop() throws Exception {
        for (AutoCloseable c : new AutoCloseable[] {node, hub, echo}) {
            if (c != null) {
                c.close();
            }
        }
    }

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        }
    }

    /** A hub with one raw tcp port open on a node, and no PROXY headers: every visitor is 127.0.0.1. */
    private void start() throws Exception {
        root = TestDirs.newRoot("rpc");
        int port = freePort();
        int lo = freePort();
        HubConfig cfg = HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test").withPortRange(lo, lo);
        hub = new Hub(cfg);
        hub.start();

        echo = new ServerSocket(0, 128, InetAddress.getLoopbackAddress());
        Thread.ofVirtual().start(() -> {
            try {
                while (true) {
                    Socket s = echo.accept();
                    Thread.ofVirtual().start(() -> {
                        try (s) {
                            s.getInputStream().transferTo(s.getOutputStream());
                        } catch (IOException ignored) {
                            // done
                        }
                    });
                }
            } catch (IOException ignored) {
                // closed
            }
        });

        // The bound given rather than derived, so that what this test holds open is decided here
        // and not by the heap the suite happens to run with.
        node = new Daemon(NodeConfig.in(root.resolve("node")), CEILING);
        node.start();
        Path sock = root.resolve("node/jailscale.sock");
        assertTrue(Ipc.call(sock, JsonObject.builder().put("cmd", "up").put("hub", "hub.test").put("addr", "127.0.0.1")
            .put("port", port).put("user", "alice").put("caFile", CERT.toString()).build()).optBool("ok", false));
        JsonObject tcp = Ipc.call(sock, JsonObject.builder().put("cmd", "open")
            .put("port", echo.getLocalPort()).put("kind", "tcp").build());
        assertTrue(tcp.optBool("ok", false), tcp.toString());
        rawPort = tcp.integer("hubPort");
    }

    /**
     * One visitor, held open. True when the port served it, which is a round trip through the
     * node's echo and not merely an accepted socket: a refused visitor is closed after the accept,
     * so connecting always succeeds and only the bytes tell the two apart.
     */
    private boolean served(Socket s, String word) throws IOException {
        s.connect(new InetSocketAddress("127.0.0.1", rawPort), 5000);
        s.setSoTimeout(10_000);
        byte[] out = word.getBytes(StandardCharsets.US_ASCII);
        s.getOutputStream().write(out);
        s.getOutputStream().flush();
        byte[] back = new byte[out.length];
        InputStream in = s.getInputStream();
        int n = 0;
        try {
            while (n < back.length) {
                int r = in.read(back, n, back.length - n);
                if (r < 0) {
                    return false;
                }
                n += r;
            }
        } catch (IOException e) {
            return false;
        }
        return java.util.Arrays.equals(out, back);
    }

    @Test
    void aVisitorThisHubCannotTellApartIsNotCappedOnARawPortEither() throws Exception {
        start();
        List<Socket> open = new ArrayList<>();
        try {
            for (int i = 0; i <= SniRouter.MAX_PER_IP + 2; i++) {
                Socket s = new Socket();
                open.add(s);
                assertTrue(served(s, "visitor-" + i),
                    "visitor " + i + " was refused; 127.0.0.1 is every visitor behind a forwarder that says nothing");
            }
            assertEquals(open.size(), hub.registry().get(node.machineKey()).visitorsInFlight(),
                "every one of them should be a stream on the node");
        } finally {
            for (Socket s : open) {
                s.close();
            }
        }
    }

    /**
     * The cap itself, on the method the raw listener takes its slot through. A hub is not needed
     * and not built: {@code takeSlot} reads nothing but its own table, and the three arguments are
     * exactly what the listener knows about a connection.
     */
    @Test
    void theCapStillAppliesToEveryVisitorTheHubCanPlace() throws Exception {
        SniRouter r = new SniRouter(null);
        InetAddress local = InetAddress.getLoopbackAddress();
        InetAddress elsewhere = InetAddress.getByName("198.51.100.7");

        // Attributed: a PROXY header named the visitor, so the cap applies whatever address the
        // connection itself arrived on -- including loopback, which is where it arrives from a
        // forwarder on this host that does send the header.
        for (int i = 0; i < SniRouter.MAX_PER_IP; i++) {
            assertTrue(r.takeSlot("203.0.113.9", local, true) != null, "visitor " + i + " is under the cap");
        }
        assertEquals(null, r.takeSlot("203.0.113.9", local, true),
            "one too many from a network the hub can name is refused, whatever it arrived on");

        // Unattributed and not local: nothing was folded together, so this is one network too.
        for (int i = 0; i < SniRouter.MAX_PER_IP; i++) {
            assertTrue(r.takeSlot(elsewhere.getHostAddress(), elsewhere, false) != null, "visitor " + i);
        }
        assertEquals(null, r.takeSlot(elsewhere.getHostAddress(), elsewhere, false),
            "the exemption is for what the hub cannot tell apart, not for everyone unattributed");

        // And a slot given back is a slot free again: the key returned is what releases it.
        String key = r.takeSlot("203.0.113.10", local, true);
        assertTrue(key != null);
        r.giveSlot(key);
        for (int i = 0; i < SniRouter.MAX_PER_IP; i++) {
            assertTrue(r.takeSlot("203.0.113.10", local, true) != null, "visitor " + i + " after the give-back");
        }
    }
}
