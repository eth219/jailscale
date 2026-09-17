package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.net.TestPorts;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * {@link Hub#listenOn} exists so that a test's port is never held by nothing between the moment it
 * is chosen and the moment the hub binds it — a window a hub lost four times in two days (#196),
 * because a running hub asks the kernel for port 0 four more times of its own.
 *
 * <p>What is tested here is the refusals. The happy path is tested by every other class in this
 * package, all of which now hand the hub a bound socket: if {@code listenOn} quietly did nothing,
 * {@code start} would bind for itself and hit the socket the test is still holding.
 */
@Timeout(30)
class ListenOnTest {

    private static HubConfig config(Path root, int port) {
        return HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath(),
            Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath(),
            false, HubConfig.POLICY_MEMBERS, true, "hub.test");
    }

    @Test
    void aSecondListenerIsRefusedRatherThanLeakingTheFirst() throws Exception {
        Path root = TestDirs.newRoot("lo1");
        try (ServerSocket first = TestPorts.listen(1024); ServerSocket second = TestPorts.listen(1024)) {
            try (Hub hub = new Hub(config(root, first.getLocalPort()))) {
                hub.listenOn(first);
                // Silently overwriting would leak the first socket for the life of the JVM, and
                // TestPorts has already retired its number so nothing would ever reuse it either.
                assertThrows(IllegalStateException.class, () -> hub.listenOn(second));
            }
            assertTrue(first.isClosed(), "close() gives back a socket the hub never started on");
        }
    }

    @Test
    void aSocketOnAnotherPortIsRefused() throws Exception {
        Path root = TestDirs.newRoot("lo2");
        try (ServerSocket mine = TestPorts.listen(1024); ServerSocket other = TestPorts.listen(1024)) {
            try (Hub hub = new Hub(config(root, mine.getLocalPort()))) {
                // A test disagreeing with itself about its own port reads exactly like the race
                // this method exists to remove, and is not it.
                IllegalArgumentException e =
                    assertThrows(IllegalArgumentException.class, () -> hub.listenOn(other));
                assertTrue(e.getMessage().contains(String.valueOf(other.getLocalPort())), e.getMessage());
            }
        }
    }

    @Test
    void anUnboundSocketIsRefused() throws Exception {
        Path root = TestDirs.newRoot("lo3");
        try (ServerSocket held = TestPorts.listen(1024); ServerSocket unbound = new ServerSocket()) {
            try (Hub hub = new Hub(config(root, held.getLocalPort()))) {
                // The message, not just the type: an unbound socket reports port -1, so the port
                // check below refuses it too and a bare assertThrows passes with the bound check
                // deleted. Measured -- that mutation survived until this line.
                IllegalArgumentException e =
                    assertThrows(IllegalArgumentException.class, () -> hub.listenOn(unbound));
                assertTrue(e.getMessage().contains("bound socket"), e.getMessage());
            }
        }
    }

    @Test
    void theHubServesOnTheSocketItWasGiven() throws Exception {
        Path root = TestDirs.newRoot("lo4");
        ServerSocket given = TestPorts.listen(1024);
        int port = given.getLocalPort();
        try (Hub hub = new Hub(config(root, port))) {
            hub.listenOn(given);
            hub.start();
            // Not "a hub is listening on that port" -- it was listening before start, because the
            // test bound it. What this says is that the hub took THAT socket rather than binding
            // its own, which it could not have done while this one was open.
            assertEquals(port, hub.port());
            assertTrue(given.isBound() && !given.isClosed());
        }
        assertTrue(given.isClosed(), "the hub owns it from listenOn, and close() gives it back");
    }
}
