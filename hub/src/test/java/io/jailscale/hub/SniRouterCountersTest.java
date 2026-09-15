package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The per-address connection counter of ARCHITECTURE.md §8.1. It is keyed by visitor address and
 * 443 is the one path that runs before any authentication, so an entry that outlives its
 * connections is memory an attacker grows for the price of a TCP connection. §12 says memory is
 * bounded by the connection limits; for this map that is only true if entries are dropped at zero.
 *
 * <p>The hub reads PROXY headers here so that one loopback test can present many distinct visitor
 * addresses, which is also how the address is obtained in the deployment §8.5 describes.
 */
@Timeout(90)
class SniRouterCountersTest {

    private static final Path CERT = Path.of("src/test/resources/tls/hub-test.crt").toAbsolutePath();
    private static final Path KEY = Path.of("src/test/resources/tls/hub-test.key").toAbsolutePath();
    /** Not a TLS handshake record, so the ClientHello peek refuses it at once and the socket closes. */
    private static final byte[] NOT_TLS = "GET / HTTP/1.1\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

    private Path root;
    private Hub hub;
    private int port;

    @AfterEach
    void stop() throws Exception {
        if (hub != null) {
            hub.close();
        }
    }

    private void startHub() throws Exception {
        root = TestDirs.newRoot("jsc");
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = s.getLocalPort();
        }
        hub = new Hub(HubConfig.withCert(URI.create("https://hub.test:" + port), root.resolve("hub"), "127.0.0.1", port,
            CERT, KEY, true, HubConfig.POLICY_MEMBERS, true, "hub.test")
            .withProxyProtocol(true, List.of()).withPortRange(0, 0));
        hub.start();
    }

    /** One connection announcing {@code srcIp}, closed as soon as the hub is done with it. */
    private void visit(String srcIp) {
        try (Socket s = new Socket("127.0.0.1", port)) {
            s.getOutputStream().write(("PROXY TCP4 " + srcIp + " 127.0.0.1 51234 443\r\n").getBytes(StandardCharsets.US_ASCII));
            s.getOutputStream().write(NOT_TLS);
            s.getOutputStream().flush();
            s.getInputStream().read(); // returns when the hub closes its side
        } catch (IOException ignored) {
            // the hub closing on us is the expected end of every connection here
        }
    }

    /** The hub closes the socket a moment before its own finally runs, so settle before asserting. */
    private void awaitNoAddresses() throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000;
        while (hub.router().trackedAddresses() != 0 && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
    }

    /**
     * The leak this exists for: an address connects once and never again. Before the entry was
     * dropped at zero, each of these left a counter behind for the life of the process, so an
     * attacker rotating addresses -- one IPv6 /64 is more than enough -- grew the map without
     * bound, unauthenticated, at one TCP connection each.
     */
    @Test
    void addressesAreForgottenOnceTheirConnectionsAreOver() throws Exception {
        startHub();
        for (int i = 0; i < 400; i++) {
            visit("203.0." + (i / 256) + "." + (i % 256));
        }
        awaitNoAddresses();
        assertEquals(0, hub.router().trackedAddresses(),
            "every connection is over, so no visitor address should still be counted");
    }

    /** While connections are open the counter must still count, or the §8.1 limit is not enforced. */
    @Test
    void addressesAreCountedWhileTheirConnectionsAreOpen() throws Exception {
        startHub();
        // Held open: the hub is waiting up to HELLO_TIMEOUT_MS for a ClientHello that never comes.
        try (Socket a = new Socket("127.0.0.1", port); Socket b = new Socket("127.0.0.1", port)) {
            announce(a, "192.0.2.7");
            announce(b, "192.0.2.8");
            assertTrue(awaitAddresses(2), "two distinct addresses are connected right now");
        }
        awaitNoAddresses();
        assertEquals(0, hub.router().trackedAddresses());
    }

    /**
     * Two connections from one address are one entry, and it survives until the second one ends.
     * Dropping it when the first finished would reset that address's count to zero and let a
     * single address hold more than {@link SniRouter#MAX_PER_IP} connections by reconnecting.
     */
    @Test
    void oneAddressWithTwoConnectionsIsOneEntryUntilBothAreOver() throws Exception {
        startHub();
        try (Socket a = new Socket("127.0.0.1", port)) {
            announce(a, "192.0.2.9");
            assertTrue(awaitAddresses(1));
            try (Socket b = new Socket("127.0.0.1", port)) {
                announce(b, "192.0.2.9");
                Thread.sleep(200);
                assertEquals(1, hub.router().trackedAddresses(), "one address, however many connections");
            }
            Thread.sleep(200);
            assertEquals(1, hub.router().trackedAddresses(), "the first connection is still open");
        }
        awaitNoAddresses();
        assertEquals(0, hub.router().trackedAddresses());
    }

    /**
     * Churn on one address leaves the count at zero rather than drifting negative, which a
     * decrement that outlived its increment would do -- and a negative count is a per-address
     * limit that never triggers again.
     */
    @Test
    void repeatedUseOfOneAddressLeavesItCountingFromZero() throws Exception {
        startHub();
        for (int i = 0; i < 200; i++) {
            visit("192.0.2.1");
        }
        awaitNoAddresses();
        assertEquals(0, hub.router().trackedAddresses());
        try (Socket s = new Socket("127.0.0.1", port)) {
            announce(s, "192.0.2.1");
            assertTrue(awaitAddresses(1), "after the churn the address is counted again from zero");
        }
        awaitNoAddresses();
        assertEquals(0, hub.router().trackedAddresses());
    }

    /**
     * A whole IPv6 /64 is one entry, which is what makes {@link SniRouter#MAX_PER_IP} a limit at all
     * once the listener is bound to {@code ::} -- one flag and an AAAA record away for any operator,
     * and the hub serves both stacks there today. Every ordinary VPS is handed a routed /64, so a
     * cap counted per address would read "64 connections, times eighteen quintillion".
     */
    @Test
    void oneIpv6NetworkIsOneEntryHoweverManyAddressesItUses() throws Exception {
        startHub();
        try (Socket a = new Socket("127.0.0.1", port); Socket b = new Socket("127.0.0.1", port);
            Socket c = new Socket("127.0.0.1", port)) {
            announce6(a, "2001:db8:1:2::1");
            announce6(b, "2001:db8:1:2:ffff:ffff:ffff:ffff");
            assertTrue(awaitAddresses(1), "two addresses in one /64 are one counted network");
            // And a different /64 is somebody else, so the bound is still per party.
            announce6(c, "2001:db8:1:3::1");
            assertTrue(awaitAddresses(2), "a different /64 is counted apart");
        }
        awaitNoAddresses();
        assertEquals(0, hub.router().trackedAddresses());
    }

    private void announce(Socket s, String srcIp) throws IOException {
        s.getOutputStream().write(("PROXY TCP4 " + srcIp + " 127.0.0.1 51234 443\r\n").getBytes(StandardCharsets.US_ASCII));
        s.getOutputStream().flush();
    }

    private void announce6(Socket s, String srcIp) throws IOException {
        s.getOutputStream().write(("PROXY TCP6 " + srcIp + " ::1 51234 443\r\n").getBytes(StandardCharsets.US_ASCII));
        s.getOutputStream().flush();
    }

    private boolean awaitAddresses(int n) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 5_000;
        while (hub.router().trackedAddresses() < n && System.currentTimeMillis() < deadline) {
            Thread.sleep(20);
        }
        return hub.router().trackedAddresses() == n;
    }
}
