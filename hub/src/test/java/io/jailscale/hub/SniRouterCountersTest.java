package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * The per-address connection counter of ARCHITECTURE.md §8.1. It is keyed by visitor address and
 * 443 is the one path that runs before any authentication, so an entry that outlives its
 * connections is memory an attacker grows for the price of a TCP connection. §12 says memory is
 * bounded by the connection limits; for this map that is only true if entries are dropped at zero.
 *
 * <p>Against {@code takeSlot}/{@code giveSlot} directly rather than through real connections. It
 * used to drive the hub over loopback with a PROXY header per connection, which is how one test
 * host could present four hundred distinct visitor addresses; the hub no longer reads those
 * headers (§8.5 went with the maintenance cut), and a loopback socket can only ever present one
 * address. Calling the pair is the same code path from one frame up -- {@code serve} takes a slot,
 * and gives back exactly what it took -- and it can still fail in the direction that matters: an
 * entry that survives its last release leaves {@code trackedAddresses} above zero.
 *
 * <p>The router is built with no hub because none of this reaches one: the maps and their locks
 * are the whole of what is under test.
 */
@Timeout(30)
class SniRouterCountersTest {

    private final SniRouter router = new SniRouter(null);

    private String take(String ip) throws Exception {
        return router.takeSlot(ip, InetAddress.getByName(ip));
    }

    /**
     * The leak this exists for: an address connects once and never again. Before the entry was
     * dropped at zero, each of these left a counter behind for the life of the process, so an
     * attacker rotating addresses -- one IPv6 /64 is more than enough -- grew the map without
     * bound, unauthenticated, at one TCP connection each.
     */
    @Test
    void addressesAreForgottenOnceTheirConnectionsAreOver() throws Exception {
        for (int i = 0; i < 400; i++) {
            router.giveSlot(take("203.0." + (i / 256) + "." + (i % 256)));
        }
        assertEquals(0, router.trackedAddresses(),
            "every connection is over, so no visitor address should still be counted");
    }

    /** While connections are open the counter must still count, or the §8.1 limit is not enforced. */
    @Test
    void addressesAreCountedWhileTheirConnectionsAreOpen() throws Exception {
        String a = take("192.0.2.7");
        String b = take("192.0.2.8");
        assertEquals(2, router.trackedAddresses(), "two distinct addresses are connected right now");
        router.giveSlot(a);
        router.giveSlot(b);
        assertEquals(0, router.trackedAddresses());
    }

    /**
     * Two connections from one address are one entry, and it survives until the second one ends.
     * Dropping it when the first finished would reset that address's count to zero and let a
     * single address hold more than {@link SniRouter#MAX_PER_IP} connections by reconnecting.
     */
    @Test
    void oneAddressWithTwoConnectionsIsOneEntryUntilBothAreOver() throws Exception {
        String first = take("192.0.2.9");
        String second = take("192.0.2.9");
        assertEquals(1, router.trackedAddresses(), "one address, however many connections");
        router.giveSlot(second);
        assertEquals(1, router.trackedAddresses(), "the first connection is still open");
        router.giveSlot(first);
        assertEquals(0, router.trackedAddresses());
    }

    /**
     * Churn on one address leaves the count at zero rather than drifting negative, which a
     * decrement that outlived its increment would do -- and a negative count is a per-address
     * limit that never triggers again.
     */
    @Test
    void repeatedUseOfOneAddressLeavesItCountingFromZero() throws Exception {
        for (int i = 0; i < 200; i++) {
            router.giveSlot(take("192.0.2.1"));
        }
        assertEquals(0, router.trackedAddresses());
        String again = take("192.0.2.1");
        assertEquals(1, router.trackedAddresses(), "after the churn the address is counted again from zero");
        router.giveSlot(again);
        assertEquals(0, router.trackedAddresses());
    }

    /**
     * And the cap itself, which the socket-driven version could never reach: the 65th connection
     * from one network is refused and, having been refused, leaves nothing behind -- a refusal that
     * kept its increment would lock that network out for the life of the process.
     */
    @Test
    void theSixtyFifthConnectionFromOneNetworkIsRefusedAndTakesNoSlot() throws Exception {
        String[] held = new String[SniRouter.MAX_PER_IP];
        for (int i = 0; i < held.length; i++) {
            held[i] = take("198.51.100.4");
            assertNotNull(held[i], "connection " + (i + 1) + " is inside the cap of " + SniRouter.MAX_PER_IP);
        }
        assertNull(take("198.51.100.4"), "one past the cap is refused");
        for (String key : held) {
            router.giveSlot(key);
        }
        assertEquals(0, router.trackedAddresses(), "the refused connection left no entry of its own");
    }

    /**
     * A v6 visitor is counted against its /64 and not its address, or the cap is "64 per address,
     * times eighteen quintillion" for anyone with a routed prefix -- which is everyone who has v6.
     */
    @Test
    void ipv6IsCountedPerNetworkAndNotPerAddress() throws Exception {
        String one = take("2001:db8:0:1::1");
        String two = take("2001:db8:0:1::2");
        assertEquals(1, router.trackedAddresses(), "two addresses in one /64 are one entry");
        String elsewhere = take("2001:db8:0:2::1");
        assertEquals(2, router.trackedAddresses(), "a different /64 is a different entry");
        router.giveSlot(one);
        router.giveSlot(two);
        router.giveSlot(elsewhere);
        assertEquals(0, router.trackedAddresses());
    }

    /**
     * A forwarder on this host arrives as loopback and folds everyone behind it onto one key, so
     * that key is exempt from the cap: capping it would cap every visitor behind the forwarder
     * together. It is still counted, which is what lets the entry be dropped at zero.
     */
    @Test
    void loopbackIsExemptFromTheCapAndStillCounted() throws Exception {
        String[] held = new String[SniRouter.MAX_PER_IP + 8];
        for (int i = 0; i < held.length; i++) {
            held[i] = take("127.0.0.1");
            assertNotNull(held[i], "a local forwarder is not capped");
        }
        assertEquals(1, router.trackedAddresses());
        for (String key : held) {
            router.giveSlot(key);
        }
        assertEquals(0, router.trackedAddresses());
    }
}
