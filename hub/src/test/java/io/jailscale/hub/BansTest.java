package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** ARCHITECTURE.md §11.5: address bans, matched on raw bytes with a prefix mask. */
@Timeout(60)
class BansTest {

    private Path root;
    private Store store;
    private Bans bans;

    @BeforeEach
    void setUp() throws Exception {
        root = TestDirs.newRoot("bans");
        store = new Store(root.resolve("hub"));
        bans = new Bans(store);
    }

    @AfterEach
    void tearDown() throws Exception {
        store.close();
    }

    @Test
    void aSingleAddressBarsOnlyItself() throws Exception {
        store.addBan("203.0.113.7", "noisy");
        assertTrue(bans.isBanned("203.0.113.7"));
        assertFalse(bans.isBanned("203.0.113.8"));
    }

    @Test
    void aBlockBarsEverythingInsideItAndNothingOutside() throws Exception {
        store.addBan("203.0.113.0/24", null);
        assertTrue(bans.isBanned("203.0.113.1"));
        assertTrue(bans.isBanned("203.0.113.255"));
        assertFalse(bans.isBanned("203.0.114.1"));
    }

    @Test
    void aPrefixThatIsNotAWholeNumberOfBytesStillMatches() throws Exception {
        store.addBan("10.0.0.0/12", null); // 10.0.0.0 - 10.15.255.255
        assertTrue(bans.isBanned("10.15.255.255"));
        assertFalse(bans.isBanned("10.16.0.0"));
    }

    @Test
    void v6IsMatchedAndNeverConfusedWithV4() throws Exception {
        store.addBan("2001:db8::/32", null);
        assertTrue(bans.isBanned("2001:db8:1234::1"));
        assertFalse(bans.isBanned("2001:db9::1"));
        assertFalse(bans.isBanned("203.0.113.7"), "a v6 rule must not match a v4 address");
    }

    @Test
    void rubbishIsRejectedRatherThanStored() {
        assertNull(Bans.parse("not-an-address", null, 0));
        assertNull(Bans.parse("203.0.113.0/33", null, 0), "prefix wider than the family");
        assertNull(Bans.parse("203.0.113.0/x", null, 0));
        assertNull(Bans.parse("", null, 0));
        assertNull(Bans.parse(null, null, 0));
        // A hostname would mean a DNS lookup driven by admin input.
        assertNull(Bans.parse("example.com", null, 0));
        assertNotNull(Bans.parse("203.0.113.0/24", null, 0));
    }

    @Test
    void liftingABanTakesEffect() throws Exception {
        store.addBan("203.0.113.7", null);
        assertTrue(bans.isBanned("203.0.113.7"));
        store.removeBan("203.0.113.7");
        assertFalse(bans.isBanned("203.0.113.7"));
    }

    @Test
    void anUnparseableAddressIsNeverBanned() throws Exception {
        store.addBan("0.0.0.0/0", "everything");
        assertTrue(bans.isBanned("203.0.113.7"), "a zero-length prefix matches every v4 address");
        assertFalse(bans.isBanned("not-an-address"));
        assertFalse(bans.isBanned(null));
    }

    @Test
    void aBanSurvivesAReload() throws Exception {
        store.addBan("198.51.100.0/24", "abuse");
        store.close();
        Store reopened = new Store(root.resolve("hub"));
        try {
            assertTrue(new Bans(reopened).isBanned("198.51.100.9"));
            assertEquals("abuse", reopened.bans().get(0).reason());
        } finally {
            reopened.close();
            store = new Store(root.resolve("hub")); // so tearDown has something to close
        }
    }
}
