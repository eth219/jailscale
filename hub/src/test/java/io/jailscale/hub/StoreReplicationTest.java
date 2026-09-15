package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The store's side of replication (ARCHITECTURE.md §13.1): a subscriber gets the state as of the
 * moment it subscribed and every event after it, and a standby that replays those has the same
 * store, on disk as well as in memory.
 */
class StoreReplicationTest {

    @Test
    void aSubscriberGetsTheStateAsOfSubscribingAndEverythingAfter() throws Exception {
        Path a = TestDirs.newRoot("primary");
        Path b = TestDirs.newRoot("standby");
        List<JsonObject> feed = new ArrayList<>();
        try (Store primary = new Store(a); Store standby = new Store(b)) {
            // Something the standby had that the primary does not: it must not survive the snapshot.
            standby.registerNode("mkey:stale", "ghost", "old-box", "linux");
            primary.registerNode("mkey:alice", "alice", "laptop", "macos");
            primary.claimName("web", "alice", "mkey:alice", "127.0.0.1:3000");
            primary.setSetting(Store.SETTING_REGISTRATION, "open");

            String snapshot = primary.subscribe(feed::add);
            assertEquals(0, feed.size(), "subscribing reports nothing that came before it");
            primary.addAdmin("alice");
            primary.createInvite("tok", null, "bob", 1, 3600, 0, "alice", false);
            assertEquals(2, feed.size());

            standby.replaceWith(snapshot);
            for (JsonObject ev : feed) {
                standby.applyReplicated(ev);
            }
            assertSame(primary, standby);
            assertNull(standby.node("mkey:stale"), "what the standby had before the snapshot is gone");
        }
        // And it was persisted, not only applied: a reopened standby reads it back from its own
        // snapshot and log with nothing left to ask the primary for.
        try (Store primary = new Store(a); Store standby = new Store(b)) {
            assertSame(primary, standby);
        }
    }

    @Test
    void unsubscribingStopsTheFeed() throws Exception {
        List<JsonObject> feed = new ArrayList<>();
        try (Store primary = new Store(TestDirs.newRoot("primary"))) {
            java.util.function.Consumer<JsonObject> l = feed::add;
            primary.subscribe(l);
            primary.addAdmin("alice");
            primary.unsubscribe(l);
            primary.addAdmin("bob");
            assertEquals(1, feed.size());
        }
    }

    @Test
    void aSnapshotFromANewerBinaryIsRefused() throws Exception {
        try (Store standby = new Store(TestDirs.newRoot("standby"))) {
            standby.addAdmin("alice");
            IOException e = assertThrows(IOException.class,
                () -> standby.replaceWith("{\"v\":" + (Store.STATE_VERSION + 1) + ",\"nextNodeId\":1,\"events\":[]}"));
            assertTrue(e.getMessage().contains("newer jailhub"), e.getMessage());
            assertTrue(standby.isAdmin("alice"), "a refused snapshot leaves the store as it was");
        }
    }

    private static void assertSame(Store expected, Store actual) throws IOException {
        // The probe registered below is stamped with each store's own clock, so it is compared by
        // id only and left out of the record comparison; on CI the two stamps were a millisecond apart.
        assertEquals(withoutProbe(expected.nodes()), withoutProbe(actual.nodes()), "nodes");
        assertEquals(expected.names(), actual.names(), "names");
        assertEquals(expected.admins(), actual.admins(), "admins");
        assertEquals(expected.invites(), actual.invites(), "invites");
        assertEquals(expected.setting(Store.SETTING_REGISTRATION, "?"), actual.setting(Store.SETTING_REGISTRATION, "?"), "settings");
        assertNotNull(actual.node("mkey:alice"));
        // Node ids continue from where the primary's would, or a promoted standby would reuse one.
        assertEquals(expected.registerNode("mkey:probe", "p", "h", "os").id(), actual.registerNode("mkey:probe", "p", "h", "os").id());
    }

    private static List<Store.NodeRec> withoutProbe(List<Store.NodeRec> nodes) {
        List<Store.NodeRec> l = new ArrayList<>();
        for (Store.NodeRec n : nodes) {
            if (!n.mkey().equals("mkey:probe")) {
                l.add(n);
            }
        }
        return l;
    }
}
