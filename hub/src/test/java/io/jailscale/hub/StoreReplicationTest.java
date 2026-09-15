package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.nio.file.Files;
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

    @Test
    void whatTheLosingPrimaryHeldIsNamedAndKeptRatherThanSilentlyDropped() throws Exception {
        // ARCHITECTURE.md §13.5: after a partition the epochs settle which host is the primary, and
        // the loser's state does not merge into the winner's -- it is replaced by it. There is no
        // lineage the two stores share, so nothing can tell a name this host has never told anyone
        // about from one the other deliberately released. What can be done is to say what went, and
        // to keep it: a node that joined the losing hub during the partition exists nowhere
        // afterwards, and would otherwise find out by being an unknown machine key.
        Path a = TestDirs.newRoot("winner");
        Path b = TestDirs.newRoot("loser");
        try (Store winner = new Store(a); Store loser = new Store(b)) {
            // Both were primaries for a while. They agree about alice, who joined before the split.
            for (Store s : List.of(winner, loser)) {
                s.registerNode("mkey:alice", "alice", "laptop", "macos");
                s.claimName("web", "alice", "mkey:alice", "127.0.0.1:3000");
            }
            // And then each served someone the other never saw.
            winner.registerNode("mkey:carol", "carol", "ci-box", "linux");
            loser.registerNode("mkey:bob", "bob", "desktop", "linux");
            loser.claimName("bobapp", "bob", "mkey:bob", "127.0.0.1:8080");
            loser.claimDomain("app.example.com", "bob", "mkey:bob");
            loser.assignPort(2222, "tcp", "bob", "mkey:bob", "127.0.0.1:22");
            loser.createAuthKey("jk_partition", "bob", null, 1, 3600);

            Store.Superseded lost = loser.replaceWith(winner.snapshotJson());

            assertTrue(lost.any(), "the loser held things the winner does not");
            assertEquals(List.of("bob/desktop"), lost.nodes());
            assertEquals(List.of("bobapp"), lost.names());
            assertEquals(List.of("app.example.com"), lost.domains());
            assertEquals(List.of(2222), lost.ports());
            assertEquals(1, lost.credentials(), "the auth-key created here");
            // Not what they agreed on, and not what the winner has that this host never had.
            assertFalse(lost.names().contains("web"), "a name both held is not lost");
            assertFalse(lost.nodes().contains("carol/ci-box"), "the winner's own node is not a loss here");

            // The replacement still happened: this host is the winner's copy now.
            assertNull(loser.node("mkey:bob"), "bob is gone from the live state");
            assertNotNull(loser.node("mkey:carol"), "and carol arrived with the snapshot");

            // And what went is recoverable rather than only named: the state as it stood is beside
            // the live one, and it is a snapshot a Store can read.
            assertTrue(Files.exists(lost.kept()), "the superseded state should be kept at " + lost.kept());
            Path recovered = TestDirs.newRoot("recovered");
            Files.copy(lost.kept(), recovered.resolve("state.snapshot"));
            try (Store back = new Store(recovered)) {
                assertNotNull(back.node("mkey:bob"), "bob should be readable from the kept copy");
                assertEquals(1, back.names().stream().filter(n -> n.name().equals("bobapp")).count());
            }
        }
    }

    @Test
    void aRecordThatChangedHandsCountsAsLostAndSoDoAdminsAndBans() throws Exception {
        // A key comparison sees only what vanished. A name released on the losing side and
        // re-claimed there by somebody else is still present under both keys, so it read as "nothing
        // lost" and bob's claim was overwritten in silence; and admins, bans and settings -- rights
        // granted and rights taken away -- were not compared at all.
        Path a = TestDirs.newRoot("winner");
        Path b = TestDirs.newRoot("loser");
        try (Store winner = new Store(a); Store loser = new Store(b)) {
            for (Store s : List.of(winner, loser)) {
                s.registerNode("mkey:alice", "alice", "laptop", "macos");
                s.claimName("web", "alice", "mkey:alice", "127.0.0.1:3000");
            }
            // The losing side released `web` and gave it to bob, and granted an admin and a ban.
            loser.releaseName("web");
            loser.registerNode("mkey:bob", "bob", "desktop", "linux");
            loser.claimName("web", "bob", "mkey:bob", "127.0.0.1:8080");
            loser.addAdmin("bob");
            loser.addBan("198.51.100.0/24", "abuse");

            Store.Superseded lost = loser.replaceWith(winner.snapshotJson());

            assertTrue(lost.names().contains("web"), "a name that changed hands is lost: " + lost);
            assertTrue(lost.nodes().contains("admin bob"), "an admin granted here is lost: " + lost);
            assertTrue(lost.names().contains("ban 198.51.100.0/24"), "a ban placed here is lost: " + lost);
            assertTrue(Files.exists(lost.kept()), "and all of it is kept");
        }
    }

    @Test
    void anOrdinaryResyncLosesNothingAndLeavesNoFile() throws Exception {
        // The common case by far: a standby's state came from this primary, so a fresh snapshot
        // takes nothing away and must not leave a warning or a file behind for an operator to
        // wonder about.
        Path a = TestDirs.newRoot("primary");
        Path b = TestDirs.newRoot("standby");
        try (Store primary = new Store(a); Store standby = new Store(b)) {
            primary.registerNode("mkey:alice", "alice", "laptop", "macos");
            primary.claimName("web", "alice", "mkey:alice", "127.0.0.1:3000");
            standby.replaceWith(primary.snapshotJson());

            Store.Superseded again = standby.replaceWith(primary.snapshotJson());
            assertFalse(again.any(), "a resync of the same state loses nothing: " + again);
            // `kept` names a copy that exists or nothing at all, so there is no path here to
            // check -- which is the point: nothing may send an operator to a file that was never
            // written. The directory is asked directly instead.
            assertNull(again.kept(), "nothing was lost, so there is no copy to name");
            assertFalse(Files.exists(b.resolve("state.superseded.snapshot")), "and none was written");

            // And a copy left by an earlier hand-off is removed rather than left beside a fresh
            // state.snapshot for the next incident's operator to read as this incident's losses.
            Files.writeString(b.resolve("state.superseded.snapshot"), "{}");
            standby.replaceWith(primary.snapshotJson());
            assertFalse(Files.exists(b.resolve("state.superseded.snapshot")), "a stale copy should be cleared");
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
