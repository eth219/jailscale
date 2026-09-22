package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Everything the hub keeps has to survive a snapshot, because after one the snapshot is the only
 * copy: {@code snapshot()} writes the state out as replayable events, replaces the file and then
 * truncates the log (ARCHITECTURE.md §6.2).
 *
 * <p>That makes a dropped field a nasty shape of bug. Each record's fields are written by hand in
 * three places -- the {@code append()} that records the change, the {@code apply()} switch that
 * replays it, and {@code snapshot()} -- and one left out of the third is invisible for as long as
 * the log still has the original event. It only disappears when a snapshot truncates that log,
 * which happens after a thousand events, which is production and not a test.
 *
 * <p>So this compares whole records rather than naming fields. Records are value types, so a record
 * that gains a component and does not gain a line in {@code snapshot()} fails here without anyone
 * having remembered to extend the test.
 */
class StoreSnapshotTest {

    private static final String NODE = "mkeyalicelaptop";

    @Test
    void everyKindOfRecordSurvivesASnapshotWithAllItsFields() throws Exception {
        Path dir = TestDirs.newRoot("snap");
        Everything before;
        try (Store s = new Store(dir)) {
            fill(s);
            before = capture(s);
            s.snapshot();
        }

        // The log is empty now, so the reopened store below has nowhere to read this from except
        // the snapshot. Without this the test would pass on the replay path and prove nothing.
        assertEquals(0, Files.size(dir.resolve("state.jsonl")));

        try (Store s = new Store(dir)) {
            Everything after = capture(s);
            // Named one at a time first, because a single assertEquals over the whole thing prints
            // both sides in full and leaves the reader to find the one field that moved.
            assertEquals(before.nodes(), after.nodes(), "nodes");
            assertEquals(before.admins(), after.admins(), "admins");
            assertEquals(before.invites(), after.invites(), "invites");
            assertEquals(before.pending(), after.pending(), "pending");
            assertEquals(before.names(), after.names(), "names");
            assertEquals(before.domains(), after.domains(), "domains");
            assertEquals(before.notices(), after.notices(), "notices");
            assertEquals(before.bans(), after.bans(), "bans");
            assertEquals(before.setting(), after.setting(), "setting");
            assertEquals(before.nextHubKey(), after.nextHubKey(), "hub key rotation");
            assertEquals(before.hubKeyActivatesAt(), after.hubKeyActivatesAt(), "hub key rotation time");
            assertEquals(before, after); // and whatever capture() grows that the lines above forget
        }
    }

    @Test
    void theNextNodeIdSurvivesTheSnapshotToo() throws Exception {
        // It is the one piece of state that is not an event, and it only matters once the
        // highest-numbered node is gone: replaying node-registered raises the counter past every
        // node still there, so a store that has never removed one recovers without the field and
        // proves nothing. Remove the newest, and the counter has to come from the snapshot header
        // or the next node to join is handed an id that has already been used.
        Path dir = TestDirs.newRoot("snap");
        try (Store s = new Store(dir)) {
            assertEquals(1, s.registerNode("mkeyone", "alice", "one", "linux").id());
            assertEquals(2, s.registerNode("mkeytwo", "bob", "two", "linux").id());
            s.removeNode("mkeytwo");
            s.snapshot();
        }
        try (Store s = new Store(dir)) {
            assertEquals(3, s.registerNode("mkeythree", "carol", "three", "linux").id());
        }
    }

    /** One of everything {@code snapshot()} writes, with a different value in every field. */
    private static void fill(Store s) throws Exception {
        s.registerNode(NODE, "alice", "laptop", "macOS");
        s.addAdmin("alice");
        s.createInvite("token-one", "CODE-ABCD", "bob", 3, 3600, 600, "alice", true);
        s.addPending("mkeydavedesktop", "desktop", "linux", "203.0.113.9", "dave");
        s.claimName("myapp", "alice", NODE, "127.0.0.1:3000");
        s.claimDomain("app.example.com", "alice", NODE);
        s.addNotice(NODE, "link-7", "myapp", "reassigned");
        s.addBan("198.51.100.0/24", "abuse");
        s.setSetting("registration", "invite");
        s.setHubKeyRotation("hkey:thenextone", 1_700_000_000_000L);
    }

    /** Everything the store can be asked for, as one value, so the comparison is total. */
    private static Everything capture(Store s) {
        return new Everything(s.nodes(), s.admins(), s.invites(), s.pending(), s.names(),
            s.domains(), s.notices(NODE), s.bans(), s.setting("registration", null),
            s.nextHubKey(), s.hubKeyActivatesAt());
    }

    private record Everything(List<Store.NodeRec> nodes, Set<String> admins, List<Store.InviteRec> invites,
        List<Store.PendingRec> pending, List<Store.NameRec> names,
        List<Store.DomainRec> domains, List<Store.NoticeRec> notices,
        List<Store.BanRec> bans, String setting, String nextHubKey, long hubKeyActivatesAt) {}
}
