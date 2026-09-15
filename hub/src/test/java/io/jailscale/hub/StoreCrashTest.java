package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.junit.jupiter.api.Test;

/**
 * What a snapshot leaves behind when the process does not survive it (ARCHITECTURE.md §6.2).
 *
 * <p>{@code snapshot()} does two things that cannot be one: it renames the new snapshot into place,
 * and it truncates the log the snapshot has just folded in. Between them the state directory holds
 * <b>both</b> — a snapshot that already counts every event, and a log that still lists them. Nothing
 * forces the truncation to disk either, so that pair is not only the width of two statements: a
 * machine that loses power within the filesystem's commit interval comes back to it.
 *
 * <p>Replaying that log on top of that snapshot has to be a no-op, and for most events it is,
 * because they are {@code put}s that land on the value already there. The ones that are not are the
 * arithmetic: {@code invite-used} and {@code authkey-used} subtract, {@code notice-added} appends.
 * Replayed twice they spend a use that was never spent and duplicate a notice, which is a credential
 * quietly worth less than it says and an operator told twice about one revocation.
 *
 * <p>Every test here reads its result out of a <b>copy</b> of the state directory rather than
 * reopening the one still in use. That is what a restart really sees — a directory, with no live
 * writer behind it — and it keeps two {@code FileOutputStream}s off one path, which is a question on
 * Windows and not worth asking.
 */
class StoreCrashTest {

    @Test
    void anInviteDoesNotSpendAUseItNeverSpent() throws Exception {
        Path dir = TestDirs.newRoot("crash");
        Store s = new Store(dir);
        s.createInvite("tok", "CODE", "bob", 3, 3600, 600, "alice", false);
        // The first snapshot folds the creation away, so the log below holds the use and not the
        // record it applies to. Without this the replayed `invite-created` would reset the count on
        // its way past and hide the double subtraction.
        s.snapshot();
        s.consumeInvite("tok");
        assertEquals(2, s.invites().get(0).usesLeft());

        try (Store r = new Store(crashDuringSnapshot(s, dir))) {
            assertEquals(2, r.invites().get(0).usesLeft(), "uses left after a lost truncation");
        }
    }

    @Test
    void anAuthKeyDoesNotSpendAUseItNeverSpent() throws Exception {
        Path dir = TestDirs.newRoot("crash");
        Store s = new Store(dir);
        s.createAuthKey("jk_secret", "carol", null, 2, 7200);
        s.snapshot();
        s.consumeAuthKey("jk_secret");
        assertEquals(1, s.authKeys().get(0).usesLeft());

        try (Store r = new Store(crashDuringSnapshot(s, dir))) {
            // The size first, because a second subtraction here does not cost a use, it costs the
            // key: `authkey-used` removes the record once nothing is left, so a two-use key with one
            // use to go comes back gone and whoever holds it — a CI runner, usually — is locked out
            // with nothing in any log to say why.
            assertEquals(1, r.authKeys().size(), "the auth-key should still be there at all");
            assertEquals(1, r.authKeys().get(0).usesLeft(), "uses left after a lost truncation");
        }
    }

    @Test
    void aNodeIsNotToldTwiceAboutOneLostName() throws Exception {
        Path dir = TestDirs.newRoot("crash");
        Store s = new Store(dir);
        s.registerNode("mkeyalice", "alice", "laptop", "linux");
        s.snapshot();
        s.addNotice("mkeyalice", "link-7", "myapp", "reassigned");
        assertEquals(1, s.notices("mkeyalice").size());

        try (Store r = new Store(crashDuringSnapshot(s, dir))) {
            assertEquals(1, r.notices("mkeyalice").size(), "notices after a lost truncation");
        }
    }

    @Test
    void anEventAfterARestartIsNotMistakenForOneTheSnapshotHolds() throws Exception {
        // The other direction, and the one the fix for the three above can get wrong in silence:
        // skipping what the snapshot already holds must not skip what it does not. Numbering has to
        // carry on across a restart, because a snapshot claiming five events and a log restarting at
        // one describes every line of that log as already folded in. No crash in this one at all —
        // an ordinary stop and start, and then the events are simply gone.
        Path dir = TestDirs.newRoot("crash");
        try (Store s = new Store(dir)) {
            for (int i = 0; i < 5; i++) {
                s.addBan("198.51.100." + i, "abuse");
            }
            s.snapshot();
            assertEquals(0, Files.size(dir.resolve("state.jsonl")), "the snapshot should have emptied the log");
        }

        Store restarted = new Store(dir);
        restarted.claimName("myapp", "alice", "mkeyalice", "127.0.0.1:3000");
        restarted.addAdmin("alice");

        try (Store r = new Store(copyOf(dir))) {
            assertEquals(5, r.bans().size(), "the bans from before the restart");
            assertEquals(1, r.names().size(), "the name claimed after the restart");
            assertTrue(r.isAdmin("alice"), "the admin added after the restart");
        }
        restarted.close();
    }

    @Test
    void stateWrittenBeforeSequenceNumbersExistedStillLoads() throws Exception {
        // The upgrade every running hub makes once: a snapshot with no `seq` beside log lines with
        // no `s`. Nothing may be skipped there -- a missing number is not a low one -- and the
        // events have to land whether they are in the snapshot or the log. Written by hand rather
        // than by an older Store, because the point is the bytes on disk and there is no older
        // Store to ask.
        Path dir = TestDirs.newRoot("upgrade");
        Files.writeString(dir.resolve("state.snapshot"),
            "{\"v\":" + Store.STATE_VERSION + ",\"nextNodeId\":2,\"events\":["
                + "{\"e\":\"node-registered\",\"id\":1,\"mkey\":\"mkeyalice\",\"user\":\"alice\","
                + "\"hostname\":\"laptop\",\"os\":\"linux\",\"at\":1}]}",
            StandardCharsets.UTF_8);
        Files.writeString(dir.resolve("state.jsonl"),
            "{\"e\":\"admin-added\",\"user\":\"alice\"}\n"
                + "{\"e\":\"name-claimed\",\"name\":\"myapp\",\"user\":\"alice\",\"mkey\":\"mkeyalice\","
                + "\"local\":\"127.0.0.1:3000\",\"at\":2}\n",
            StandardCharsets.UTF_8);

        try (Store s = new Store(dir)) {
            assertEquals(1, s.nodes().size(), "the node from the old snapshot");
            assertTrue(s.isAdmin("alice"), "the admin from the old log");
            assertEquals(1, s.names().size(), "the name from the old log");

            // And from here on it numbers its own, so the next snapshot carries the field and the
            // window this class is about is closed for good on this directory.
            s.claimName("second", "alice", "mkeyalice", "127.0.0.1:3001");
            s.snapshot();
            assertTrue(Files.readString(dir.resolve("state.snapshot"), StandardCharsets.UTF_8).contains("\"seq\":"),
                "the snapshot it writes should carry the sequence it folded through");
        }
    }

    @Test
    void theKnockQueueIsBoundedPerNetworkNotPerAddress() throws Exception {
        // ARCHITECTURE.md §11.5: five pending knocks per address, counted per /64 in v6 like every
        // other bound there. Counted per address it is five times as many addresses as a routed /64
        // holds, and unlike the connection caps each knock is appended to the log and rewritten into
        // every snapshot after it, so the overflow outlives the process.
        Path dir = TestDirs.newRoot("knock");
        try (Store s = new Store(dir)) {
            for (int i = 1; i <= 5; i++) {
                s.addPending("mkey:v6-" + i, "box" + i, "linux", "2001:db8:1:2::" + i, null);
            }
            assertEquals(5, s.pendingCountFrom("2001:db8:1:2::99"),
                "a fresh address in a /64 that has knocked five times is the same caller");
            assertEquals(0, s.pendingCountFrom("2001:db8:1:3::1"), "a different /64 is not");

            // v4 is unchanged: there an address is what an attacker has to acquire.
            s.addPending("mkey:v4", "box", "linux", "203.0.113.7", null);
            assertEquals(1, s.pendingCountFrom("203.0.113.7"));
            assertEquals(0, s.pendingCountFrom("203.0.113.8"));
        }
    }

    @Test
    void anOrdinarySnapshotStillCompactsTheLog() throws Exception {
        // The truncation is what keeps the log from growing without bound, and a fix that made
        // replay idempotent by leaving the log alone would pass every test above and lose that.
        Path dir = TestDirs.newRoot("crash");
        try (Store s = new Store(dir)) {
            for (int i = 0; i < 20; i++) {
                s.addBan("198.51.100." + i, "abuse");
            }
            assertTrue(Files.size(dir.resolve("state.jsonl")) > 0);
            s.snapshot();
            assertEquals(0, Files.size(dir.resolve("state.jsonl")), "the log after a snapshot");
            assertEquals(20, s.bans().size());
        }
    }

    /**
     * Takes a snapshot the way a process that is about to die does, and returns the directory a
     * restart would find: the log is copied aside before the snapshot and restored into the copy
     * afterwards, so what is there is a snapshot that has folded those events in beside a log that
     * still carries them.
     */
    private static Path crashDuringSnapshot(Store s, Path dir) throws Exception {
        Path saved = Files.createTempFile("saved", ".jsonl");
        Files.copy(dir.resolve("state.jsonl"), saved, StandardCopyOption.REPLACE_EXISTING);
        s.snapshot();
        Path copy = copyOf(dir);
        Files.copy(saved, copy.resolve("state.jsonl"), StandardCopyOption.REPLACE_EXISTING);
        Files.delete(saved);
        return copy;
    }

    /** The state directory as it stands, somewhere else: what a restart opens, with no writer behind it. */
    private static Path copyOf(Path dir) throws Exception {
        Path copy = TestDirs.newRoot("restart");
        for (String name : new String[] {"state.snapshot", "state.jsonl"}) {
            if (Files.exists(dir.resolve(name))) {
                Files.copy(dir.resolve(name), copy.resolve(name), StandardCopyOption.REPLACE_EXISTING);
            }
        }
        return copy;
    }
}
