package io.jailscale.hub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * ARCHITECTURE.md §6.2: the state directory carries the format version it was written with, and a hub
 * that does not understand it refuses to start. Snapshots always wrote the field; until this test
 * existed nothing read it, so an older binary replayed a newer snapshot as if it were its own.
 */
@Timeout(30)
class StateVersionTest {

    @Test
    void refusesAStateNewerThanItUnderstands() throws Exception {
        Path dir = TestDirs.newRoot("sv");
        Files.writeString(dir.resolve("state.snapshot"),
            "{\"v\":" + (Store.STATE_VERSION + 1) + ",\"nextNodeId\":7,\"events\":[]}", StandardCharsets.UTF_8);
        IOException e = assertThrows(IOException.class, () -> new Store(dir).close());
        assertTrue(e.getMessage().contains("state version " + (Store.STATE_VERSION + 1)), e.getMessage());
        assertTrue(e.getMessage().contains("newer jailhub"), e.getMessage());
    }

    @Test
    void readsItsOwnVersionAndAVersionlessSnapshot() throws Exception {
        Path a = TestDirs.newRoot("sv");
        Files.writeString(a.resolve("state.snapshot"),
            "{\"v\":" + Store.STATE_VERSION + ",\"nextNodeId\":5,\"events\":[]}", StandardCharsets.UTF_8);
        try (Store s = new Store(a)) {
            assertEquals(0, s.nodes().size());
        }
        // Written before the field was read back; treated as this version rather than rejected.
        Path b = TestDirs.newRoot("sv");
        Files.writeString(b.resolve("state.snapshot"), "{\"nextNodeId\":5,\"events\":[]}", StandardCharsets.UTF_8);
        try (Store s = new Store(b)) {
            assertEquals(0, s.nodes().size());
        }
    }

    @Test
    void roundTripsThroughASnapshotItWrote() throws Exception {
        Path dir = TestDirs.newRoot("sv");
        try (Store s = new Store(dir)) {
            s.addAdmin("alice");
            s.snapshot();
        }
        String written = Files.readString(dir.resolve("state.snapshot"), StandardCharsets.UTF_8);
        assertTrue(written.contains("\"v\":" + Store.STATE_VERSION), written);
        try (Store s = new Store(dir)) {
            assertTrue(s.isAdmin("alice"));
        }
    }
}
