package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.ipc.Ipc;
import io.jailscale.proto.json.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * One daemon per state directory (ARCHITECTURE.md §9.4). Two of them share a MachineKey and a state
 * file, which is what this prevents; where the surviving one listens is what the file it holds says.
 */
@Timeout(120)
class DaemonLockTest {

    /** Short, because the socket inside it has to fit in {@code sun_path}. */
    private static NodeConfig freshHome() throws IOException {
        Path root = Path.of("/tmp");
        Path dir = Files.isWritable(root) ? Files.createTempDirectory(root, "lock") : Files.createTempDirectory("lock");
        return NodeConfig.in(dir);
    }

    @Test
    void theHolderRecordsItsPidAndTheSocketItListensOn() throws Exception {
        NodeConfig cfg = freshHome();
        DaemonLock held = DaemonLock.acquire(cfg);
        try {
            JsonObject holder = DaemonLock.holder(cfg);
            assertNotNull(holder);
            assertEquals(ProcessHandle.current().pid(), holder.optLong("pid"));
            assertEquals(cfg.socketPath().toAbsolutePath().toString(), holder.string("socket"));
        } finally {
            held.close();
        }
    }

    @Test
    void theLockIsReleasedWhenTheHolderLetsGo() throws Exception {
        NodeConfig cfg = freshHome();
        DaemonLock first = DaemonLock.acquire(cfg);
        assertThrows(IOException.class, () -> DaemonLock.acquire(cfg));
        first.close();
        DaemonLock.acquire(cfg).close(); // the next daemon gets it
    }

    /**
     * The lock is a file lock, so the check has to survive being made from another process -- which
     * is the only arrangement that matters, since the two daemons this prevents are two processes.
     * The second one is started the way the CLI and an installed unit start theirs.
     */
    @Test
    void asecondDaemonProcessRefusesToStartAndSaysWhoHasIt() throws Exception {
        NodeConfig cfg = freshHome();
        Process first = daemon(cfg);
        try {
            long deadline = System.currentTimeMillis() + 30_000;
            while (!Ipc.isAlive(cfg.socketPath()) && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }
            assertTrue(Ipc.isAlive(cfg.socketPath()), "the first daemon never came up");

            Process second = daemon(cfg);
            assertTrue(second.waitFor(60, java.util.concurrent.TimeUnit.SECONDS), "the second daemon did not exit");
            String said = new String(second.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertEquals(1, second.exitValue(), said);
            assertTrue(said.contains("already running"), said);
            assertTrue(said.contains("pid " + first.pid()), "it should name the holder: " + said);
            assertTrue(said.contains(cfg.socketPath().toAbsolutePath().toString()), said);
            // And the first is untouched: it still owns the socket and the lock file.
            assertTrue(Ipc.isAlive(cfg.socketPath()));
            assertEquals(first.pid(), DaemonLock.holder(cfg).optLong("pid"));
        } finally {
            first.destroy();
            first.waitFor(30, java.util.concurrent.TimeUnit.SECONDS);
        }
    }

    private static Process daemon(NodeConfig cfg) throws IOException {
        List<String> cmd = Service.daemonCommand(cfg, null);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        return pb.start();
    }
}
