package io.jailscale.node;

import io.jailscale.proto.json.Json;
import io.jailscale.proto.json.JsonObject;
import java.io.Closeable;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * One daemon per state directory, and a record of where that daemon listens (ARCHITECTURE.md §9.4).
 *
 * <p>Two daemons on one directory is the failure worth preventing: they share a MachineKey, both
 * connect to the hub as the same node, and both write {@code node.json}. It used to be reachable by
 * accident, because the CLI starts a daemon whenever it cannot reach one, and whether it can reach
 * one depended on the environment.
 *
 * <p>The lock is what makes the guarantee; the file's contents are what make it useful. Holding it
 * proves no other daemon is running, so the socket path written beside it is current by
 * construction rather than a note that might be stale -- which is why this replaces a plain pointer
 * file. The lock is an {@code fcntl} record lock, so the kernel releases it when the process dies,
 * however it dies, and there is no stale lock to clean up and no pid to test for liveness.
 */
final class DaemonLock implements Closeable {

    /**
     * The byte that is locked is past any content, because a Windows lock is mandatory: locking the
     * bytes the CLI reads would make reading them fail there rather than return the holder.
     */
    private static final long SENTINEL = Long.MAX_VALUE - 1;

    private final FileChannel channel;
    private final FileLock lock;

    private DaemonLock(FileChannel channel, FileLock lock) {
        this.channel = channel;
        this.lock = lock;
    }

    static Path file(NodeConfig cfg) {
        return cfg.configDir().resolve("daemon.lock");
    }

    /**
     * Takes the lock and records this process and its socket, or throws saying who holds it.
     * The channel stays open for the life of the daemon: closing it drops the lock.
     */
    static DaemonLock acquire(NodeConfig cfg) throws IOException {
        Files.createDirectories(cfg.configDir());
        FileChannel ch;
        try {
            ch = FileChannel.open(file(cfg), StandardOpenOption.CREATE,
                StandardOpenOption.READ, StandardOpenOption.WRITE);
        } catch (IOException e) {
            // The bare path is what this used to say, and a container with a root-owned state
            // volume is where it says it: the reader needs to be told it is about permissions.
            throw new IOException("cannot open the daemon lock at " + file(cfg) + " (" + e.getMessage()
                + "). The state directory has to be writable by the user running the daemon.", e);
        }
        FileLock l;
        try {
            l = ch.tryLock(SENTINEL, 1, false);
        } catch (OverlappingFileLockException e) {
            l = null; // another thread of this process already holds it, which counts as held
        } catch (IOException e) {
            ch.close();
            throw e;
        }
        if (l == null) {
            String holder = describe(cfg);
            ch.close();
            throw new IOException("another jailscale daemon is already running" + holder);
        }
        ch.truncate(0);
        ch.write(StandardCharsets.UTF_8.encode(JsonObject.builder()
            .put("pid", ProcessHandle.current().pid())
            .put("socket", cfg.socketPath().toAbsolutePath().toString())
            .toJson() + "\n"), 0);
        ch.force(true);
        return new DaemonLock(ch, l);
    }

    /** What the running daemon wrote about itself, or null if there is nothing readable there. */
    static JsonObject holder(NodeConfig cfg) {
        try {
            return Json.parseObject(Files.readString(file(cfg), StandardCharsets.UTF_8).strip());
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** " (pid 123, socket /run/user/501/jailscale.sock)", or "" when the file says nothing. */
    private static String describe(NodeConfig cfg) {
        JsonObject o = holder(cfg);
        if (o == null) {
            return "";
        }
        String socket = o.optString("socket", null);
        return " (pid " + o.optLong("pid") + (socket == null ? "" : ", socket " + socket) + ")";
    }

    @Override
    public void close() throws IOException {
        try {
            lock.release();
        } finally {
            channel.close();
        }
    }
}
