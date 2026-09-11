package io.jailscale.hub;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * A short temporary directory for tests. Both the hub and the node listen on an AF_UNIX socket
 * inside their state directory, and {@code sun_path} holds only 104 bytes on macOS (108 on
 * Linux). macOS resolves {@code java.io.tmpdir} to {@code /var/folders/<random>/T/}, which is
 * long enough to push the socket path over that limit, so Unix-like systems get {@code /tmp}.
 * Windows has no {@code /tmp} but a short {@code java.io.tmpdir}, so it falls back to that.
 */
final class TestDirs {

    private TestDirs() {}

    /** Creates a fresh directory under the shortest temporary root available on this platform. */
    static Path newRoot(String prefix) throws IOException {
        Path shortRoot = Path.of("/tmp");
        if (Files.isDirectory(shortRoot) && Files.isWritable(shortRoot)) {
            return Files.createTempDirectory(shortRoot, prefix);
        }
        return Files.createTempDirectory(prefix);
    }
}
