package io.jailscale.node;

import java.nio.file.Files;
import java.nio.file.Path;

/** File locations for the node (ARCHITECTURE.md §4, §9.4). */
public record NodeConfig(Path configDir, Path socketPath) {

    public static NodeConfig defaults() {
        Path dir = defaultConfigDir();
        return new NodeConfig(dir, defaultSocketPath(dir));
    }

    public static NodeConfig in(Path dir) {
        return new NodeConfig(dir, dir.resolve("jailscale.sock"));
    }

    public Path stateFile() {
        return configDir.resolve("node.json");
    }

    public Path daemonLog() {
        return configDir.resolve("daemon.log");
    }

    static Path defaultConfigDir() {
        String env = System.getenv("JAILSCALE_HOME");
        if (env != null && !env.isBlank()) {
            return Path.of(env);
        }
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (os.contains("win")) {
            String local = System.getenv("LOCALAPPDATA");
            return Path.of(local != null ? local : System.getProperty("user.home"), "jailscale");
        }
        String xdg = System.getenv("XDG_CONFIG_HOME");
        Path base = xdg != null && !xdg.isBlank() ? Path.of(xdg) : Path.of(System.getProperty("user.home"), ".config");
        return base.resolve("jailscale");
    }

    static Path defaultSocketPath(Path configDir) {
        String runtime = System.getenv("XDG_RUNTIME_DIR");
        if (runtime != null && !runtime.isBlank() && Files.isDirectory(Path.of(runtime))) {
            return Path.of(runtime, "jailscale.sock");
        }
        return configDir.resolve("jailscale.sock");
    }
}
