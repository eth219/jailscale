package io.jailscale.node;

import java.nio.file.Files;
import java.nio.file.Path;

/** File locations for the node (ARCHITECTURE.md §4, §9.4), and the timings a test moves. */
public record NodeConfig(Path configDir, Path socketPath, Tuning tuning) {

    /**
     * The bounds of §9.3, in one place so that adding one is not a new signature (#61).
     *
     * <p>These were constructor parameters on {@link Daemon}, one delegating overload per arity:
     * two knobs cost three {@code Daemon} constructors, and a third would have cost a fourth. The hub had the other idiom for the same job -- {@code static
     * volatile} fields set in a {@code @BeforeEach} -- which cost a restore in every test that
     * touched one and relied on surefire running them one at a time. A record on the config that
     * already reaches both costs neither.
     *
     * <p>Nothing on the command line reaches these. The derived ceiling is the only one anything
     * has measured, and the way to move it is the heap ceiling it comes from.
     */
    public record Tuning(int visitorCeiling, long firstByteMs) {

        /** The shipped values: the bound derived from this JVM's heap, and §9.3's deadline. */
        public static Tuning defaults() {
            return new Tuning(Visitors.defaultCeiling(), Visitors.FIRST_BYTE_MS);
        }

        public Tuning visitorCeiling(int v) {
            return new Tuning(v, firstByteMs);
        }

        public Tuning firstByteMs(long v) {
            return new Tuning(visitorCeiling, v);
        }
    }

    public static NodeConfig defaults() {
        Path dir = defaultConfigDir();
        return new NodeConfig(dir, defaultSocketPath(dir), Tuning.defaults());
    }

    public static NodeConfig in(Path dir) {
        return new NodeConfig(dir, dir.resolve("jailscale.sock"), Tuning.defaults());
    }

    /** The same locations with different timings; how a test reaches {@link Tuning}. */
    public NodeConfig withTuning(Tuning t) {
        return new NodeConfig(configDir, socketPath, t);
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
