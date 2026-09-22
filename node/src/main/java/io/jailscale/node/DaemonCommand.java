package io.jailscale.node;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * How the daemon is started (ARCHITECTURE.md §9.4): one command, whether the CLI spawns it or an
 * operator's own launchd plist, systemd unit or scheduled task does.
 *
 * <p>{@code jailscale service install|uninstall|status} used to write those files -- three unit
 * templates and three registration tools, verified on one of the three platforms -- and was
 * removed. This is the half everything still depends on: the argument list, in one place, so that
 * the daemon the CLI starts and the daemon a unit starts are the same process started the same
 * way. A unit of the operator's own runs {@code jailscale daemon}, and {@code deploy/} has one to
 * copy.
 */
final class DaemonCommand {

    private DaemonCommand() {}

    /**
     * The command that starts the daemon: the native binary, or the JVM and this classpath for the
     * fallback JAR. The one place that decides this -- {@code Main.spawnDaemon} used to build its
     * own version, which had drifted into using {@code -cp} where this used {@code -jar} and a
     * relative home where this used an absolute one, so a daemon started by the CLI and one started
     * by a unit were launched two different ways. Both paths are passed and both are absolute:
     * whoever launches the daemon decides where it listens, so the CLI and the daemon cannot
     * disagree about it, and an operator writing a unit by hand has one command to copy.
     */
    static List<String> of(NodeConfig cfg) {
        return of(cfg, System.getenv("JAILSCALE_DAEMON_OPTS"));
    }

    /**
     * As above, with the runtime options taken as an argument so a test can supply them.
     *
     * <p>{@code JAILSCALE_DAEMON_OPTS} is a way in for the options the native runtime reads before
     * {@code main} does, {@code -XX:MaxHeapSize=} to lift the ceiling the build set (§14) being the
     * one in use. It is a measurement and diagnosis hatch rather than a product surface, which is
     * why it is an environment variable and not a flag on {@code up}: nothing measured so far asks
     * for a different ceiling. They go straight after the executable, which is where both a native
     * image and a JVM look, so a unit that sets it in its own environment gets it on the daemon it
     * starts.
     */
    static List<String> of(NodeConfig cfg, String opts) {
        List<String> cmd = new ArrayList<>();
        String exe = ProcessHandle.current().info().command().orElse("jailscale");
        String base = Path.of(exe).getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        cmd.add(exe);
        // Straight after the executable, which is the only place both kinds of runtime look: a
        // native image parses -XX: before main sees the arguments, and a JVM only accepts them
        // before -cp and the main class.
        if (opts != null && !opts.isBlank()) {
            cmd.addAll(List.of(opts.trim().split("\\s+")));
        }
        if (base.equals("java") || base.equals("java.exe")) {
            // Every entry absolute: a unit's ExecStart runs from a working directory of the init
            // system's choosing, not from wherever the CLI happened to be.
            StringBuilder cp = new StringBuilder();
            for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
                cp.append(cp.length() == 0 ? "" : File.pathSeparator).append(Path.of(entry).toAbsolutePath());
            }
            cmd.add("-cp");
            cmd.add(cp.toString());
            cmd.add(Main.class.getName());
        }
        cmd.add("daemon");
        cmd.add("--home");
        cmd.add(cfg.configDir().toAbsolutePath().toString());
        // And the socket, which is not always inside that directory: where XDG_RUNTIME_DIR is set,
        // which is every systemd login session, the CLI looks for it in /run/user/<uid>. Passing
        // only the home let the daemon bind the other one, and the CLI then waited five seconds for
        // a socket nobody was listening on and left the daemon it had just started behind.
        cmd.add("--socket");
        cmd.add(cfg.socketPath().toAbsolutePath().toString());
        return cmd;
    }
}
