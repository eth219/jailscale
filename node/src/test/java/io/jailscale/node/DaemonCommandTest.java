package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.util.Args;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The one command that starts the daemon, whether the CLI spawns it or a unit does
 * ({@code Service.daemonCommand}). Both used to be built separately, and had drifted: one passed
 * {@code -cp} and a main class where the other passed {@code -jar}, and one passed the home
 * directory as given where the other made it absolute.
 */
class DaemonCommandTest {

    private static NodeConfig cfgIn(Path dir) {
        return NodeConfig.in(dir);
    }

    @Test
    void withoutOptionsItIsTheExecutableAndTheSubcommand() {
        List<String> cmd = Service.daemonCommand(cfgIn(Path.of("nodehome")), null);
        assertEquals("daemon", cmd.get(cmd.size() - 5));
        assertEquals("--home", cmd.get(cmd.size() - 4));
        assertEquals("--socket", cmd.get(cmd.size() - 2));
        // A unit's ExecStart runs from systemd's working directory, so neither path may be relative.
        assertTrue(Path.of(cmd.get(cmd.size() - 3)).isAbsolute(), "relative home: " + cmd);
        assertTrue(Path.of(cmd.get(cmd.size() - 1)).isAbsolute(), "relative socket: " + cmd);
        assertTrue(cmd.stream().noneMatch(a -> a.startsWith("-XX:")), cmd.toString());
    }

    /**
     * Position is the whole point: a native image parses {@code -XX:} before {@code main} sees the
     * arguments and a JVM only accepts it before {@code -cp}, so anywhere after the subcommand it
     * would arrive as an argument to the daemon instead and be rejected as one.
     */
    @Test
    void optionsComeStraightAfterTheExecutable() {
        List<String> cmd = Service.daemonCommand(cfgIn(Path.of("nodehome")),
            "-XX:MaxHeapSize=128m -XX:PrintFlags=/tmp/node.flags");
        assertEquals("-XX:MaxHeapSize=128m", cmd.get(1));
        assertEquals("-XX:PrintFlags=/tmp/node.flags", cmd.get(2));
        assertTrue(cmd.indexOf("daemon") > 2, cmd.toString());
        // Whatever the runtime is, nothing may sit between the executable and its own options.
        assertEquals(cmd.get(0), ProcessHandle.current().info().command().orElse("jailscale"));
    }

    /**
     * The socket is not always inside the config directory: where {@code XDG_RUNTIME_DIR} is set,
     * which is every systemd login session, the CLI looks for it in {@code /run/user/<uid>}. The
     * daemon has to be told which one, or it binds the other, and the CLI then waits five seconds
     * for a socket nobody is listening on, reports that the daemon did not start, and leaves it
     * running -- one more orphan for every command typed.
     */
    @Test
    void theDaemonIsToldTheSocketTheCliWillWaitOn() {
        NodeConfig cfg = new NodeConfig(Path.of("nodehome"), Path.of("/run/user/501/jailscale.sock"), NodeConfig.Tuning.defaults());
        List<String> cmd = Service.daemonCommand(cfg, null);
        String[] tail = cmd.subList(cmd.indexOf("daemon"), cmd.size()).toArray(new String[0]);

        NodeConfig asTheDaemonReadsIt = Main.configOf(Args.parse(tail));
        // Absolute on both sides, for the same reason the home is: an ExecStart has no working
        // directory of ours. On Windows "/run/..." is a path relative to the current drive, so the
        // one the command carries is the one to compare with.
        assertEquals(cfg.socketPath().toAbsolutePath(), asTheDaemonReadsIt.socketPath(), cmd.toString());
        assertEquals(cfg.configDir().toAbsolutePath(), asTheDaemonReadsIt.configDir(), cmd.toString());
    }

    /** Without one, the socket is where it has always been, so an existing unit keeps working. */
    @Test
    void aHomeOnItsOwnStillMeansTheSocketInsideIt() {
        NodeConfig cfg = Main.configOf(Args.parse(new String[] {"daemon", "--home", "/tmp/nodehome"}));
        assertEquals(Path.of("/tmp/nodehome/jailscale.sock"), cfg.socketPath());
    }

    @Test
    void blankOptionsAreNotAnArgument() {
        List<String> plain = Service.daemonCommand(cfgIn(Path.of("nodehome")), null);
        assertEquals(plain, Service.daemonCommand(cfgIn(Path.of("nodehome")), "   "));
        assertEquals(plain, Service.daemonCommand(cfgIn(Path.of("nodehome")), ""));
    }

    /** Under a JVM the classpath is handed over whole, and absolute, or a unit cannot find it. */
    @Test
    void underAJvmTheClasspathIsAbsolute() {
        List<String> cmd = Service.daemonCommand(cfgIn(Path.of("nodehome")), null);
        int cp = cmd.indexOf("-cp");
        if (cp < 0) {
            return; // a native image: no classpath to pass
        }
        for (String entry : cmd.get(cp + 1).split(java.io.File.pathSeparator)) {
            assertTrue(Path.of(entry).isAbsolute(), entry + " is relative, in " + cmd);
        }
        assertEquals(Main.class.getName(), cmd.get(cp + 2));
    }
}
