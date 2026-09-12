package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        assertEquals("daemon", cmd.get(cmd.size() - 3));
        assertEquals("--home", cmd.get(cmd.size() - 2));
        assertTrue(Path.of(cmd.get(cmd.size() - 1)).isAbsolute(),
            "a unit's ExecStart runs from systemd's working directory, so the home must be absolute: " + cmd);
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
            "-XX:MaxHeapSize=128m -XX:ProfilesDumpFile=/tmp/node.iprof");
        assertEquals("-XX:MaxHeapSize=128m", cmd.get(1));
        assertEquals("-XX:ProfilesDumpFile=/tmp/node.iprof", cmd.get(2));
        assertTrue(cmd.indexOf("daemon") > 2, cmd.toString());
        // Whatever the runtime is, nothing may sit between the executable and its own options.
        assertEquals(cmd.get(0), ProcessHandle.current().info().command().orElse("jailscale"));
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
