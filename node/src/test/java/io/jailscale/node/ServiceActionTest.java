package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * {@code jailscale service <action>} refuses anything that is not one of the three actions, on
 * whichever of launchd, systemd and schtasks this machine uses. The check sits in each platform's
 * own switch, so a fourth word reaching one of them would otherwise fall through to whatever that
 * branch does last.
 *
 * <p>Deliberately not covered here: {@code install} and {@code uninstall}. They register and
 * deregister a real user agent or unit on the machine running the tests, and a test suite is not
 * allowed to do that to a developer's login session. What they write is
 * {@link Service#daemonCommand}, which {@link DaemonCommandTest} covers in full; what remains
 * unexercised is each platform's unit template and the {@code launchctl}/{@code systemctl}/
 * {@code schtasks} calls around it.
 */
class ServiceActionTest {

    private static final NodeConfig CFG = NodeConfig.in(Path.of("nodehome"));

    @Test
    void anActionThatIsNotOneOfTheThreeIsRefused() {
        for (String bogus : new String[] {"start", "stop", "restart", "enable", "reload", "Install", "INSTALL", ""}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> Service.run(bogus, CFG),
                "accepted: jailscale service " + bogus);
            // The message is the usage line, because it is the only place the three are listed.
            assertEquals("service install | uninstall | status", e.getMessage());
        }
    }

    /**
     * Nothing is written or registered on the way to that refusal: the check is the first thing in
     * each platform's switch, so a typo cannot leave half an installation behind.
     */
    @Test
    void aRefusedActionTouchesNothing() throws Exception {
        Path plist = Path.of(System.getProperty("user.home"), "Library", "LaunchAgents", "io.jailscale.node.plist");
        Path unit = Path.of(System.getProperty("user.home"), ".config", "systemd", "user", "jailscale.service");
        boolean plistBefore = java.nio.file.Files.exists(plist);
        boolean unitBefore = java.nio.file.Files.exists(unit);

        assertThrows(IllegalArgumentException.class, () -> Service.run("start", CFG));

        assertEquals(plistBefore, java.nio.file.Files.exists(plist), plist + " changed");
        assertEquals(unitBefore, java.nio.file.Files.exists(unit), unit + " changed");
    }
}
