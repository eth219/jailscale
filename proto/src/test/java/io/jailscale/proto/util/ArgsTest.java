package io.jailscale.proto.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The parser both binaries put every typed word through. It had no test of its own: the two that
 * touched argv checked one command's worth of it each ({@code DaemonCommandTest} the daemon's own
 * line, {@code ReachabilityTest} two hub flags), so the rules everything else depends on -- what
 * counts as a value, what a declared flag changes, how a duration is read -- were only ever
 * exercised by the code that assumed them.
 */
class ArgsTest {

    // --- values and flags ------------------------------------------------------------------------

    @Test
    void aValueIsTheNextWordOrWhatFollowsTheEquals() {
        Args a = Args.parse(new String[] {"open", "8080", "--name", "web", "--host=10.0.0.1"});
        assertEquals("web", a.get("name"));
        assertEquals("10.0.0.1", a.get("host"));
        assertEquals(List.of("open", "8080"), a.positional());
    }

    @Test
    void anEqualsKeepsAValueThatWouldOtherwiseLookLikeAnOption() {
        // The only way to pass a value starting with "--": bare, the next-word rule below refuses it.
        Args a = Args.parse(new String[] {"ban", "add", "1.2.3.4", "--reason=--weird"});
        assertEquals("--weird", a.get("reason"));
        assertEquals("", Args.parse(new String[] {"--user="}).get("user"));
    }

    @Test
    void aDeclaredFlagLeavesTheNextWordAlone() {
        // Why the flag list exists: `--no-address-check serve` must not eat the subcommand.
        Args declared = Args.parse(new String[] {"--no-address-check", "serve"}, "no-address-check");
        assertTrue(declared.flag("no-address-check"));
        assertEquals("serve", declared.positional(0));

        Args undeclared = Args.parse(new String[] {"--no-address-check", "serve"});
        assertEquals("serve", undeclared.get("no-address-check"), "the subcommand became the value");
        assertNull(undeclared.positional(0));
    }

    /**
     * The documented rule -- "any option followed by another option (or nothing) takes no value" --
     * is what saves an undeclared flag, and it costs an option that wanted one: {@code --name}
     * before {@code --gate} silently becomes the string "true" rather than an error. Pinned here
     * because both binaries rely on the saving half, and because the cost should be visible to
     * whoever changes it.
     */
    @Test
    void anOptionFollowedByAnotherOptionTakesNoValue() {
        Args a = Args.parse(new String[] {"open", "8080", "--name", "--gate"}, "gate");
        assertTrue(a.flag("gate"));
        assertEquals("true", a.get("name"), "a link named \"true\"");

        Args end = Args.parse(new String[] {"open", "8080", "--name"});
        assertEquals("true", end.get("name"));
    }

    @Test
    void flagIsTrueOnlyForTheWordTrue() {
        Args a = Args.parse(new String[] {"--gate=false", "--off"}, "off");
        assertFalse(a.flag("gate"), "--gate=false must not read as on");
        assertTrue(a.has("gate"), "but it was still given");
        assertTrue(a.flag("off"));
        assertFalse(a.flag("never-given"));
        assertFalse(a.has("never-given"));
    }

    @Test
    void theLastOfARepeatedOptionWins() {
        Args a = Args.parse(new String[] {"--user", "alice", "--user", "bob"});
        assertEquals("bob", a.get("user"));
    }

    @Test
    void aBareDashDashEndsTheOptions() {
        Args a = Args.parse(new String[] {"up", "--", "--hub", "--debug"}, "debug");
        assertEquals(List.of("up", "--hub", "--debug"), a.positional());
        assertFalse(a.has("hub"));
        assertFalse(a.flag("debug"));
    }

    @Test
    void aSingleDashIsPositional() {
        // -XX:MaxHeapSize= and friends reach the daemon this way (Service.daemonCommand).
        Args a = Args.parse(new String[] {"-XX:MaxHeapSize=128m", "daemon"});
        assertEquals(List.of("-XX:MaxHeapSize=128m", "daemon"), a.positional());
    }

    @Test
    void positionalsAreIndexedAndRunOut() {
        Args a = Args.parse(new String[] {"node", "approve"});
        assertEquals("node", a.positional(0));
        assertEquals("approve", a.positional(1));
        assertNull(a.positional(2), "a missing word is null, not an exception");
        assertNull(Args.parse(new String[0]).positional(0));
    }

    // --- typed reads -----------------------------------------------------------------------------

    @Test
    void requireNamesTheOptionItIsMissing() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> Args.parse(new String[0]).require("base-url"));
        assertEquals("--base-url is required", e.getMessage());
        assertEquals("x", Args.parse(new String[] {"--base-url", "x"}).require("base-url"));
    }

    @Test
    void integerFallsBackAndRefusesWhatIsNotOne() {
        assertEquals(443, Args.parse(new String[0]).integer("port", 443));
        assertEquals(8443, Args.parse(new String[] {"--port", "8443"}).integer("port", 443));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
            () -> Args.parse(new String[] {"--port", "https"}).integer("port", 443));
        assertEquals("--port must be a number", e.getMessage());
        // The "takes no value" rule turns a valueless --port into "true", which must not be a port.
        assertThrows(IllegalArgumentException.class, () -> Args.parse(new String[] {"--port"}).integer("port", 443));
    }

    // --- durations: --ttl, --grace ---------------------------------------------------------------

    @Test
    void aDurationSuffixMultiplies() {
        assertEquals(90, Args.parseSeconds("90s"));
        assertEquals(600, Args.parseSeconds("10m"));
        assertEquals(86400, Args.parseSeconds("24h"));
        assertEquals(7 * 86400, Args.parseSeconds("7d"));
        assertEquals(30 * 86400, Args.parseSeconds("30d"));
    }

    @Test
    void aPlainNumberIsSeconds() {
        assertEquals(1, Args.parseSeconds("1"));
        assertEquals(0, Args.parseSeconds("0"));
    }

    @Test
    void caseAndSurroundingSpaceDoNotMatter() {
        assertEquals(86400, Args.parseSeconds("24H"));
        assertEquals(604800, Args.parseSeconds(" 7d "));
    }

    @Test
    void whatIsNotADurationIsRefusedAsOne() {
        for (String bad : new String[] {"", "  ", "d", "24w", "1h30m", "abc", "-", "2 4h"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Args.parseSeconds(bad), "accepted " + "\"" + bad + "\"");
            assertTrue(e.getMessage().startsWith("bad duration"), e.getMessage());
        }
    }

    /**
     * An empty value reaches this through {@code --ttl=}, which is a plausible typo, and it used to
     * leave the parser through {@code charAt(-1)}: a {@code StringIndexOutOfBoundsException} is not
     * an {@code IllegalArgumentException}, so both binaries fell past the handler that prints
     * "error: ..." and exits 2, and reported a Java exception with exit 1 instead.
     */
    @Test
    void anEmptyValueIsRefusedTheSameWayAsABadOne() {
        Args a = Args.parse(new String[] {"invite", "--ttl="});
        assertTrue(a.has("ttl"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> a.seconds("ttl", 0));
        assertEquals("bad duration ", e.getMessage());
    }

    @Test
    void secondsFallsBackWhenTheOptionIsAbsent() {
        assertEquals(24 * 3600, Args.parse(new String[] {"gate", "web"}).seconds("ttl", 24 * 3600));
        assertEquals(3600, Args.parse(new String[] {"--ttl", "1h"}).seconds("ttl", 0));
    }
}
