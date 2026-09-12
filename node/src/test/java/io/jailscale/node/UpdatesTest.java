package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class UpdatesTest {

    private static int cmp(String a, String b) {
        Integer c = Updates.compare(a, b);
        assertTrue(c != null, a + " vs " + b + " should be comparable");
        return Integer.signum(c);
    }

    @Test
    void ordersReleases() {
        assertEquals(0, cmp("0.1.0", "0.1.0"));
        assertEquals(-1, cmp("0.1.0", "0.1.1"));
        assertEquals(-1, cmp("0.1.0", "0.2.0"));
        assertEquals(-1, cmp("0.9.9", "1.0.0"));
        assertEquals(1, cmp("1.0.0", "0.9.9"));
        // Ten is above nine, which is where a string comparison would have said the opposite.
        assertEquals(-1, cmp("0.9.0", "0.10.0"));
        assertEquals(-1, cmp("0.1.9", "0.1.10"));
        // A missing component is zero, and the tag's leading v is not part of the number.
        assertEquals(0, cmp("0.1", "0.1.0"));
        assertEquals(0, cmp("v0.1.0", "0.1.0"));
        assertEquals(-1, cmp("v0.1.0", "v0.2.0"));
    }

    @Test
    void aSnapshotIsBelowTheReleaseItIsHeadingFor() {
        // Otherwise the machine this is developed on would be told it is behind by its own build.
        assertEquals(-1, cmp("0.2.0-SNAPSHOT", "0.2.0"));
        assertEquals(1, cmp("0.2.0-SNAPSHOT", "0.1.0"));
        assertEquals(-1, cmp("0.2.0-SNAPSHOT", "0.2.1"));
    }

    @Test
    void whatItCannotReadItDoesNotGuess() {
        // "cannot tell" has to stay distinguishable from "no update", or a source build quietly
        // reports itself current for ever.
        assertNull(Updates.compare("dev", "0.1.0"));
        assertNull(Updates.compare("0.1.0", "not-a-version"));
        assertNull(Updates.compare(null, "0.1.0"));
        assertNull(Updates.compare("", "0.1.0"));
        assertNull(Updates.compare("0.1.0.1.2", "0.1.0"));
        assertNull(Updates.compare("-1.0.0", "0.1.0"));
    }

    @Test
    void everyOutcomeSaysSomethingUseful() {
        assertEquals("jailscale 0.1.0 is the latest release.",
            new Updates.Result("0.1.0", "0.1.0", false, 0, null).line());
        assertTrue(new Updates.Result("0.1.0", "0.2.0", true, 0, null).line().contains("0.2.0 is out"));
        assertTrue(new Updates.Result("0.1.0", "0.2.0", true, 0, null).line().contains(Updates.PAGE));
        assertEquals("could not check for updates: no route to host",
            new Updates.Result("0.1.0", null, false, 0, "no route to host").line());
    }

    @Test
    void theUpdateUrlIsNotSomethingAPeerCanChoose() {
        // The hub is trusted to route bytes, not to say what this node should run (§11.2). If this
        // ever becomes configurable, a compromised hub can point every node at a binary it picked.
        assertEquals("https://api.github.com/repos/eth219/jailscale/releases/latest", Updates.LATEST.toString());
        assertEquals("https", Updates.LATEST.getScheme());
    }
}
