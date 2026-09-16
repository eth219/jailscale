package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * ARCHITECTURE.md §11.3: which verdicts the exit status of {@code jailscale verify} is about.
 *
 * <p>One is not, and the rule has to discriminate rather than be constant in either direction: a
 * {@code checked()} that always answered true is the bug this was written for -- `jailscale down`
 * and then `jailscale verify` exiting 1 -- and one that always answered false is the command
 * reporting success at an interception, which is the only thing it exists to catch.
 */
class ProbeResultTest {

    private static ProbeResult with(String verdict, boolean ok) {
        return new ProbeResult("app.hub.test", ok, verdict, 1_700_000_000_000L);
    }

    @Test
    void onlyTheNameThatWasNotProbedIsLeftOutOfTheVerdict() {
        assertFalse(with(ProbeResult.NOT_OPEN, false).checked(),
            "nothing was probed: neither a pass nor a failure");
        assertTrue(with("terminated by this node", true).checked());
        assertTrue(with("TERMINATED ELSEWHERE", false).checked(),
            "the one thing this command exists to catch has to count");
        assertTrue(with("unreachable: connect timed out", false).checked(),
            "something was tried and did not answer, which is not the same as not trying");
        assertTrue(with("keying material unavailable (needs TLS 1.3)", false).checked());
    }
}
