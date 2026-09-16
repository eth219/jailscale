package io.jailscale.proto.net;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The helper the rest of the tests get their ports from (jailscale#108). */
class TestPortsTest {

    /**
     * The property the whole thing exists for: two callers are never given the same number. The
     * pressure comes from the kernel, which reuses a port it has just been handed back, so this
     * asks for enough of them to give it the chance -- a listener between every two reservations is
     * the shape that was failing in the suite, an echo server taking the port a hub was about to
     * bind.
     */
    @Test
    void nothingIsHandedTheSamePortTwice() throws Exception {
        Set<Integer> seen = new HashSet<>();
        List<ServerSocket> held = new ArrayList<>();
        try {
            for (int i = 0; i < 40; i++) {
                assertTrue(seen.add(TestPorts.reserve()), "reserve() repeated a port");
                ServerSocket s = TestPorts.listen(1);
                held.add(s);
                assertTrue(seen.add(s.getLocalPort()), "listen() was given a port already promised");
            }
        } finally {
            for (ServerSocket s : held) {
                s.close();
            }
        }
    }

    /**
     * And the deterministic half, which needs no luck from the kernel: a range is scanned, so a
     * second caller asking for one has to be made to skip what the first was given. Without the
     * check this returns the same base every time, and the two test classes that ask for a raw-port
     * range would be handed the same four ports.
     */
    @Test
    void aRangeIsNotHandedOutTwice() throws Exception {
        int first = TestPorts.reserveRange(4);
        int second = TestPorts.reserveRange(4);
        assertTrue(Math.abs(first - second) >= 4,
            "two ranges overlap: " + first + " and " + second);
    }
}
