package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The arithmetic behind the node's visitor bound (ARCHITECTURE.md §9.3). The measurements it comes
 * from are in {@link Visitors}; what is pinned here is that the shipped ceiling still produces the
 * number those measurements chose, and that the two edges behave.
 */
class VisitorCeilingTest {

    private static final long MIB = 1024 * 1024;

    @Test
    void theShippedCeilingGivesTheCountThatWasMeasuredAtIt() {
        // 64m is native.maxHeap in node/pom.xml. If that moves, this fails and the measurements in
        // Visitors have to be redone rather than the number here edited to match.
        assertEquals(450, Visitors.ceilingFor(64 * MIB));
    }

    @Test
    void aRaisedCeilingBuysProportionallyMoreVisitors() {
        // The diagnosis hatch of §14: -XX:MaxHeapSize= through JAILSCALE_DAEMON_OPTS. A node given
        // more heap should serve more visitors, not go on holding the number that suited 64 MiB.
        assertEquals(900, Visitors.ceilingFor(128 * MIB));
        assertEquals(5400, Visitors.ceilingFor(768 * MIB));
    }

    @Test
    void aHeapTooSmallToDivideStillLeavesANodeUsable() {
        // Below about 9 MiB the division says single digits, and a node that will serve four
        // visitors is a worse answer than one that admits its configuration is wrong by running.
        assertEquals(64, Visitors.ceilingFor(1 * MIB));
        assertEquals(64, Visitors.ceilingFor(8 * MIB));
    }

    @Test
    void noCeilingAtAllIsReadAsTheShippedOne() {
        // A JVM with no -Xmx reports Long.MAX_VALUE for maxMemory on some configurations; taken
        // literally the multiplication overflows and the bound becomes negative, which admits
        // nobody. The shipped ceiling is the honest fallback.
        assertEquals(Visitors.ceilingFor(64 * MIB), Visitors.ceilingFor(Long.MAX_VALUE));
    }

    @Test
    void theBoundTheProcessActuallyRunsWithIsTheOneDerived() {
        assertEquals(Visitors.ceilingFor(Runtime.getRuntime().maxMemory()), Visitors.MAX_IN_FLIGHT);
        assertTrue(Visitors.MAX_IN_FLIGHT >= 64, "the floor is a floor: " + Visitors.MAX_IN_FLIGHT);
    }
}
