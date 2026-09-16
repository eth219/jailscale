package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.control.Message;
import org.junit.jupiter.api.Test;

/**
 * The node-side twin of {@code ProtoSkewTest.theHubCannotDemandMoreThanItSpeaks}
 * (ARCHITECTURE.md §5.4). The hub asserts that its floor is not above what it speaks; the node has
 * the same pair of constants and, until this, nothing asserting the same of them.
 *
 * <p>The mistake it catches is a flag day raised in two commits with the node's landing first:
 * {@link HubLink#MIN_HUB_PROTO} at 2 while {@link Message#PROTO} is still 1 makes every node built
 * from that commit refuse every hub in existence -- including a hub built from the same commit,
 * which speaks 1 -- in {@code HubLink.connectOnce}, and the suite stays green while it does.
 *
 * <p><b>What it cannot catch.</b> Both are compile-time constants, so javac folds them into this
 * class and the comparison is between the values {@code node} was last built against. A reactor
 * build is what makes them the live ones, which is what {@code ./mvnw package} and every release
 * do; a tree that rebuilt {@code proto} alone would compare two stale copies and pass. It is also
 * the *relationship* that is asserted and not either value, so it says nothing about whether the
 * floor is the right one -- only that the node cannot demand a hub newer than itself.
 *
 * <p>It deliberately does not speak the wire. {@code ProtoSkewTest} drives a skewed handshake
 * against a live hub with the protocol number as the only variable; whether the node's refusal path
 * deserves that treatment too is a larger question than this invariant and is not asked here.
 */
class HubProtoFloorTest {

    @Test
    void theNodeCannotDemandAHubNewerThanItSpeaks() {
        assertTrue(HubLink.MIN_HUB_PROTO <= Message.PROTO,
            "MIN_HUB_PROTO=" + HubLink.MIN_HUB_PROTO + " is above the PROTO=" + Message.PROTO
                + " this node speaks, so it would refuse every hub built from this commit");
    }
}
