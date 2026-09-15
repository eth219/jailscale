package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.jailscale.proto.control.Message;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The turn-taking behind the periodic self-probe (ARCHITECTURE.md §11.3). What the schedule owes is
 * that every open name is looked at once per pass, whatever happens to the list of links while the
 * pass runs -- because the length of a pass is what bounds how long an intercepted name can go
 * unnoticed. These are the cases where getting that wrong costs a name its turn without saying so.
 */
class ProbeScheduleTest {

    private static NodeState.LinkRec link(String kind, String name) {
        NodeState.LinkRec r = new NodeState.LinkRec(kind, "127.0.0.1", 3000, name);
        if (Message.LinkOpen.HTTPS.equals(kind)) {
            r.url = "https://" + name + ".hub.example.com";
        }
        return r;
    }

    private static List<NodeState.LinkRec> links(String... kinds) {
        List<NodeState.LinkRec> out = new ArrayList<>();
        for (int i = 0; i < kinds.length; i++) {
            out.add(link(kinds[i], "n" + i));
        }
        return out;
    }

    /** A link that has already been probed at some point, so it is not the never-looked-at one. */
    private static NodeState.LinkRec probed(String name) {
        NodeState.LinkRec r = link(Message.LinkOpen.HTTPS, name);
        r.lastProbe = new ProbeResult(name, true, "terminated by this node", 1);
        return r;
    }

    private static List<String> names(List<NodeState.LinkRec> links, Set<NodeState.LinkRec> pass, int ticks) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < ticks; i++) {
            NodeState.LinkRec rec = Daemon.dueProbe(links, pass);
            out.add(rec == null ? null : rec.name);
        }
        return out;
    }

    @Test
    void everyNameGetsItsTurnOncePerPassAndOnlyOnePerTick() {
        List<NodeState.LinkRec> l = links("https", "https", "https");
        // Seven ticks over three names is two full passes and one tick into a third.
        assertEquals(List.of("n0", "n1", "n2", "n0", "n1", "n2", "n0"), names(l, new HashSet<>(), 7));
    }

    @Test
    void rawPortsAndUnansweredNamesAreNeverCandidates() {
        // A tcp or udp link carries no TLS of ours to compare, and an https link the hub has not
        // answered for yet has no URL to connect to. Neither may take a tick from a name that has one.
        List<NodeState.LinkRec> l = links("tcp", "https", "udp", "https");
        assertEquals(List.of("n1", "n3", "n1", "n3"), names(l, new HashSet<>(), 4));

        NodeState.LinkRec pending = new NodeState.LinkRec(Message.LinkOpen.HTTPS, "127.0.0.1", 3000, "pending");
        assertNull(Daemon.dueProbe(List.of(pending), new HashSet<>()));
    }

    @Test
    void aNodeWithNothingToProbeSaysSo() {
        assertNull(Daemon.dueProbe(List.of(), new HashSet<>()));
        assertNull(Daemon.dueProbe(links("tcp", "udp"), new HashSet<>()));
    }

    @Test
    void closingALinkDoesNotCostAnotherNameItsTurn() {
        // The case a position could not survive: probe the first name, then close it. A cursor
        // holding "index 1" now points past n1, which loses its turn for the rest of the pass --
        // in the loop whose whole purpose is that no name goes unlooked-at for long.
        List<NodeState.LinkRec> l = new ArrayList<>(links("https", "https", "https"));
        Set<NodeState.LinkRec> pass = new HashSet<>();
        assertEquals("n0", Daemon.dueProbe(l, pass).name);
        l.remove(0);
        assertEquals(List.of("n1", "n2"), names(l, pass, 2));
    }

    @Test
    void openingALinkMidPassMakesItDueInThatPass() {
        // The other half of the same property: a name nothing has looked at yet is not made to wait
        // for the next pass, because "not in the set" is exactly "has not had its turn".
        List<NodeState.LinkRec> l = new ArrayList<>(links("https", "https"));
        Set<NodeState.LinkRec> pass = new HashSet<>();
        assertEquals("n0", Daemon.dueProbe(l, pass).name);
        l.add(link(Message.LinkOpen.HTTPS, "fresh"));
        assertEquals(List.of("n1", "fresh", "n0"), names(l, pass, 3));
    }

    @Test
    void aNameWithNoVerdictAtAllGoesFirst() {
        // Until its first probe, what `status` says about a name is an empty field rather than an
        // answer, so it is the one worth spending the tick on wherever it sits in the list.
        List<NodeState.LinkRec> l = List.of(probed("a"), probed("b"), link(Message.LinkOpen.HTTPS, "c"));
        assertEquals(List.of("c", "a", "b"), names(l, new HashSet<>(), 3));
    }

    @Test
    void reopeningANameInsideAPassDoesNotInheritItsTurn() {
        // §11.4: deliberately reopening a name is the answer to a revocation warning. The record is
        // a new one with no verdict, so it must not be held off by the turn the old one took --
        // `status` would sit blank for the one name the operator is watching until the pass ended.
        List<NodeState.LinkRec> l = new ArrayList<>(List.of(probed("a"), probed("b"), probed("c")));
        Set<NodeState.LinkRec> pass = new HashSet<>(l);     // all three have had their turn
        l.set(0, link(Message.LinkOpen.HTTPS, "a"));        // "a" closed and opened again
        assertEquals("a", Daemon.dueProbe(l, pass).name);
        // Keyed by name the pass would have read as complete and started over, handing b and c a
        // second turn each before the new record got its first. Keyed by the record, only it is due.
        assertEquals(4, pass.size());
    }

    @Test
    void aPassTakesTheSameTimeWhateverTheNameCount() {
        // The point of the whole schedule: what is held still is how long a name waits for its
        // turn, not how long a tick is. A node with one name and a node with twenty both look at
        // every name they hold once every PROBE_PASS_MS.
        assertEquals(Daemon.PROBE_PASS_MS, Daemon.probeTick(1));
        assertEquals(Daemon.PROBE_PASS_MS, Daemon.probeTick(0));   // nothing to probe: no faster
        assertEquals(Daemon.PROBE_PASS_MS, Daemon.probeTick(20) * 20);
        assertEquals(90_000L, Daemon.probeTick(20));
        // ...down to the floor, which the 20-link ceiling does not reach. It is there so that
        // raising the ceiling cannot turn this into a request a second by arithmetic alone.
        assertEquals(Daemon.PROBE_MIN_TICK_MS, Daemon.probeTick(10_000));

        assertEquals(2, Daemon.probableNames(links("https", "tcp", "https", "udp")));
        assertEquals(0, Daemon.probableNames(links("tcp")));
    }

    @Test
    void jitterOnlyEverShortensATick() {
        // So the moment a name is looked at is not one anybody can name in advance, while a pass
        // still finishes inside its target rather than drifting past it.
        long tick = Daemon.probeTick(20);
        boolean moved = false;
        for (int i = 0; i < 1000; i++) {
            long j = Daemon.jitter(tick);
            assertTrue(j <= tick && j >= tick - tick / 5, "jittered to " + j + " from " + tick);
            moved |= j != tick;
        }
        assertTrue(moved, "a jitter that never moves anything is not one");
        assertEquals(0L, Daemon.jitter(0));   // a node with nothing to probe must not spin
    }

    @Test
    void oneTickCostsOneProbeWhateverTheNameCount() {
        // The work in a tick does not grow with the number of names: a node at the 20-link ceiling
        // still has exactly one name selected per tick, and the ceiling is what a pass costs.
        String[] many = new String[20];
        java.util.Arrays.fill(many, "https");
        List<NodeState.LinkRec> l = links(many);
        Set<NodeState.LinkRec> pass = new HashSet<>();
        assertEquals(20, new HashSet<>(names(l, pass, 20)).size());
        assertEquals(20, pass.size());
    }
}
