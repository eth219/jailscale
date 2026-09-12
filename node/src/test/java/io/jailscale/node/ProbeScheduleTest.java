package io.jailscale.node;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.jailscale.proto.control.Message;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The turn-taking behind the periodic self-probe (ARCHITECTURE.md §11.3). §15 objected that a
 * period for running it has to scale with the number of open names; it does not, if one tick probes
 * one name. These are the cases where getting that wrong would either probe nothing or probe
 * everything at once.
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

    @Test
    void everyNameGetsItsTurnAndOnlyOnePerTick() {
        List<NodeState.LinkRec> l = links("https", "https", "https");
        int at = 0;
        List<Integer> visited = new ArrayList<>();
        for (int tick = 0; tick < 7; tick++) {
            int i = Daemon.nextProbeIndex(l, at);
            visited.add(i);
            at = (i + 1) % l.size();
        }
        // Round robin, so seven ticks over three names is two full passes and one over.
        assertEquals(List.of(0, 1, 2, 0, 1, 2, 0), visited);
    }

    @Test
    void rawPortsAreSteppedOverRatherThanWastingATick() {
        // A tcp link has no TLS of ours to compare, so a tick that lands on one must move on to the
        // next https link in the same tick instead of probing nothing for half an hour.
        List<NodeState.LinkRec> l = links("tcp", "https", "udp", "https");
        assertEquals(1, Daemon.nextProbeIndex(l, 0));
        assertEquals(1, Daemon.nextProbeIndex(l, 1));
        assertEquals(3, Daemon.nextProbeIndex(l, 2));
        assertEquals(3, Daemon.nextProbeIndex(l, 3));
    }

    @Test
    void aNodeWithNothingToProbeSaysSo() {
        assertEquals(-1, Daemon.nextProbeIndex(List.of(), 0));
        assertEquals(-1, Daemon.nextProbeIndex(links("tcp", "udp"), 0));
        // An https link the hub has not answered for yet has no URL to connect to.
        NodeState.LinkRec pending = new NodeState.LinkRec(Message.LinkOpen.HTTPS, "127.0.0.1", 3000, "pending");
        assertEquals(-1, Daemon.nextProbeIndex(List.of(pending), 0));
    }

    @Test
    void oneTickCostsOneProbeWhateverTheNameCount() {
        // The claim §15 asked for: the work in a tick does not grow with the number of names. A
        // node at the 20-link ceiling still has exactly one name selected per tick.
        String[] many = new String[20];
        java.util.Arrays.fill(many, "https");
        List<NodeState.LinkRec> l = links(many);
        for (int at = 0; at < l.size(); at++) {
            assertEquals(at, Daemon.nextProbeIndex(l, at), "tick starting at " + at);
        }
    }
}
