package io.jailscale.hub;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Live node groups by MachineKey (ARCHITECTURE.md §5.3). */
final class Registry {

    private final Hub hub;
    private final Map<String, NodeGroup> byKey = new ConcurrentHashMap<>();

    Registry(Hub hub) {
        this.hub = hub;
    }

    NodeGroup attach(NodeSession s) {
        NodeGroup g = byKey.computeIfAbsent(s.machineKey(), k -> new NodeGroup(hub, k));
        g.attach(s);
        return g;
    }

    void detach(NodeSession s) {
        NodeGroup g = byKey.get(s.machineKey());
        if (g != null) {
            g.detach(s);
            if (g.isEmpty()) {
                byKey.remove(s.machineKey(), g);
                hub.links().groupEnded(g);
            }
        }
    }

    /** The MachineKeys attached right now. */
    List<String> machineKeys() {
        return new ArrayList<>(byKey.keySet());
    }

    NodeGroup get(String mkey) {
        return byKey.get(mkey);
    }

    List<NodeGroup> all() {
        return new ArrayList<>(byKey.values());
    }

    int size() {
        return byKey.size();
    }

    /**
     * What the nodes online right now together said they will hold (ARCHITECTURE.md §9.3). A node
     * that advertises nothing -- any build older than the field -- contributes 0, so this is a
     * lower bound on what the deployment can serve and not a total to divide by.
     */
    long visitorCapacity() {
        // Summed as a long, and it has to be: this adds up numbers the nodes chose. A node that
        // sends Integer.MAX_VALUE is only lying to itself about admission -- the hub then never
        // refuses on its behalf and its own bound resets what it cannot take, which is what a node
        // that says nothing gets -- but two of them would wrap an int sum negative and put a
        // negative capacity on the hub's public page. Nothing else here validates it, on purpose:
        // any positive number a node names is a number it is entitled to name.
        long n = 0;
        for (NodeGroup g : byKey.values()) {
            n += Math.max(0, g.visitorCeiling());
        }
        return n;
    }

    void closeAll(String reason) {
        for (NodeGroup g : all()) {
            g.goodbyeAll(reason);
        }
    }

    void drainAll() {
        for (NodeGroup g : all()) {
            g.drain();
        }
    }

    int liveSessions() {
        int n = 0;
        for (NodeGroup g : all()) {
            n += g.connections();
        }
        return n;
    }
}
