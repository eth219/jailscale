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

    NodeGroup get(String mkey) {
        return byKey.get(mkey);
    }

    List<NodeGroup> all() {
        return new ArrayList<>(byKey.values());
    }

    int size() {
        return byKey.size();
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
