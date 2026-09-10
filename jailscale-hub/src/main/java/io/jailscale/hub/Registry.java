package io.jailscale.hub;

import io.jailscale.proto.control.Message;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Live sessions by MachineKey. A second connection with the same key replaces the first (DESIGN.md §8). */
final class Registry {

    private final Map<String, NodeSession> byKey = new ConcurrentHashMap<>();

    void attach(NodeSession s) {
        NodeSession old = byKey.put(s.machineKey(), s);
        if (old != null && old != s) {
            old.goodbye(Message.Goodbye.SHUTDOWN);
        }
    }

    void detach(NodeSession s) {
        if (s.machineKey() != null) {
            byKey.remove(s.machineKey(), s);
        }
    }

    NodeSession get(String mkey) {
        return byKey.get(mkey);
    }

    List<NodeSession> all() {
        return new ArrayList<>(byKey.values());
    }

    int size() {
        return byKey.size();
    }

    void closeAll(String reason) {
        for (NodeSession s : all()) {
            s.goodbye(reason);
        }
    }
}
