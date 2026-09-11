package io.jailscale.hub;

import io.jailscale.proto.util.Log;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ACME http-01 tokens that nodes asked the hub to answer on port 80 for their own domains
 * (ARCHITECTURE.md §8.3). Short-lived, capped per node; the hub never learns the node's keys.
 */
final class Challenges {

    private static final Log LOG = Log.get("challenge");
    static final long TTL_MS = 10 * 60_000;
    static final int MAX_PER_NODE = 10;

    private record Entry(String keyAuthorization, String mkey, long expiresAt) {}

    private final Map<String, Entry> byToken = new ConcurrentHashMap<>();

    /** Returns false when the node already holds too many live tokens. */
    boolean set(String mkey, String token, String keyAuthorization) {
        long now = System.currentTimeMillis();
        int mine = 0;
        for (Map.Entry<String, Entry> e : byToken.entrySet()) {
            if (e.getValue().expiresAt() < now) {
                byToken.remove(e.getKey(), e.getValue());
            } else if (e.getValue().mkey().equals(mkey) && !e.getKey().equals(token)) {
                mine++;
            }
        }
        if (mine >= MAX_PER_NODE) {
            return false;
        }
        byToken.put(token, new Entry(keyAuthorization, mkey, now + TTL_MS));
        return true;
    }

    void clear(String mkey, String token) {
        Entry e = byToken.get(token);
        if (e != null && e.mkey().equals(mkey)) {
            byToken.remove(token, e);
        }
    }

    void clearNode(String mkey) {
        byToken.entrySet().removeIf(e -> e.getValue().mkey().equals(mkey));
    }

    /** The key authorization for a token, or null. */
    String answer(String token) {
        Entry e = byToken.get(token);
        if (e == null || e.expiresAt() < System.currentTimeMillis()) {
            return null;
        }
        LOG.info("answered http-01 challenge for node {}", e.mkey());
        return e.keyAuthorization();
    }
}
