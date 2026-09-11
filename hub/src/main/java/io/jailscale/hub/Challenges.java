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

    private record Entry(String domain, String keyAuthorization, String mkey, long expiresAt) {}

    private final Map<String, Entry> byToken = new ConcurrentHashMap<>();

    static final String TOKEN_IN_USE = "token-in-use";
    static final String TOO_MANY = "too-many-challenges";

    /**
     * Stores the token and returns null, or the reason it was not: {@link #TOO_MANY} when the node
     * already holds too many live tokens, {@link #TOKEN_IN_USE} when the token is another node's.
     * A token is stored against the domain it was issued for and answered only for that Host: a
     * relay that answers any token under any name validates every domain pointed at the hub, for
     * any node that asks.
     */
    String set(String mkey, String domain, String token, String keyAuthorization) {
        long now = System.currentTimeMillis();
        int mine = 0;
        for (Map.Entry<String, Entry> e : byToken.entrySet()) {
            if (e.getValue().expiresAt() < now) {
                byToken.remove(e.getKey(), e.getValue());
            } else if (e.getValue().mkey().equals(mkey) && !e.getKey().equals(token)) {
                mine++;
            }
        }
        Entry held = byToken.get(token);
        if (held != null && held.expiresAt() >= now && !held.mkey().equals(mkey)) {
            return TOKEN_IN_USE;
        }
        if (mine >= MAX_PER_NODE) {
            return TOO_MANY;
        }
        byToken.put(token, new Entry(domain, keyAuthorization, mkey, now + TTL_MS));
        return null;
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

    /** The key authorization for a token asked for under {@code host}, or null. */
    String answer(String host, String token) {
        Entry e = byToken.get(token);
        if (e == null || e.expiresAt() < System.currentTimeMillis()) {
            return null;
        }
        if (host == null || !host.equals(e.domain())) {
            LOG.warn("http-01 token of {} asked for under {}, refusing", e.domain(), host);
            return null;
        }
        LOG.info("answered http-01 challenge for {} (node {})", e.domain(), e.mkey());
        return e.keyAuthorization();
    }
}
