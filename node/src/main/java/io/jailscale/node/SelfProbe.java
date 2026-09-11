package io.jailscale.node;

import io.jailscale.proto.util.Log;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HexFormat;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLSession;

/**
 * Detects a hub that serves one of this node's names itself, or hands it to another node
 * (DESIGN.md §12.3). The signing conditions of §12.1 do not cover this: they are enforced by the
 * hub, so they stop a rogue node and say nothing about a rogue hub.
 *
 * <p>The check is RFC 5705 keying material. Both ends of a TLS 1.3 session derive the same bytes
 * from it and nobody else can, so the node records what it exported for every visitor session it
 * terminated, then connects to its own public name and exports again. If that value is not one it
 * recorded, something between the visitor and this node terminated the TLS -- which is exactly
 * what a hub holding the wildcard key can do. A hub that merely reads and re-encrypts is caught
 * too, since the re-encrypted session is a different one.
 *
 * <p>Limit worth stating: the probe leaves this node's address, so a hub that singles those
 * connections out and routes only them here is not caught. It has to discriminate to do that.
 */
final class SelfProbe {

    private static final Log LOG = Log.get("probe");
    /** RFC 5705 label. Anything works as long as both sides agree; this is not registered. */
    static final String LABEL = "EXPERIMENTAL jailscale self probe";
    static final int LENGTH = 32;
    /** How long a terminated session stays checkable, and how many are kept. */
    static final long WINDOW_MS = 120_000;
    static final int MAX_KEPT = 4096;

    private record Seen(String value, long at) {}

    private final Deque<Seen> recent = new ArrayDeque<>();

    /** The keying material for {@code session}, or null when the session cannot produce it. */
    static String material(SSLSession session) {
        if (!(session instanceof ExtendedSSLSession e)) {
            return null;
        }
        try {
            return HexFormat.of().formatHex(e.exportKeyingMaterialData(LABEL, null, LENGTH));
        } catch (javax.net.ssl.SSLKeyException | RuntimeException ex) {
            return null; // TLS 1.2 and below, or a session that has not finished
        }
    }

    /** Remembers that this node terminated the session with this keying material. */
    void record(String value) {
        if (value == null) {
            return;
        }
        synchronized (recent) {
            long cutoff = System.currentTimeMillis() - WINDOW_MS;
            while (!recent.isEmpty() && (recent.peekFirst().at() < cutoff || recent.size() >= MAX_KEPT)) {
                recent.removeFirst();
            }
            recent.addLast(new Seen(value, System.currentTimeMillis()));
        }
    }

    /** True when this node terminated a session with this keying material inside the window. */
    boolean terminatedHere(String value) {
        if (value == null) {
            return false;
        }
        long cutoff = System.currentTimeMillis() - WINDOW_MS;
        synchronized (recent) {
            for (Seen s : recent) {
                if (s.at() >= cutoff && constantTimeEquals(s.value(), value)) {
                    return true;
                }
            }
        }
        return false;
    }

    int size() {
        synchronized (recent) {
            return recent.size();
        }
    }

    void warn(String name) {
        LOG.error("{}: the TLS for this name was terminated by something other than this node. "
            + "A hub holding the wildcard key can do that (DESIGN.md §12.3, detection §12.5). Treat the name as compromised.", name);
    }

    private static boolean constantTimeEquals(String a, String b) {
        return java.security.MessageDigest.isEqual(
            a.getBytes(java.nio.charset.StandardCharsets.US_ASCII),
            b.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }
}
