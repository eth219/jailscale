package io.jailscale.hub;

import io.jailscale.proto.util.Log;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/**
 * Addresses the operator has barred from joining or reconnecting (ARCHITECTURE.md §11.5).
 *
 * <p>An entry is a single address or a CIDR block, v4 or v6. Matching is done on the raw bytes
 * with a prefix-length mask, so no text parsing happens on the hot path and a v4 entry never
 * matches a v6 address.
 *
 * <p>This bars the control plane only: registering, and connecting as an already-registered node.
 * A ban is not a firewall. Visitors are unaffected, since the point is to stop someone running
 * nodes on this hub, not to stop them reading a page.
 */
final class Bans {

    private static final Log LOG = Log.get("bans");

    /** A parsed entry, kept alongside its text so the admin page can show what was typed. */
    record Entry(String cidr, byte[] network, int prefixBits, String reason, long at) {

        boolean matches(byte[] addr) {
            if (addr == null || addr.length != network.length) {
                return false;
            }
            int fullBytes = prefixBits / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (addr[i] != network[i]) {
                    return false;
                }
            }
            int rest = prefixBits % 8;
            if (rest == 0) {
                return true;
            }
            int mask = 0xff << (8 - rest);
            return (addr[fullBytes] & mask) == (network[fullBytes] & mask);
        }
    }

    private final Store store;

    Bans(Store store) {
        this.store = store;
    }

    /**
     * Parses "203.0.113.7", "203.0.113.0/24" or "2001:db8::/32". Returns null when the text is not
     * an address or the prefix is out of range, so callers can report it rather than storing junk.
     */
    static Entry parse(String cidr, String reason, long at) {
        if (cidr == null || cidr.isBlank()) {
            return null;
        }
        String text = cidr.trim();
        String host = text;
        int bits = -1;
        int slash = text.lastIndexOf('/');
        if (slash >= 0) {
            host = text.substring(0, slash);
            try {
                bits = Integer.parseInt(text.substring(slash + 1));
            } catch (NumberFormatException _) {
                return null;
            }
        }
        byte[] addr;
        try {
            // Literal only: a hostname here would mean a DNS lookup driven by admin input.
            addr = parseLiteral(host);
        } catch (UnknownHostException _) {
            return null;
        }
        if (addr == null) {
            return null;
        }
        int max = addr.length * 8;
        if (bits < 0) {
            bits = max;
        }
        if (bits > max || bits < 0) {
            return null;
        }
        return new Entry(text, addr, bits, reason, at);
    }

    private static byte[] parseLiteral(String host) throws UnknownHostException {
        if (host.isEmpty()) {
            return null;
        }
        for (int i = 0; i < host.length(); i++) {
            char c = host.charAt(i);
            if (!(Character.isDigit(c) || c == '.' || c == ':' || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return null;
            }
        }
        return InetAddress.getByName(host).getAddress();
    }

    /** True when this address is barred. A malformed or unknown address is never barred. */
    boolean isBanned(String ip) {
        List<Store.BanRec> all = store.bans();
        if (all.isEmpty() || ip == null) {
            return false;
        }
        byte[] addr;
        try {
            addr = parseLiteral(ip);
        } catch (UnknownHostException _) {
            return false;
        }
        if (addr == null) {
            return false;
        }
        for (Store.BanRec b : all) {
            Entry e = parse(b.cidr(), b.reason(), b.at());
            if (e != null && e.matches(addr)) {
                return true;
            }
        }
        return false;
    }

    /** The entry that bars this address, or null. Used to tell the operator which rule hit. */
    String matching(String ip) {
        byte[] addr;
        try {
            addr = parseLiteral(ip);
        } catch (UnknownHostException _) {
            return null;
        }
        if (addr == null) {
            return null;
        }
        for (Store.BanRec b : store.bans()) {
            Entry e = parse(b.cidr(), b.reason(), b.at());
            if (e != null && e.matches(addr)) {
                return b.cidr();
            }
        }
        return null;
    }

    void logRefusal(String ip, String what) {
        LOG.warn("{} refused from {}: banned by {}", what, ip, matching(ip));
    }
}
