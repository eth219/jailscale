package io.jailscale.proto.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HexFormat;

/**
 * The key a per-address limit should count against (ARCHITECTURE.md §8.1, §11.5): what one party
 * holds, rather than what one packet says.
 *
 * <p>A bound of "so many per address" assumes an address costs something to have. In IPv4 it does --
 * an attacker has to acquire each one -- so the address is the key. In IPv6 it does not: the
 * smallest thing anybody is handed is a /64, every ordinary VPS comes with one routed to it, and
 * that is 18 quintillion source addresses for free. Counted per address, every limit the hub has is
 * a limit of "64 connections, times as many as you like", which is not a limit. So a v6 source is
 * keyed on its /64.
 *
 * <p><b>What is left.</b> A subscriber given a /48 -- common for a residential line, and some
 * hosting -- holds 65,536 of these and gets that many buckets. That is a real remainder and it is
 * five orders of magnitude off where it started; /48 would close it and would also put an entire
 * ISP customer's site, or a campus, behind one bucket, which is a worse trade for a limit whose
 * whole job is to be invisible to honest callers.
 *
 * <p><b>Not the only prefix rule here.</b> {@code dns.ResponseRate} keys on the /24 in v4 as well as
 * the /64 in v6, because there the party being defended is the victim of a reflection and a victim
 * is a network. Here the party being counted is the caller, and in v4 a caller is an address.
 */
public final class NetKey {

    private NetKey() {}

    /** The key for {@code ip}, which may be a v4 or v6 literal; anything unparsable is its own key. */
    public static String of(String ip) {
        if (ip == null) {
            return "";
        }
        if (ip.isEmpty() || ip.indexOf(':') < 0) {
            return ip;
        }
        // Only what could be a v6 literal is handed to getByName, because getByName is not the
        // literal parser its name suggests: it short-circuits on a string starting with a hex digit
        // or a colon and sends everything else to the resolver. A colon-bearing name like "zz::1"
        // measured 264 ms of blocking DNS on the path this sits on -- the same hazard the PROXY
        // header parser carried a guard and a "found by fuzzing" comment for, until §8.5 took that
        // parser out of the hub. Anything that
        // cannot be a literal is its own key, which is what an unparsable input should be anyway.
        char first = ip.charAt(0);
        if (first != ':' && Character.digit(first, 16) < 0) {
            return ip;
        }
        try {
            return of(InetAddress.getByName(ip));
        } catch (UnknownHostException | RuntimeException _) {
            return ip;
        }
    }

    /** As above from an address the socket already gave us. */
    public static String of(InetAddress a) {
        byte[] b = a.getAddress();
        if (b.length != 16) {
            return a.getHostAddress();
        }
        // The /64, written so that it cannot be confused with an address: a key is never parsed
        // back, but it is logged and compared, and "the network" should read as one.
        return HexFormat.of().formatHex(b, 0, 8) + "/64";
    }
}
