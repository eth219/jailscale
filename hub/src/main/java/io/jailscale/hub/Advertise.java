package io.jailscale.hub;

import io.jailscale.hub.dns.DnsQuery;
import io.jailscale.hub.dns.DnsResponder;
import io.jailscale.proto.util.Log;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Which public address this hub answers for itself, and which name servers the parent delegates
 * to, found without asking the operator (ARCHITECTURE.md §13).
 *
 * <p>The operator has already written the addresses down once, in the glue at the parent:
 * {@code ns1.<hub>} and {@code ns2.<hub>}. So the hub asks the public resolvers for those, then
 * asks each address directly, on port 53, for {@code _jailhub-self.<hub>} TXT; the one that
 * answers with this process's own token is this host. A peer answers with a different token. A
 * {@code --advertise} flag exists only for a host whose public address is not one any resolver
 * can be asked about.
 */
final class Advertise {

    private static final Log LOG = Log.get("advertise");
    /** The labels a two-host operator delegates to. More than two hubs is not a shape this design has. */
    static final List<String> LABELS = List.of("ns1", "ns2");
    static final int DIRECT_TIMEOUT_MS = 3000;

    private Advertise() {}

    /**
     * The glue the parent holds for {@code hub}: label to IPv4 address, for the labels it has.
     * Read from the parent zone's own name servers, asked without recursion, whose referral for
     * a delegated name carries the glue. Not from a recursive resolver: once the subdomain is
     * delegated, a resolver asked for {@code ns2.<hub>} asks the hubs, and a hub that did not yet
     * know the glue answered from the wildcard with itself -- which the resolver cached and this
     * lookup then believed, so both hubs thought they were the same host. The first deployment of
     * the delegation did exactly that.
     */
    static Map<String, String> glue(String hub) {
        String parent = hub.substring(hub.indexOf('.') + 1);
        List<String> servers = new java.util.ArrayList<>();
        for (String r : DnsQuery.PUBLIC_RESOLVERS) {
            try {
                for (String nsName : DnsQuery.ns(r, 53, parent, DnsQuery.PUBLIC_TIMEOUT_MS)) {
                    for (String a : DnsQuery.a(r, 53, nsName, DnsQuery.PUBLIC_TIMEOUT_MS)) {
                        if (!servers.contains(a)) {
                            servers.add(a);
                        }
                    }
                }
                if (!servers.isEmpty()) {
                    break;
                }
            } catch (IOException | RuntimeException e) {
                LOG.debug("{} for NS of {}: {}", r, parent, e.toString());
            }
        }
        return glue(hub, servers, 53);
    }

    /** As above, asking the parent's servers given (tests pass a fake parent and its port). */
    static Map<String, String> glue(String hub, List<String> parentServers, int port) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String server : parentServers) {
            try {
                Map<String, String> referral = DnsQuery.referralGlue(server, port, LABELS.get(0) + "." + hub, DIRECT_TIMEOUT_MS);
                for (String label : LABELS) {
                    String a = referral.get(label + "." + hub);
                    if (a != null) {
                        out.put(label, a);
                    }
                }
                if (!out.isEmpty()) {
                    return out;
                }
            } catch (IOException | RuntimeException e) {
                LOG.debug("parent {} for {}: {}", server, hub, e.toString());
            }
        }
        return out;
    }

    /**
     * The address in {@code glue} that answers {@code _jailhub-self.<hub>} with {@code token} on
     * {@code port}, or null when none does: this host is not one of the delegated servers, or its
     * port 53 is not reachable from itself, which the dns-01 self-check reports separately.
     */
    static String whoAmI(Map<String, String> glue, String hub, int port, String token) {
        String name = DnsResponder.SELF_LABEL + "." + hub;
        for (Map.Entry<String, String> e : glue.entrySet()) {
            try {
                if (DnsQuery.txt(e.getValue(), port, name, DIRECT_TIMEOUT_MS).contains(token)) {
                    return e.getValue();
                }
            } catch (IOException | RuntimeException ex) {
                LOG.debug("{} ({}): {}", e.getKey(), e.getValue(), ex.toString());
            }
        }
        return null;
    }
}
