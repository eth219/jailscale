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
 * to, found without asking the operator (ARCHITECTURE.md §13.3).
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

    /** What the public resolvers hold as glue: label to IPv4 address, for the labels that resolve. */
    static Map<String, String> glue(String hub) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String label : LABELS) {
            String name = label + "." + hub;
            for (String r : DnsQuery.PUBLIC_RESOLVERS) {
                try {
                    List<String> a = DnsQuery.a(r, 53, name, DnsQuery.PUBLIC_TIMEOUT_MS);
                    if (!a.isEmpty()) {
                        out.put(label, a.get(0));
                        break;
                    }
                } catch (IOException | RuntimeException e) {
                    LOG.debug("{} for {}: {}", r, name, e.toString());
                }
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
