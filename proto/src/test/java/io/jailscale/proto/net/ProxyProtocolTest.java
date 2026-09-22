package io.jailscale.proto.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * The PROXY v1 line a node prepends for its local app (ARCHITECTURE.md §9.3).
 *
 * <p>This file used to cover the reader as well -- v1 text, v2 binary, LOCAL, the hostname a v1
 * address may not be -- and that half went with the hub's side of the PROXY protocol (§8.5). What
 * is left is the half that is still called, from {@code Visitors.proxyLine}: an app behind a link
 * reads this line to learn who the visitor is, so the field order is the app's business and not
 * ours to get wrong. Source before destination, addresses before ports, which is not the order the
 * arguments are in.
 */
class ProxyProtocolTest {

    @Test
    void v1LineIsSourceThenDestinationThenTheirPorts() {
        assertEquals("PROXY TCP4 203.0.113.5 127.0.0.1 51234 3000\r\n",
            ProxyProtocol.v1Line("203.0.113.5", 51234, "127.0.0.1", 3000));
    }

    @Test
    void anIpv6SourceSaysTCP6() {
        // The family is read off the source address, so a v6 visitor reaching a v4 local target
        // still says TCP6 -- which is what HAProxy's own parser expects, and the branch is one
        // character away from being written the other way round.
        assertEquals("PROXY TCP6 2001:db8::1 127.0.0.1 51234 3000\r\n",
            ProxyProtocol.v1Line("2001:db8::1", 51234, "127.0.0.1", 3000));
    }
}
