package io.jailscale.proto.net;

/**
 * The PROXY protocol's v1 line, which a node prepends for its local app so the app learns who the
 * visitor is (ARCHITECTURE.md §9.3). Writing one is all that is left here.
 *
 * <p>The reader -- v1 text, v2 binary, as nginx {@code proxy_protocol on} and HAProxy
 * {@code send-proxy(-v2)} send them -- was the hub's half, for a hub behind a proxy that already
 * owned 443 (§8.5), and went with that deployment. It was also a parser reachable before any
 * authentication, which is one fewer of those.
 */
public final class ProxyProtocol {

    private ProxyProtocol() {}

    /** The v1 line a node prepends for its local app (ARCHITECTURE.md §9.3). */
    public static String v1Line(String srcIp, int srcPort, String dstIp, int dstPort) {
        boolean v6 = srcIp.contains(":");
        return "PROXY " + (v6 ? "TCP6" : "TCP4") + " " + srcIp + " " + dstIp + " " + srcPort + " " + dstPort + "\r\n";
    }
}
