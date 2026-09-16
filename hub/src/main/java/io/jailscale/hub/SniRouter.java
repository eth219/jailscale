package io.jailscale.hub;

import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.net.NetKey;
import io.jailscale.proto.tls.Sni;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Public port 443 (ARCHITECTURE.md §8.1): peek the ClientHello, then either terminate TLS for the
 * hub's own name, relay the raw bytes to the node serving {@code <name>.<hub>}, or answer with
 * a short page under the wildcard certificate.
 */
final class SniRouter {

    private static final Log LOG = Log.get("sni");
    static final int HELLO_TIMEOUT_MS = 5_000;
    static final int MAX_PER_IP = 64;
    static final int MAX_PER_NAME = 1024;
    static final long HOLD_MS = 3_000;

    private final Hub hub;
    private final Map<String, AtomicInteger> perIp = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> perName = new ConcurrentHashMap<>();
    /**
     * Visitors being relayed right now. Its own counter rather than a sum over {@link #perName}:
     * that map exists to enforce a per-name cap and summing it would walk every name a scrape, for
     * a number the relay can keep exactly as it enters and leaves.
     */
    private final AtomicInteger current = new AtomicInteger();

    SniRouter(Hub hub) {
        this.hub = hub;
    }

    /**
     * Takes one slot for {@code key} and returns how many are now held. The counter is created
     * and incremented inside the map's own lock, and {@link #release} removes it inside that same
     * lock once the last holder lets go, so an entry never outlives the connections it counts.
     *
     * <p>Counting in a map keyed by the visitor address means an address nobody has connected
     * from since is an entry nobody will ever look at again, and this is the one path here that
     * runs before any authentication: reaching it costs an attacker a TCP connection, so leaving
     * the entries behind is a map that grows for as long as the process lives. {@code RateLimiter}
     * makes the same point about buckets and answers it by pruning; a counter that is back at zero
     * needs no pruning heuristic, because zero and absent are the same state.
     */
    private static int acquire(Map<String, AtomicInteger> counts, String key) {
        int[] held = new int[1];
        counts.compute(key, (k, c) -> {
            AtomicInteger v = c == null ? new AtomicInteger() : c;
            held[0] = v.incrementAndGet();
            return v;
        });
        return held[0];
    }

    /**
     * Takes a visitor slot for one connection, or null when that network is already at
     * {@link #MAX_PER_IP} and nothing was taken. What comes back is the key, to be handed to
     * {@link #giveSlot}: the caller gives back what it took rather than an address the key may not
     * have come from.
     *
     * <p>Both listeners ask here -- 443 above, and the raw tcp ports of §8.4, which accept on their
     * own sockets and so never reached this at all. They had one rule written twice, and only one
     * of the two copies had the exemption below: a forwarder on this host that sends no PROXY
     * header folds every visitor onto one address, so a raw port capped the world at 64 while 443
     * behind the same forwarder capped nobody.
     *
     * <p><b>Counted against the network and not the address</b> ({@link NetKey}): in v4 those are
     * the same thing, and in v6 they are not -- a routed /64 is free and standard, so a per-address
     * cap of 64 would be "64 per address, times eighteen quintillion". {@code ip} itself is
     * untouched, since it is what gets logged, banned and handed to the node as the visitor's
     * address; when nothing attributed the connection the key is taken from the bytes {@code peer}
     * holds, rather than formatting that address to text and parsing it straight back once per
     * connection.
     *
     * <p><b>The exemption is for visitors this hub cannot tell apart</b>, not for a peer that
     * happens to be local. Once a header has attributed the connection the cap applies again --
     * testing the socket's peer instead meant that every hub behind nginx on localhost, which is
     * the deployment deploy/nginx-stream.conf documents, had no per-address cap at all and one
     * client could exhaust MAX_PER_NAME and the node's ceiling.
     */
    String takeSlot(String ip, InetAddress peer, boolean attributed) {
        String key = attributed ? NetKey.of(ip) : NetKey.of(peer);
        boolean unattributedLocal = !attributed && peer.isLoopbackAddress();
        if (acquire(perIp, key) > MAX_PER_IP && !unattributedLocal) {
            release(perIp, key);
            return null;
        }
        return key;
    }

    /** Gives back what {@link #takeSlot} took, which is why it is the key and not the address. */
    void giveSlot(String key) {
        release(perIp, key);
    }

    /** Gives a slot back, dropping the entry when it was the last one. */
    private static void release(Map<String, AtomicInteger> counts, String key) {
        counts.computeIfPresent(key, (k, c) -> c.decrementAndGet() == 0 ? null : c);
    }

    /** Visitor networks (NetKey: a v4 address, a v6 /64) with at least one connection open. */
    int trackedAddresses() {
        return perIp.size();
    }

    /** Names with at least one connection open. Zero when nothing is in flight. */
    int trackedNames() {
        return perName.size();
    }

    /**
     * Visitors being relayed to a node right now. The page prints {@link #MAX_PER_NAME} as the cap
     * and had nothing measured to read it against, which made a limit look like a load figure.
     */
    int visitorsInFlight() {
        return current.get();
    }

    /** Serves one accepted raw connection to completion. */
    void serve(Socket socket) {
        long acceptedAt = System.nanoTime();
        String ip = socket.getInetAddress().getHostAddress();
        int visitorPort = socket.getPort();
        boolean attributed = false;
        try {
            socket.setSoTimeout(HELLO_TIMEOUT_MS);
            io.jailscale.proto.net.ProxyProtocol.Header ph = hub.readProxyHeader(socket);
            if (ph != null && ph.known()) {
                ip = ph.srcIp();
                visitorPort = ph.srcPort();
                attributed = true;
            }
        } catch (IOException e) {
            LOG.debug("{}: {}", ip, e.getMessage());
            Relay.closeQuietly(socket);
            return;
        }
        String ipKey = takeSlot(ip, socket.getInetAddress(), attributed);
        if (ipKey == null) {
            Metrics.VISITORS_REFUSED.increment();
            Relay.closeQuietly(socket);
            return;
        }
        String name = null;
        boolean held = true;
        try {
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(HELLO_TIMEOUT_MS);
            Sni.Peek peek = Sni.peek(socket.getInputStream());
            long peekedAt = System.nanoTime();
            RelayStages.PEEK.record(peekedAt - acceptedAt);
            String sni = peek.serverName();
            if (sni == null) {
                LOG.debug("{}: no SNI, closing", ip);
                Metrics.VISITORS_REFUSED.increment();
                Relay.closeQuietly(socket);
                return;
            }
            if (sni.equals(hub.config().hostname())) {
                // The hub's own name: a node's control connection, the admin pages, /v1/key. Not a
                // visitor, and HttpFront runs a NodeSession here for the whole life of the link, so
                // leaving the slot held counted every node against the visitor cap until it dropped
                // -- and since that cap is now per /64, sixteen nodes sharing one subnet or office
                // LAN, at the four connections each the design expects, refused the seventeenth node
                // and every visitor from that network with it.
                giveSlot(ipKey);
                held = false;
                hub.front().serve(layer(socket, peek.consumed(), hub.tls().context().getSocketFactory()), ip);
                return;
            }
            name = hub.links().nameOf(sni);
            Links.Link link;
            if (name != null) {
                link = hub.links().byName(name);
                if (link == null && hub.store().nameOwner(name) != null) {
                    link = hub.links().awaitOnline(name, false, HOLD_MS); // node reconnecting (hand-off, restart)
                }
                if (link == null) {
                    Metrics.VISITORS_REFUSED.increment();
                    fallback(socket, peek.consumed(), name);
                    return;
                }
            } else {
                // A user domain (ARCHITECTURE.md §8.3): passthrough only, the hub has no certificate to answer with.
                name = sni.toLowerCase(java.util.Locale.ROOT);
                link = hub.links().byDomain(name);
                if (link == null && hub.store().domain(name) != null) {
                    link = hub.links().awaitOnline(name, true, HOLD_MS);
                }
                if (link == null) {
                    LOG.debug("{}: unknown SNI {}, closing", ip, sni);
                    Metrics.VISITORS_REFUSED.increment();
                    Relay.closeQuietly(socket);
                    return;
                }
            }
            RelayStages.RESOLVE.record(System.nanoTime() - peekedAt);
            if (acquire(perName, name) > MAX_PER_NAME) {
                release(perName, name);
                Metrics.VISITORS_REFUSED.increment();
                Relay.closeQuietly(socket);
                return;
            }
            // The third cap, and the only one whose number comes from somewhere else: what the node
            // said it will hold (ARCHITECTURE.md §9.3). Here with the other two rather than left to
            // NodeGroup.openVisitor, so that all three admission decisions are made in one place and
            // a visitor the hub cannot deliver is turned away before a stream is opened for it. The
            // check in openVisitor stays as the backstop for the race between this and the open, and
            // for the raw ports, which do not come through here.
            int ceiling = link.group().visitorCeiling();
            if (ceiling > 0 && link.group().visitorsInFlight() >= ceiling) {
                release(perName, name);
                Metrics.VISITORS_REFUSED.increment();
                Metrics.VISITORS_REFUSED_CAPACITY.increment();
                // Closed rather than answered. The hub has the key and could serve a page the way
                // fallback() does for an offline node, but that is a full TLS handshake per refused
                // visitor -- about 2.8 ms of hub CPU on the gate's runner -- and a node at its bound
                // is exactly when the hub has least to spare. The operator sees this in
                // jailhub_visitors_refused_capacity_total and on the admin page instead.
                Relay.closeQuietly(socket);
                return;
            }
            try {
                Metrics.VISITORS.increment();
                current.incrementAndGet();
                relay(socket, peek, link, ip, visitorPort, acceptedAt);
            } finally {
                current.decrementAndGet();
                release(perName, name);
            }
        } catch (IOException e) {
            LOG.debug("{}: {}", ip, e.getMessage());
            Relay.closeQuietly(socket);
        } finally {
            if (held) {
                giveSlot(ipKey);
            }
        }
    }

    private void relay(Socket socket, Sni.Peek peek, Links.Link link, String visitorIp, int visitorPort,
        long acceptedAt) throws IOException {
        NodeGroup group = link.group();
        socket.setSoTimeout(0);
        long beforeOpen = System.nanoTime();
        MuxStream stream = group.openVisitor(link, peek.serverName(), visitorIp, visitorPort,
            link.domain() != null ? "domain:" + link.domain() : hub.tls().keyId(), false);
        long openedAt = System.nanoTime();
        RelayStages.OPEN.record(openedAt - beforeOpen);
        try {
            Relay.pump(socket, stream, peek.consumed(), group.clientSide(stream), acceptedAt, openedAt);
        } finally {
            group.visitorDone(stream);
        }
    }

    /** TLS with the wildcard certificate (the hub has the key) and a one-line answer. */
    private void fallback(Socket socket, byte[] consumed, String name) throws IOException {
        try (SSLSocket s = layer(socket, consumed, hub.tls().context().getSocketFactory())) {
            s.setSoTimeout(HELLO_TIMEOUT_MS);
            s.startHandshake();
            // Drain the request line so the client gets a clean response.
            io.jailscale.proto.http.Http.readRequest(s.getInputStream(), 4096);
            // noindex,nofollow like every other page the hub writes (HttpFront.NOINDEX): this one
            // is served under the wildcard for any name at all, so it says of whatever name a
            // crawler was handed that this hub knows it, which is the thing /links is kept out of
            // an index for.
            // Through HttpFront.secured for the same reason as everything on the hub's own name:
            // this is an HTML page in a browser, and it is reached under the wildcard, which is the
            // widest surface the hub has.
            HttpFront.secured(HttpResponse.html(404, "<!doctype html><meta charset=utf-8>" + HttpFront.NOINDEX
                + "<title>jailscale</title><p><b>" + HttpFront.escape(name) + "</b> is not open right now.</p>"))
                .writeTo(s.getOutputStream());
        } catch (io.jailscale.proto.http.HttpException e) {
            // not HTTP; nothing to say
        }
    }

    /** Wraps an accepted socket in server-mode TLS, replaying the bytes already read. */
    static SSLSocket layer(Socket socket, byte[] consumed, SSLSocketFactory factory) throws IOException {
        SSLSocket s = (SSLSocket) factory.createSocket(socket, new ByteArrayInputStream(consumed), true);
        s.setUseClientMode(false);
        javax.net.ssl.SSLParameters p = s.getSSLParameters();
        p.setProtocols(Tls.PROTOCOLS);
        p.setApplicationProtocols(Tls.ALPN_HTTP11);
        s.setSSLParameters(p);
        return s;
    }
}
