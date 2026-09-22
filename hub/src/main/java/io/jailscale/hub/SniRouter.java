package io.jailscale.hub;

import io.jailscale.proto.http.Http;
import io.jailscale.proto.http.HttpException;
import io.jailscale.proto.http.HttpRequest;
import io.jailscale.proto.http.HttpResponse;
import io.jailscale.proto.mux.MuxStream;
import io.jailscale.proto.net.NetKey;
import io.jailscale.proto.tls.Sni;
import io.jailscale.proto.tls.Tls;
import io.jailscale.proto.util.Log;
import io.jailscale.proto.util.Throttle;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Public port 443 (ARCHITECTURE.md §8.1): peek the ClientHello, then either terminate TLS for the
 * hub's own name, relay the raw bytes to the node serving {@code <name>.<hub>}, or answer with
 * a short page under the wildcard certificate.
 */
final class SniRouter {

    private static final Log LOG = Log.get("sni");
    /** See {@link #refused}: one line a minute about visitors the hub turned away before relaying. */
    private static final Throttle REFUSED_LOG = new Throttle(60_000);
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
    /**
     * Since this hub started: visitors handed to a node, visitors turned away before that, and the
     * subset of those turned away because the node was already holding what it said it would
     * (ARCHITECTURE.md §9.3). The last is the one an operator can act on -- it says to give that
     * node more heap, or to move a name -- where the others say a visitor was malformed, early, or
     * abusive. Read by {@code jailhub status}; nothing here is per name or per address, so a total
     * says how much the hub is doing and never who is doing it.
     */
    private final LongAdder routed = new LongAdder();
    private final LongAdder refused = new LongAdder();
    private final LongAdder refusedCapacity = new LongAdder();

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
     * of the two copies had the exemption below: a forwarder on this host folds every visitor onto
     * one address, so a raw port capped the world at 64 while 443 behind the same forwarder capped
     * nobody.
     *
     * <p><b>Counted against the network and not the address</b> ({@link NetKey}): in v4 those are
     * the same thing, and in v6 they are not -- a routed /64 is free and standard, so a per-address
     * cap of 64 would be "64 per address, times eighteen quintillion". The key is taken from the
     * bytes {@code peer} holds rather than by formatting that address to text and parsing it
     * straight back once per connection; {@code ip} itself is what gets logged, banned and handed
     * to the node as the visitor's address.
     *
     * <p><b>The exemption is for visitors this hub cannot tell apart.</b> A forwarder on this host
     * arrives as loopback and folds every visitor behind it onto one key, so capping that key at 64
     * would cap everyone behind the forwarder together. The hub used to be able to tell them apart
     * -- a PROXY header from a trusted proxy named the real visitor (§8.5) -- and with that gone,
     * a deployment that puts something in front of 443 has no per-address cap at all; §15 says so.
     */
    String takeSlot(String ip, InetAddress peer) {
        String key = NetKey.of(peer);
        if (acquire(perIp, key) > MAX_PER_IP && !peer.isLoopbackAddress()) {
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

    long visitorsRouted() {
        return routed.sum();
    }

    long visitorsRefused() {
        return refused.sum();
    }

    /** The subset of {@link #visitorsRefused} that hit a node's own bound (ARCHITECTURE.md §9.3). */
    long visitorsRefusedCapacity() {
        return refusedCapacity.sum();
    }

    /** Serves one accepted raw connection to completion. */
    void serve(Socket socket) {
        String ip = socket.getInetAddress().getHostAddress();
        int visitorPort = socket.getPort();
        String ipKey = takeSlot(ip, socket.getInetAddress());
        if (ipKey == null) {
            refused.increment();
            Relay.closeQuietly(socket);
            return;
        }
        String name = null;
        boolean held = true;
        try {
            socket.setTcpNoDelay(true);
            socket.setSoTimeout(HELLO_TIMEOUT_MS);
            Sni.Peek peek = Sni.peek(socket.getInputStream());
            String sni = peek.serverName();
            if (sni == null) {
                LOG.debug("{}: no SNI, closing", ip);
                refused.increment();
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
                    refused.increment();
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
                    refused.increment();
                    Relay.closeQuietly(socket);
                    return;
                }
            }
            if (acquire(perName, name) > MAX_PER_NAME) {
                release(perName, name);
                refused.increment();
                refused(ip, name, "the per-name cap of " + MAX_PER_NAME);
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
                refused.increment();
                refusedCapacity.increment();
                refused(ip, name, "the node's ceiling of " + ceiling);
                // Closed rather than answered. The hub has the key and could serve a page the way
                // fallback() does for an offline node, but that is a full TLS handshake per refused
                // visitor -- about 2.8 ms of hub CPU on the gate's runner -- and a node at its bound
                // is exactly when the hub has least to spare. The refusal is logged and counted,
                // and the admin page says what each node is holding, instead.
                Relay.closeQuietly(socket);
                return;
            }
            try {
                routed.increment();
                current.incrementAndGet();
                relay(socket, peek, link, ip, visitorPort);
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

    private void relay(Socket socket, Sni.Peek peek, Links.Link link, String visitorIp, int visitorPort)
        throws IOException {
        NodeGroup group = link.group();
        socket.setSoTimeout(0);
        MuxStream stream;
        try {
            stream = group.openVisitor(link, peek.serverName(), visitorIp, visitorPort,
                link.domain() != null ? "domain:" + link.domain() : hub.tls().keyId());
        } catch (IOException e) {
            refused(visitorIp, peek.serverName(), e.getMessage());
            throw e;
        }
        try {
            Relay.pump(socket, stream, peek.consumed(), group.clientSide(stream));
        } finally {
            group.visitorDone(stream);
        }
    }

    /**
     * Says, at most once a minute, that a visitor was turned away before it was relayed.
     *
     * <p>All four refusals above -- the per-name cap, the node's ceiling, the backstop in
     * {@link NodeGroup#openVisitor} and whatever else it throws -- used to close the socket and
     * increment a counter, and that was all. A counter says how many; it does not say which cap,
     * and the visitor is told nothing either: a closed socket mid-handshake reaches it as
     * {@code SSLHandshakeException: Remote host terminated the handshake}, which is the same
     * sentence for all four.
     *
     * <p>That is how #183 came to be unanswerable. The `load` job failed on main with 455 of 1000
     * visitors seeing exactly that, and the hub's log at info held nothing about any of them -- so
     * the run said which test failed and nothing whatever about why, and a re-run made it go away.
     *
     * <p>One line a minute rather than one a visitor, because a hub at a cap refuses continuously
     * and a log that says so every time is a log nobody reads. It is the argument
     * {@code Visitors.refuse} already makes on the node side, with the same interval.
     */
    private static void refused(String ip, String name, String why) {
        if (REFUSED_LOG.ready()) {
            LOG.info("{}: visitor for {} refused before it was relayed: {}", ip, name, why);
        }
    }

    /** TLS with the wildcard certificate (the hub has the key) and a one-line answer. */
    private void fallback(Socket socket, byte[] consumed, String name) throws IOException {
        try (SSLSocket s = layer(socket, consumed, hub.tls().context().getSocketFactory())) {
            s.setSoTimeout(HELLO_TIMEOUT_MS);
            s.startHandshake();
            // Read the request: draining it is what lets the client see a clean response, and the
            // method is what says whether that response carries its body (RFC 9110 §9.3.2).
            HttpRequest req = Http.readRequest(s.getInputStream(), 4096);
            // noindex,nofollow like every other page the hub writes (HttpFront.NOINDEX): this one
            // is served under the wildcard for any name at all, so it says of whatever name a
            // crawler was handed that this hub knows it, and that is not for an index.
            // Through HttpFront.secured for the same reason as everything on the hub's own name:
            // this is an HTML page in a browser, and it is reached under the wildcard, which is the
            // widest surface the hub has.
            HttpFront.secured(HttpResponse.html(404, "<!doctype html><meta charset=utf-8>" + HttpFront.NOINDEX
                + "<title>jailscale</title><p><b>" + HttpFront.escape(name) + "</b> is not open right now.</p>"))
                .writeTo(s.getOutputStream(), req.isHead());
        } catch (HttpException _) {
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
